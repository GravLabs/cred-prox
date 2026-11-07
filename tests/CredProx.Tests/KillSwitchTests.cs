using System.Diagnostics.Metrics;
using CredProx;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M18 (§8.4): the kill switch. <c>CredProx:KillSwitch</c> lists cluster and caller ids
/// that are out of service; the <see cref="Stage.ApplyKillSwitch"/> feature answers
/// <c>503 credprox.vendor_disabled</c> / <c>503 credprox.caller_disabled</c> before any
/// forwarding work, the lists flip live on reload, and the section is fail-closed like
/// every other (a switch silently unarmed by a typo is the failure this guards).
/// </summary>
public sealed class KillSwitchTests
{
    // ---- the binder: validation and binding ----

    private static KillSwitchRegistry Bind(params (string Key, string? Value)[] entries) =>
        new KillSwitchBinder(Root(entries)).Bind();

    private static IConfiguration Root((string Key, string? Value)[] entries) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(entries
                .Select(e => ("CredProx:" + e.Key, e.Value))
                .ToDictionary(e => e.Item1, e => e.Item2))
            .Build();

    [Fact]
    public void BothLists_Bind_AndMatchCaseInsensitively()
    {
        var registry = Bind(
            ("KillSwitch:Clusters:0", "acme"),
            ("KillSwitch:Clusters:1", "vendor-b"),
            ("KillSwitch:Callers:0", "batch-app"));

        Assert.True(registry.IsClusterDisabled("acme"));
        Assert.True(registry.IsClusterDisabled("ACME"));
        Assert.True(registry.IsCallerDisabled("Batch-App"));
        Assert.False(registry.IsClusterDisabled("other"));
        Assert.False(registry.IsCallerDisabled("app-a"));

        Assert.False(KillSwitchRegistry.Empty.IsClusterDisabled("acme"));
        Assert.False(KillSwitchRegistry.Empty.IsCallerDisabled("batch-app"));
    }

    [Fact]
    public void MissingSection_NothingDisabled()
    {
        var registry = Bind(("SomethingElse:0", "x"));

        Assert.Equal(0, registry.DisabledClusterCount);
        Assert.Equal(0, registry.DisabledCallerCount);
    }

    [Fact]
    public void MisspelledKey_FailsStartup()
    {
        // "Cluster" (singular) would bind to nothing — an unarmed switch.
        var ex = Assert.Throws<OptionsValidationException>(() => Bind(
            ("KillSwitch:Cluster:0", "acme")));

        Assert.Contains("'Cluster'", ex.Message);
        Assert.Contains("Callers, Clusters", ex.Message);
        Assert.Contains("CredProx:KillSwitch", ex.Message);
    }

    [Fact]
    public void MapShapedEntry_FailsStartup()
    {
        // Clusters is a list: the map-shaped entry looks meaningful but the binder
        // ignores every non-index key — exactly the silent no-op a kill switch must not
        // have.
        var ex = Assert.Throws<OptionsValidationException>(() => Bind(
            ("KillSwitch:Clusters:acme", "true")));

        Assert.Contains("'Clusters:acme'", ex.Message);
        Assert.Contains("must be indexed", ex.Message);
    }

    [Fact]
    public void BlockUnderListIndex_FailsStartup()
    {
        var ex = Assert.Throws<OptionsValidationException>(() => Bind(
            ("KillSwitch:Clusters:0:Id", "acme")));

        Assert.Contains("nested block under 'Clusters:0'", ex.Message);
    }

    [Fact]
    public void SingleValueInsteadOfList_FailsStartup()
    {
        var ex = Assert.Throws<OptionsValidationException>(() => Bind(
            ("KillSwitch:Clusters", "acme")));

        Assert.Contains("as a list of ids", ex.Message);
        Assert.Contains("'Clusters'", ex.Message);
    }

    [Fact]
    public void BlankEntry_FailsStartup()
    {
        var ex = Assert.Throws<OptionsValidationException>(() => Bind(
            ("KillSwitch:Clusters:0", "")));

        Assert.Contains("empty 'Clusters' entry", ex.Message);
    }

    // ---- the provider: live reload ----

    [Fact]
    public void FailedRebind_KeepsThePreviousSwitchState()
    {
        var source = new ReloadableMemoryConfigurationSource(new Dictionary<string, string?>
        {
            ["CredProx:KillSwitch:Clusters:0"] = "acme",
        });
        var config = new ConfigurationBuilder().Add(source).Build();
        var reloadable = (ReloadableMemoryConfigurationProvider)config.Providers
            .OfType<ReloadableMemoryConfigurationProvider>().Single();
        var provider = Provider(config);
        var before = provider.Current;

        // The reload carries a typo — the switch must keep guarding acme, not drop the
        // whole section.
        reloadable.Set("CredProx:KillSwitch:Clusterz:0", "vendor-b");
        reloadable.Reload();

        Assert.Same(before, provider.Current);
        Assert.True(before.IsClusterDisabled("acme"));
    }

    [Fact]
    public void FlipOff_ThenBackOn_WorksAcrossReloads()
    {
        var source = new ReloadableMemoryConfigurationSource(new Dictionary<string, string?>());
        var config = new ConfigurationBuilder().Add(source).Build();
        var reloadable = (ReloadableMemoryConfigurationProvider)config.Providers
            .OfType<ReloadableMemoryConfigurationProvider>().Single();
        var provider = Provider(config);
        Assert.False(provider.Current.IsClusterDisabled("acme"));

        reloadable.Set("CredProx:KillSwitch:Clusters:0", "acme");
        reloadable.Reload();
        Assert.True(provider.Current.IsClusterDisabled("acme"));

        // Back on = the same flip in the other direction; the entry is removed outright
        // (a leftover blank entry would be a validation error by design — the switch
        // refuses to guess what an empty id meant).
        reloadable.Remove("CredProx:KillSwitch:Clusters:0");
        reloadable.Reload();
        Assert.False(provider.Current.IsClusterDisabled("acme"));
    }

    [Fact]
    public void Startup_EagerBindRejectsBadSection_ThroughTheDiPath()
    {
        // The startup validator resolves the registry forwarder; that resolution is what
        // fails, so a bad section never leaves the switch silently unarmed.
        var config = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?> { ["CredProx:KillSwitch:Clusters:acme"] = "true" }).Build();
        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(config);
        services.AddSingleton<ISecretSource, ConfigurationSecretSource>();
        services.AddSingleton(sp => new KillSwitchBinder(config));
        services.AddSingleton(sp => new KillSwitchRegistryProvider(
            sp.GetRequiredService<KillSwitchBinder>(),
            sp.GetRequiredService<ISecretSource>(),
            NullLogger<KillSwitchRegistryProvider>.Instance));
        services.AddTransient(sp => sp.GetRequiredService<KillSwitchRegistryProvider>().Current);
        var provider = services.BuildServiceProvider();

        Assert.Throws<OptionsValidationException>(() => provider.GetService<KillSwitchRegistry>());
    }

    // ---- the feature: enforcement ----

    [Fact]
    public async Task DisabledCaller_503CallerDisabled()
    {
        var feature = Feature(("KillSwitch:Callers:0", "app-a"));

        var killed = await Apply(feature, "app-a");
        Assert.True(Aborted(killed));
        Assert.Equal(503, killed.Response.StatusCode);
        Assert.Contains("credprox.caller_disabled", M4Contexts.ResponseBody(killed));

        var other = await Apply(feature, "app-b");
        Assert.False(Aborted(other));
    }

    [Fact]
    public async Task DisabledCluster_503VendorDisabled()
    {
        var feature = Feature(("KillSwitch:Clusters:0", "cluster-1"));

        var killed = await Apply(feature, "app-a");
        Assert.True(Aborted(killed));
        Assert.Equal(503, killed.Response.StatusCode);
        Assert.Contains("credprox.vendor_disabled", M4Contexts.ResponseBody(killed));
    }

    [Fact]
    public async Task OtherClusters_AreNotAffected()
    {
        var feature = Feature(("KillSwitch:Clusters:0", "some-other-cluster"));

        Assert.False(Aborted(await Apply(feature, "app-a")));
    }

    [Fact]
    public async Task AnonymousRoute_OnADisabledCluster_IsStillKilled()
    {
        var feature = Feature(("KillSwitch:Clusters:0", "cluster-1"));

        var context = M4Contexts.Create(out _);
        context.Features.Set<CallerIdentity>(null); // anonymous: no caller identity at all
        await feature.ApplyAsync(context, default);

        Assert.True(Aborted(context));
        Assert.Contains("credprox.vendor_disabled", M4Contexts.ResponseBody(context));
    }

    [Fact]
    public async Task EmptySwitch_ServesEverything()
    {
        var feature = Feature(("KillSwitch:Callers:0", "someone-else"));

        Assert.False(Aborted(await Apply(feature, "app-a")));
    }

    [Fact]
    public async Task CallerCheckRunsBeforeClusterCheck_CallerCodeIsMoreSpecific()
    {
        var feature = Feature(
            ("KillSwitch:Callers:0", "app-a"),
            ("KillSwitch:Clusters:0", "cluster-1"));

        var killed = await Apply(feature, "app-a");
        Assert.Contains("credprox.caller_disabled", M4Contexts.ResponseBody(killed));

        // A different caller on the killed cluster still gets the vendor code.
        var vendor = await Apply(feature, "app-b");
        Assert.Contains("credprox.vendor_disabled", M4Contexts.ResponseBody(vendor));
    }

    [Fact]
    public void Stage_SitsAfterAuthentication_BeforeEverythingOutbound()
    {
        // Ordering properties (§8.4, §3.4): a valid key was seen (no anonymous bypass) but
        // nothing that could touch a partition source, token endpoint or upstream ran.
        Assert.True((int)Stage.ApplyKillSwitch > (int)Stage.AuthenticateCaller);
        Assert.True((int)Stage.ApplyKillSwitch < (int)Stage.AuthorizeOperation);
        Assert.True((int)Stage.ApplyKillSwitch < (int)Stage.ResolveDestination);
        Assert.True((int)Stage.ApplyKillSwitch < (int)Stage.AttachCredential);
    }

    [Fact]
    public async Task Rejections_IncrementMeter_WithKindAndIdTags()
    {
        var feature = Feature(
            ("KillSwitch:Callers:0", "app-a"),
            ("KillSwitch:Clusters:0", "some-other-cluster"));

        using var listener = new MeterListener();
        var seen = new List<(string Kind, string Id)>();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Name == "credprox.killswitch.rejections")
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((_, _, tags, _) =>
        {
            string? kind = null;
            string? id = null;
            foreach (var tag in tags)
            {
                if (tag.Key == "credprox.kind")
                {
                    kind = (string?)tag.Value;
                }
                else if (tag.Key is "credprox.caller" or "credprox.cluster")
                {
                    id = (string?)tag.Value;
                }
            }

            seen.Add((kind!, id!));
        });
        listener.Start();

        Assert.True(Aborted(await Apply(feature, "app-a"))); // caller
        Assert.False(Aborted(await Apply(feature, "app-b"))); // passes; no measurement

        Assert.Single(seen);
        Assert.Equal(("caller", "app-a"), seen[0]);
    }

    // ---- helpers ----

    private static KillSwitchRegistryProvider Provider(IConfiguration config) =>
        new(
            new KillSwitchBinder(config),
            new ConfigurationSecretSource(config),
            NullLogger<KillSwitchRegistryProvider>.Instance);

    private static KillSwitchFeature Feature(params (string Key, string? Value)[] entries)
    {
        var config = Root(entries);
        return new KillSwitchFeature(Provider(config));
    }

    // The context's cluster is always the stub's "cluster-1"; other cluster ids are
    // exercised by disabling those ids instead (a switch entry that names no present
    // cluster must simply never fire).
    private async Task<DefaultHttpContext> Apply(KillSwitchFeature feature, string callerId)
    {
        var context = M4Contexts.Create(out _);
        context.Features.Set(new CallerIdentity(callerId, "k1"));
        await feature.ApplyAsync(context, default);
        return context;
    }

    private static bool Aborted(DefaultHttpContext context) =>
        context.Features.Get<CredProxRequestState>()!.IsAborted;
}
