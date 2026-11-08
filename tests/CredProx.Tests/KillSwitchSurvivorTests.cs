using System.Diagnostics.Metrics;
using CredProx;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Xunit;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Model;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage of the kill switch: the binder's guidance texts (a switch silently
/// unarmed is the failure mode), the cluster-id resolution order between the matched
/// cluster and the route's own cluster binding, the cluster rejection metric tags, and the
/// provider's guards and rebind log lines.
/// </summary>
public sealed class KillSwitchSurvivorTests
{
    private static IConfiguration Config(params (string Key, string? Value)[] entries) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(entries
                .Select(e => ("CredProx:" + e.Key, e.Value))
                .ToDictionary(e => e.Item1, e => e.Item2))
            .Build();

    [Fact]
    public void Binder_UnknownKey_ErrorNamesTheSection()
    {
        var ex = Assert.Throws<OptionsValidationException>(
            () => new KillSwitchBinder(Config(("KillSwitch:Clusterz:0", "acme"))).Bind());

        var failure = Assert.Single(ex.Failures);
        Assert.Contains("'CredProx:KillSwitch' section", failure, StringComparison.Ordinal);
    }

    [Fact]
    public void Binder_SingleValue_ExplainsTheListShapeAndItsConsequence()
    {
        var ex = Assert.Throws<OptionsValidationException>(
            () => new KillSwitchBinder(Config(("KillSwitch:Clusters", "acme"))).Bind());

        var failure = Assert.Single(ex.Failures);
        Assert.Contains("takes 'Clusters' as a list of ids", failure, StringComparison.Ordinal);
        Assert.Contains("write 'Clusters:0'", failure, StringComparison.Ordinal); // the fix recipe itself is part of the message
        Assert.Contains("silently leave the switch unarmed", failure, StringComparison.Ordinal);
    }

    [Fact]
    public void Binder_EmptyEntry_NamesThePathAndCarriesTheFixTail()
    {
        var ex = Assert.Throws<OptionsValidationException>(() => new KillSwitchBinder(Config(
            ("KillSwitch:Clusters:0", "acme"),
            ("KillSwitch:Clusters:1", "  "))).Bind());

        var failure = Assert.Single(ex.Failures);
        Assert.Contains(
            "declares an empty 'Clusters' entry at 'CredProx:KillSwitch:Clusters:1'",
            failure,
            StringComparison.Ordinal);
        Assert.EndsWith("remove it or give it the id.", failure, StringComparison.Ordinal);
    }

    // ---- feature ----

    private sealed class ClusterStub(RouteModel route, ClusterModel cluster) : IReverseProxyFeature
    {
        public RouteModel Route { get; } = route;

        public ClusterModel Cluster { get; } = cluster;

        public IReadOnlyList<DestinationState> AllDestinations { get; } = [];

        public IReadOnlyList<DestinationState> AvailableDestinations { get; set; } = [];

        public DestinationState? ProxiedDestination { get; set; }
    }

    private static KillSwitchFeature Feature(params (string Key, string? Value)[] entries) =>
        new(new KillSwitchRegistryProvider(
            new KillSwitchBinder(Config(entries)),
            new ConfigurationSecretSource(Config(entries)),
            NullLogger<KillSwitchRegistryProvider>.Instance));

    // A null clusterId models the Config.ClusterId that the feature's null-propagation
    // tolerates (the fallback leg of the resolution).
    private static DefaultHttpContext ContextWith(string? clusterId, string? routeClusterId)
    {
        var context = M4Contexts.Create(out _);
        var route = new RouteModel(
            new RouteConfig { RouteId = "route-1", ClusterId = routeClusterId },
            cluster: null,
            HttpTransformer.Default);
        var cluster = new ClusterModel(
            new Yarp.ReverseProxy.Configuration.ClusterConfig { ClusterId = clusterId! },
            new HttpMessageInvoker(new SocketsHttpHandler()));
        context.Features.Set<IReverseProxyFeature>(new ClusterStub(route, cluster));
        context.Features.Set(new CallerIdentity("app-z", "k1"));
        return context;
    }

    [Fact]
    public async Task Apply_NullContext_Throws()
    {
        var feature = Feature(("KillSwitch:Clusters:0", "acme"));

        await Assert.ThrowsAsync<ArgumentNullException>(() => feature.ApplyAsync(null!, default).AsTask());
    }

    [Fact]
    public async Task ClusterId_PrefersTheMatchedClusterOverTheRouteBinding()
    {
        // The matched cluster wins; the route's own ClusterId binding is only the fallback.
        // Resolving only the route side would arm the switch against the wrong target.
        var feature = Feature(("KillSwitch:Clusters:0", "cluster-1"));
        var context = ContextWith(clusterId: "cluster-1", routeClusterId: "route-bound-other");

        await feature.ApplyAsync(context, default);

        Assert.True(context.Features.Get<CredProxRequestState>()!.IsAborted);
        Assert.Contains("credprox.vendor_disabled", M4Contexts.ResponseBody(context), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ClusterId_FallsBackToRouteBinding_AndTagsTheClusterRejection()
    {
        // Route-only resolution plus the exact metric tags of a cluster rejection — the
        // tag names are the dashboard contract. The cluster id is unique to this test and
        // the callback takes only OUR event: MeterListener is process-wide, so rejections
        // from parallel kill-switch tests used to overwrite `seen` (the tags of whichever
        // event landed last, not the contract this test runs).
        var feature = Feature(("KillSwitch:Clusters:0", "tag-contract-cluster"));
        var context = ContextWith(clusterId: null, routeClusterId: "tag-contract-cluster");

        using var listener = new MeterListener();
        var seen = new List<KeyValuePair<string, string?>>();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Name == "credprox.killswitch.rejections")
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((_, _, tags, _) =>
        {
            var pair = tags.ToArray()
                .Select(t => new KeyValuePair<string, string?>(t.Key, (string?)t.Value)).ToList();
            if (pair.Any(t => t.Key == "credprox.cluster" && t.Value == "tag-contract-cluster"))
            {
                seen = pair;
            }
        });
        listener.Start();

        await feature.ApplyAsync(context, default);

        Assert.True(context.Features.Get<CredProxRequestState>()!.IsAborted);
        var expected = new List<KeyValuePair<string, string?>>
        {
            new("credprox.kind", "cluster"),
            new("credprox.cluster", "tag-contract-cluster"),
        };
        Assert.Equal(expected, seen);
    }

    // ---- provider ----

    private sealed class ManualChangeToken : IChangeToken
    {
        private Action<object?>? _callback;
        private object? _state;

        public bool ActiveChangeCallbacks => true;

        public bool HasChanged => false;

        public IDisposable RegisterChangeCallback(Action<object?> callback, object? state)
        {
            _callback = callback;
            _state = state;
            return new NoopDisposable();
        }

        public void Fire() => _callback?.Invoke(_state);

        private sealed class NoopDisposable : IDisposable
        {
            public void Dispose()
            {
            }
        }
    }

    private sealed class StubSecretSource(ManualChangeToken token) : ISecretSource
    {
        public string Scheme => "triage";

        public ValueTask<string?> GetSecretAsync(string name, CancellationToken cancellationToken) =>
            new((string?)null);

        public IChangeToken GetChangeToken() => token;
    }

    [Fact]
    public void Provider_ConstructorGuards()
    {
        var config = Config(("KillSwitch:Clusters:0", "acme"));
        var binder = new KillSwitchBinder(config);
        var secretSource = new ConfigurationSecretSource(config);
        ILogger<KillSwitchRegistryProvider> logger = NullLogger<KillSwitchRegistryProvider>.Instance;

        Assert.Throws<ArgumentNullException>(() => new KillSwitchRegistryProvider(null!, secretSource, logger));
        Assert.Throws<ArgumentNullException>(() => new KillSwitchRegistryProvider(binder, null!, logger));
        Assert.Throws<ArgumentNullException>(() => new KillSwitchRegistryProvider(binder, secretSource, null!));
    }

    [Fact]
    public void Provider_SuccessfulRebind_LogsTheCounts()
    {
        var source = new ReloadableMemoryConfigurationSource(
            new Dictionary<string, string?> { ["CredProx:KillSwitch:Clusters:0"] = "acme" });
        var config = new ConfigurationBuilder().Add(source).Build();
        var logs = new List<string?>();
        var token = new ManualChangeToken();
        _ = new KillSwitchRegistryProvider(
            new KillSwitchBinder(config),
            new StubSecretSource(token),
            new LoggerFactory([new CapturingLoggerProvider(logs)]).CreateLogger<KillSwitchRegistryProvider>());

        token.Fire();

        Assert.Contains(
            "CredProx kill switch rebound: 1 cluster(s) and 0 caller(s) out of service.",
            logs);
    }

    [Fact]
    public void Provider_FailedRebind_LogsTheExactLine_AndKeepsThePreviousSwitch()
    {
        var source = new ReloadableMemoryConfigurationSource(
            new Dictionary<string, string?> { ["CredProx:KillSwitch:Clusters:0"] = "acme" });
        var config = new ConfigurationBuilder().Add(source).Build();
        var logs = new List<string?>();
        var token = new ManualChangeToken();
        var provider = new KillSwitchRegistryProvider(
            new KillSwitchBinder(config),
            new StubSecretSource(token),
            new LoggerFactory([new CapturingLoggerProvider(logs)]).CreateLogger<KillSwitchRegistryProvider>());

        // A reload where Clusters becomes a single value fails validation (silently-unarmed
        // is exactly what the binder refuses).
        ((ReloadableMemoryConfigurationProvider)config.Providers
            .OfType<ReloadableMemoryConfigurationProvider>().Single()).Set("CredProx:KillSwitch:Clusters", "acme");
        ((ReloadableMemoryConfigurationProvider)config.Providers
            .OfType<ReloadableMemoryConfigurationProvider>().Single()).Reload();
        token.Fire();

        Assert.Contains(
            "CredProx kill switch failed to rebind after a configuration change; keeping the previous switch state.",
            logs);
        Assert.True(provider.Current.IsClusterDisabled("acme")); // previous state still serving
    }
}
