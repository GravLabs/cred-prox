using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using System.Text;
using CredProx;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Xunit;
using Yarp.ReverseProxy.Model;

namespace CredProx.Tests;

/// <summary>
/// The <see cref="Stage.ApplyCallerBudget"/> feature (M15, plan §3.7): declared budgets
/// admit exactly <c>PermitsPerInterval</c> requests per window with a
/// <c>429 credprox.caller_throttled</c> + <c>Retry-After</c> beyond, per-cluster overrides
/// replace the default field by field, the window is per caller app (key rotation shares
/// it), and callers without limits pass untouched. Times are exact via
/// <see cref="FakeTimeProvider"/>.
/// </summary>
public sealed class CallerBudgetFeatureTests
{
    [Fact]
    public async Task CallerWithoutLimits_IsUnlimited()
    {
        var (feature, _) = Setup(permits: null);

        for (var i = 0; i < 50; i++)
        {
            var context = Context();
            await feature.ApplyAsync(context, default);
            Assert.False(Aborted(context));
        }
    }

    [Fact]
    public async Task NoCallerIdentity_PassesThrough()
    {
        var (feature, _) = Setup(permits: 1);
        var context = Context(identity: null);

        await feature.ApplyAsync(context, default);

        Assert.False(Aborted(context));
    }

    [Fact]
    public async Task BudgetExceeded_429_WithRetryAfter_And_Code()
    {
        var (feature, _) = Setup(permits: 2, interval: "00:00:10");

        Assert.False(Aborted(await Apply(feature)));
        Assert.False(Aborted(await Apply(feature)));

        var third = await Apply(feature);
        Assert.True(Aborted(third));
        Assert.Equal(429, third.Response.StatusCode);
        Assert.Contains("credprox.caller_throttled", M4Contexts.ResponseBody(third));
        Assert.Equal("10", third.Response.Headers.RetryAfter.ToString());
    }

    [Fact]
    public async Task WindowReset_AdmitsAgain_AndRetryAfterShrinks()
    {
        var time = new FakeTimeProvider();
        var (feature, _) = Setup(permits: 1, interval: "00:00:10", time: time);

        Assert.False(Aborted(await Apply(feature)));
        var rejected = await Apply(feature);
        Assert.True(Aborted(rejected));
        Assert.Equal("10", rejected.Response.Headers.RetryAfter.ToString());

        time.Advance(TimeSpan.FromSeconds(4));
        var later = await Apply(feature);
        Assert.True(Aborted(later));
        Assert.Equal("6", later.Response.Headers.RetryAfter.ToString());

        time.Advance(TimeSpan.FromSeconds(6));
        Assert.False(Aborted(await Apply(feature)));
    }

    [Fact]
    public async Task PerClusterOverride_ReplacesDefault()
    {
        // Default 5/min; cluster-1 (the context's cluster) overrides to 1/10s.
        var (feature, _) = Setup(
            permits: 5,
            interval: "00:01:00",
            clusterOverrides: ("cluster-1", "1", "00:00:10"));

        Assert.False(Aborted(await Apply(feature)));
        Assert.True(Aborted(await Apply(feature)));
    }

    [Fact]
    public async Task ClusterOverride_ZeroPermits_DisablesBudgetForThatCluster()
    {
        var (feature, _) = Setup(
            permits: 1,
            clusterOverrides: ("cluster-1", "0", null));

        Assert.False(Aborted(await Apply(feature)));
        Assert.False(Aborted(await Apply(feature)));
    }

    [Fact]
    public async Task ClusterOverride_InheritsUnsetFields()
    {
        // Cluster sets only PermitsPerInterval: the caller's Interval is inherited.
        var time = new FakeTimeProvider();
        var (feature, _) = Setup(
            permits: 5,
            interval: "00:00:10",
            time: time,
            clusterOverrides: ("cluster-1", "1", null));

        Assert.False(Aborted(await Apply(feature)));
        var rejected = await Apply(feature);
        Assert.True(Aborted(rejected));
        Assert.Equal("10", rejected.Response.Headers.RetryAfter.ToString());
    }

    [Fact]
    public async Task KeyRotation_SharesTheCallerBudget()
    {
        // The budget belongs to the caller app, not the key: rotating keys mid-window
        // must not hand out a fresh budget (§3.7).
        var (feature, _) = Setup(permits: 1);

        Assert.False(Aborted(await Apply(feature, keyId: "k1")));
        Assert.True(Aborted(await Apply(feature, keyId: "k2-rotated")));
    }

    [Fact]
    public async Task UnknownCluster_UsesDefaultBudget()
    {
        // An override for a different cluster must not disable the default budget.
        var (feature, _) = Setup(
            permits: 1,
            clusterOverrides: ("other-cluster", "999", null));

        Assert.False(Aborted(await Apply(feature)));
        Assert.True(Aborted(await Apply(feature)));
    }

    [Fact]
    public async Task CallerGoneFromRegistry_PassesThrough_AuthStagesGuardIt()
    {
        var provider = Registry(("app-a", 1, null, null));
        var feature = new CallerBudgetFeature(provider, new CallerBudgetRegistry(new FakeTimeProvider()));
        var context = Context(new CallerIdentity("app-gone", "k1"));

        await feature.ApplyAsync(context, default);

        Assert.False(Aborted(context));
    }

    [Fact]
    public void Stage_SitsBetweenDestinationAndShaping()
    {
        // Ordering properties (§3.7): after AuthorizeOperation (blocked operations
        // consume no budget — the pipeline stops at the first abort) and after
        // ResolveDestination (cluster overrides), before ShapeHeaders/AttachCredential
        // (a rejected request never reaches a token endpoint or the upstream).
        Assert.True((int)Stage.ApplyCallerBudget > (int)Stage.AuthorizeOperation);
        Assert.True((int)Stage.ApplyCallerBudget > (int)Stage.ResolveDestination);
        Assert.True((int)Stage.ApplyCallerBudget < (int)Stage.ShapeHeaders);
        Assert.True((int)Stage.ApplyCallerBudget < (int)Stage.AttachCredential);
    }

    [Fact]
    public async Task Rejection_IncrementsMeter_WithCallerAndClusterTags()
    {
        var (feature, _) = Setup(permits: 1);

        using var listener = new MeterListener();
        var rejections = 0;
        string? callerTag = null;
        string? clusterTag = null;
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Name == "credprox.caller_throttle.rejections")
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((_, _, tags, _) =>
        {
            rejections++;
            foreach (var tag in tags)
            {
                if (tag.Key == "credprox.caller")
                {
                    callerTag = (string?)tag.Value;
                }

                if (tag.Key == "credprox.cluster")
                {
                    clusterTag = (string?)tag.Value;
                }
            }
        });
        listener.Start();

        await Apply(feature); // admitted, no measurement
        await Apply(feature); // rejected

        Assert.Equal(1, rejections);
        Assert.Equal("app-a", callerTag);
        Assert.Equal("cluster-1", clusterTag);
    }

    private static async Task<DefaultHttpContext> Apply(
        CallerBudgetFeature feature, string keyId = "k1")
    {
        var context = Context(new CallerIdentity("app-a", keyId));
        await feature.ApplyAsync(context, default);
        return context;
    }

    private static bool Aborted(DefaultHttpContext context) =>
        context.Features.Get<CredProxRequestState>()!.IsAborted;

    private static DefaultHttpContext Context(CallerIdentity? identity = null)
    {
        var context = M4Contexts.Create(out _);
        context.Features.Set(identity ?? new CallerIdentity("app-a", "k1"));
        return context;
    }

    private static (CallerBudgetFeature Feature, CallerBudgetRegistry Budgets) Setup(
        int? permits,
        string? interval = null,
        (string Cluster, string? Permits, string? Interval)? clusterOverrides = null,
        FakeTimeProvider? time = null)
    {
        time ??= new FakeTimeProvider();

        var provider = Registry(("app-a", permits, interval, clusterOverrides));
        var budgets = new CallerBudgetRegistry(time);
        return (new CallerBudgetFeature(provider, budgets), budgets);
    }

    private static CallerRegistryProvider Registry(
        (string Caller, int? Permits, string? Interval, (string Cluster, string? Permits, string? Interval)? Overrides) caller)
    {
        var entries = new Dictionary<string, string?>
        {
            [$"CredProx:Callers:{caller.Caller}:Keys:0:KeyId"] = "k1",
            [$"CredProx:Callers:{caller.Caller}:Keys:0:KeyHash"] =
                "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("unused"))).ToLowerInvariant(),
        };

        if (caller.Permits is { } permits)
        {
            entries[$"CredProx:Callers:{caller.Caller}:Limits:PermitsPerInterval"] = permits.ToString();
        }

        if (caller.Interval is not null)
        {
            entries[$"CredProx:Callers:{caller.Caller}:Limits:Interval"] = caller.Interval;
        }

        if (caller.Overrides is { } o)
        {
            if (o.Permits is not null)
            {
                entries[$"CredProx:Callers:{caller.Caller}:Limits:Clusters:{o.Cluster}:PermitsPerInterval"] = o.Permits;
            }

            if (o.Interval is not null)
            {
                entries[$"CredProx:Callers:{caller.Caller}:Limits:Clusters:{o.Cluster}:Interval"] = o.Interval;
            }
        }

        var config = new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
        return new CallerRegistryProvider(
            new CallerBinder(config, new SecretAccessorFactory(new ConfigurationSecretSource(config))),
            new ConfigurationSecretSource(config),
            NullLogger<CallerRegistryProvider>.Instance);
    }
}
