using CredProx;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage of <see cref="ClusterThrottleRegistry"/>: per-cluster override
/// merging across every effective field, and the pause state's expiry clamp and
/// extend-only semantics.
/// </summary>
public sealed class ClusterThrottleRegistryTests
{
    [Fact]
    public void GetEffective_AppliesEveryPerClusterOverride()
    {
        var options = new ThrottleOptions
        {
            PermitsPerInterval = 5,
            Interval = TimeSpan.FromSeconds(1),
            MaxConcurrency = 3,
            QueueLimit = 9,
            MaxQueueWait = TimeSpan.FromSeconds(5),
            PauseOnVendorThrottle = true,
            MaxPause = TimeSpan.FromMinutes(1),
        };
        options.Clusters["c1"] = new ThrottleClusterOptions
        {
            PermitsPerInterval = 1,
            Interval = TimeSpan.FromSeconds(30),
            MaxConcurrency = 2,
            QueueLimit = 4,
            MaxQueueWait = TimeSpan.FromSeconds(2),
            PauseOnVendorThrottle = false,
            MaxPause = TimeSpan.FromSeconds(10),
        };
        var registry = new ClusterThrottleRegistry(options, new FakeTimeProvider());

        var overridden = registry.GetEffective("c1");
        Assert.Equal(1, overridden.PermitsPerInterval);
        Assert.Equal(TimeSpan.FromSeconds(30), overridden.Interval);
        Assert.Equal(2, overridden.MaxConcurrency);
        Assert.Equal(4, overridden.QueueLimit);
        Assert.Equal(TimeSpan.FromSeconds(2), overridden.MaxQueueWait);
        Assert.False(overridden.PauseOnVendorThrottle);
        Assert.Equal(TimeSpan.FromSeconds(10), overridden.MaxPause);

        var defaults = registry.GetEffective("other");
        Assert.Equal(5, defaults.PermitsPerInterval);
        Assert.Equal(TimeSpan.FromSeconds(1), defaults.Interval);
        Assert.Equal(3, defaults.MaxConcurrency);
        Assert.Equal(9, defaults.QueueLimit);
        Assert.Equal(TimeSpan.FromSeconds(5), defaults.MaxQueueWait);
        Assert.True(defaults.PauseOnVendorThrottle);
        Assert.Equal(TimeSpan.FromMinutes(1), defaults.MaxPause);
    }

    [Fact]
    public void Pause_ExpiryClampsToZero_AndOnlyEverExtends()
    {
        var time = new FakeTimeProvider();
        var registry = new ClusterThrottleRegistry(new ThrottleOptions(), time);
        var state = registry.GetOrCreate("cluster-a");

        state.PauseUntil(time.GetUtcNow() + TimeSpan.FromSeconds(2));
        time.Advance(TimeSpan.FromSeconds(1));
        Assert.Equal(TimeSpan.FromSeconds(1), state.PauseRemaining(time));

        // Expired: exactly zero, never negative.
        time.Advance(TimeSpan.FromSeconds(2));
        Assert.Equal(TimeSpan.Zero, state.PauseRemaining(time));

        // An expired-or-shrinking target never shortens the live pause.
        state.PauseUntil(time.GetUtcNow() - TimeSpan.FromSeconds(1));
        Assert.Equal(TimeSpan.Zero, state.PauseRemaining(time));

        state.PauseUntil(time.GetUtcNow() + TimeSpan.FromSeconds(5));
        state.PauseUntil(time.GetUtcNow() + TimeSpan.FromSeconds(3));
        Assert.Equal(TimeSpan.FromSeconds(5), state.PauseRemaining(time));
    }
}
