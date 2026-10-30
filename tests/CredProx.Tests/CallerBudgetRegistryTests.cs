using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// <see cref="CallerBudgetRegistry"/> window lifecycle (M15, plan §3.7): windows are keyed
/// per caller × cluster, a rebind that changes a caller's limits replaces that window
/// (fresh count), unchanged limits keep it, and keys come only from config shapes.
/// </summary>
public sealed class CallerBudgetRegistryTests
{
    [Fact]
    public void SameLimits_KeepOneWindow()
    {
        var registry = new CallerBudgetRegistry(new FakeTimeProvider());
        var interval = TimeSpan.FromMinutes(1);

        Assert.True(registry.TryAcquire("app-a", "*", 2, interval, out _));
        Assert.True(registry.TryAcquire("app-a", "*", 2, interval, out _));
        Assert.False(registry.TryAcquire("app-a", "*", 2, interval, out var retryAfter));
        Assert.True(retryAfter > TimeSpan.Zero);

        // Same shape again: still the same exhausted window, not a fresh one.
        Assert.False(registry.TryAcquire("app-a", "*", 2, interval, out _));
    }

    [Fact]
    public void LimitsChange_ReplacesWindowFresh()
    {
        var registry = new CallerBudgetRegistry(new FakeTimeProvider());
        var interval = TimeSpan.FromMinutes(1);

        Assert.True(registry.TryAcquire("app-a", "*", 1, interval, out _));
        Assert.False(registry.TryAcquire("app-a", "*", 1, interval, out _));

        // Rebind raised the budget: the window is replaced, permits are available again.
        Assert.True(registry.TryAcquire("app-a", "*", 4, interval, out _));
    }

    [Fact]
    public void DifferentClusters_HaveSeparateWindows()
    {
        var registry = new CallerBudgetRegistry(new FakeTimeProvider());
        var interval = TimeSpan.FromMinutes(1);

        Assert.True(registry.TryAcquire("app-a", "openai", 1, interval, out _));
        Assert.False(registry.TryAcquire("app-a", "openai", 1, interval, out _));
        Assert.True(registry.TryAcquire("app-a", "anthropic", 1, interval, out _));
    }

    [Fact]
    public void DifferentCallers_HaveSeparateWindows()
    {
        var registry = new CallerBudgetRegistry(new FakeTimeProvider());
        var interval = TimeSpan.FromMinutes(1);

        Assert.True(registry.TryAcquire("app-a", "*", 1, interval, out _));
        Assert.False(registry.TryAcquire("app-a", "*", 1, interval, out _));
        Assert.True(registry.TryAcquire("app-b", "*", 1, interval, out _));
    }

    [Fact]
    public void Clear_ResetsEveryWindow()
    {
        var registry = new CallerBudgetRegistry(new FakeTimeProvider());
        var interval = TimeSpan.FromMinutes(1);

        Assert.True(registry.TryAcquire("app-a", "*", 1, interval, out _));
        Assert.False(registry.TryAcquire("app-a", "*", 1, interval, out _));

        registry.Clear();

        Assert.True(registry.TryAcquire("app-a", "*", 1, interval, out _));
    }
}
