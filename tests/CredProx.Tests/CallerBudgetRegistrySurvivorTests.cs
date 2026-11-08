using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage of <see cref="CallerBudgetRegistry"/>: the key separator that keeps
/// caller/cluster splits unambiguous, and the interval as an independent trigger for the
/// rebind window replacement (§3.7).
/// </summary>
public sealed class CallerBudgetRegistrySurvivorTests
{
    [Fact]
    public void KeySeparator_KeepsAdjacentSplitsApart()
    {
        // "ab"+"|"+"c" and "a"+"|"+"bc" must be distinct budgets; without the separator
        // both spellings concatenate to the same key and share one window — an unrelated
        // caller would burn another's budget.
        var registry = new CallerBudgetRegistry(new FakeTimeProvider());
        var interval = TimeSpan.FromMinutes(1);

        Assert.True(registry.TryAcquire("ab", "c", 1, interval, out _));
        Assert.True(registry.TryAcquire("a", "bc", 1, interval, out _));

        // And the first pair's own window is intact (its one permit was consumed by the
        // first call only): a false here would mean the second caller's permit leaked in.
        Assert.False(registry.TryAcquire("ab", "c", 1, interval, out _));
    }

    [Fact]
    public void IntervalChange_AloneReplacesTheWindow()
    {
        // A rebind that only widens the window (permits unchanged) must still replace the
        // limiter — a fresh window on rebind is the documented §3.7 semantics.
        var registry = new CallerBudgetRegistry(new FakeTimeProvider());

        Assert.True(registry.TryAcquire("app-a", "openai", 1, TimeSpan.FromSeconds(10), out _));
        Assert.False(registry.TryAcquire("app-a", "openai", 1, TimeSpan.FromSeconds(10), out _));

        Assert.True(registry.TryAcquire("app-a", "openai", 1, TimeSpan.FromSeconds(30), out _));
    }
}
