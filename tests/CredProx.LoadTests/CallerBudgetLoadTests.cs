using System.Collections.Concurrent;
using CredProx;
using Xunit;

namespace CredProx.LoadTests;

/// <summary>
/// §5.2 "Caller budgets" (M15, §3.7) under load: a burst of concurrent requests against a
/// per-caller budget admits exactly <c>PermitsPerInterval</c> — never one more, never one
/// fewer — and refills exactly on the window boundary. Real clock, real threads: the races
/// the deterministic unit tests cannot reach.
/// </summary>
[Trait("Layer", "Nightly")]
public sealed class CallerBudgetLoadTests
{
    [Fact]
    public async Task Burst_AdmitsExactlyTheBudget_RejectsTheRest()
    {
        const int Budget = 50;
        const int Burst = 200;
        var registry = new CallerBudgetRegistry(TimeProvider.System);
        var interval = TimeSpan.FromSeconds(10);

        var results = await Task.WhenAll(Enumerable.Range(0, Burst).Select(_ => Task.Run(() =>
            registry.TryAcquire("app-a", "cluster", Budget, interval, out var retryAfter)
                ? (true, retryAfter)
                : (false, retryAfter))))
            .WaitBoundedAsync("the burst to drain");

        var admitted = results.Count(r => r.Item1);
        Assert.Equal(Budget, admitted);

        var rejected = results.Where(r => !r.Item1).ToList();
        Assert.Equal(Burst - Budget, rejected.Count);
        Assert.All(rejected, r => Assert.True(r.retryAfter > TimeSpan.Zero, "every rejection advertises a Retry-After"));
    }

    [Fact]
    public async Task Burst_RefillsOnWindowBoundary_NotBefore()
    {
        const int Budget = 30;
        var registry = new CallerBudgetRegistry(TimeProvider.System);
        var interval = TimeSpan.FromMilliseconds(400);

        // Drain the first window from many threads at once.
        var first = await Task.WhenAll(Enumerable.Range(0, Budget * 3).Select(i => Task.Run(() =>
            registry.TryAcquire("app-a", "cluster", Budget, interval, out _))))
            .WaitBoundedAsync("the first burst");
        Assert.Equal(Budget, first.Count(a => a));

        // Just before the boundary nothing may pass; after it, the budget is whole again.
        await Task.Delay(300);
        Assert.False(registry.TryAcquire("app-a", "cluster", Budget, interval, out _));

        await Task.Delay(150);
        var second = await Task.WhenAll(Enumerable.Range(0, Budget * 2).Select(i => Task.Run(() =>
            registry.TryAcquire("app-a", "cluster", Budget, interval, out _))))
            .WaitBoundedAsync("the second burst");
        Assert.Equal(Budget, second.Count(a => a));
    }

    [Fact]
    public async Task ConcurrentRebind_NoDisposedLimiter_KeepsBudgetExact()
    {
        // Review F1 regression: hammer one key from many threads while the configured limits
        // flip between two shapes (a rebind storm). No thread may observe an
        // ObjectDisposedException, and once the shape settles the budget must be exact —
        // replacement must never hand a fresh window to every racing thread.
        var registry = new CallerBudgetRegistry(TimeProvider.System);
        var interval = TimeSpan.FromSeconds(10);

        var errors = new ConcurrentQueue<Exception>();
        var storm = Enumerable.Range(0, 16).Select(i => Task.Run(() =>
        {
            try
            {
                for (var n = 0; n < 250; n++)
                {
                    var permits = (i + n) % 2 == 0 ? 1000 : 1001;
                    registry.TryAcquire("app-a", "cluster", permits, interval, out _);
                }
            }
            catch (Exception e)
            {
                errors.Enqueue(e);
            }

            return 0;
        })).ToList();

        await Task.WhenAll(storm).WaitBoundedAsync("the rebind storm");
        Assert.True(errors.IsEmpty, string.Join("; ", errors.Select(e => e.GetType().Name + ": " + e.Message)));

        // Settle on one shape: the next concurrent burst must admit exactly its budget.
        const int Budget = 5;
        var after = await Task.WhenAll(Enumerable.Range(0, 40).Select(i => Task.Run(() =>
            registry.TryAcquire("app-a", "cluster", Budget, interval, out _))))
            .WaitBoundedAsync("the settling burst");
        Assert.Equal(Budget, after.Count(a => a));
    }
}
