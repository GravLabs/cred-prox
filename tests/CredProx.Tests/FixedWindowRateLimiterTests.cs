using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading.RateLimiting;
using CredProx;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage of <see cref="FixedWindowRateLimiter"/>: the discriminating
/// witnesses the composed ThrottleHandler tests do not reach — argument guards on the
/// async surface, per-path statistics counters, the pre-cancelled-token core path,
/// dispose-time queue and timer release, timer lifecycle (witnessed by a decorating
/// TimeProvider), and the lease metadata surface.
/// </summary>
public sealed class FixedWindowRateLimiterTests
{
    private static readonly MethodInfo AcquireAsyncCore =
        typeof(FixedWindowRateLimiter).GetMethod("AcquireAsyncCore", BindingFlags.NonPublic | BindingFlags.Instance)!;

    private static readonly MethodInfo AttemptAcquireCore =
        typeof(FixedWindowRateLimiter).GetMethod("AttemptAcquireCore", BindingFlags.NonPublic | BindingFlags.Instance)!;

    // ---- argument guards on both cores (the public wrappers' own <1 guard cannot be
    // bypassed from outside, so the core guards are driven directly; the >1 case is
    // reachable through the public surface) ----

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Cores_GuardZeroAndPermitCountOneOnly(bool async)
    {
        var limiter = new FixedWindowRateLimiter(1, TimeSpan.FromSeconds(1), 5, new FakeTimeProvider());
        using (limiter)
        {
            var core = async ? AcquireAsyncCore : AttemptAcquireCore;
            var args = async
                ? new object?[] { 0, CancellationToken.None }
                : new object?[] { 0 };

            // Direct core call with 0: the guard must refuse (statement-removal mutant
            // falls through to the grant path and hands out a lease).
            var ex = InvokeExpectThrow(core, limiter, args);
            var aore = Assert.IsType<ArgumentOutOfRangeException>(ex);
            Assert.Equal("permitCount", aore.ParamName);
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task BothSurfaces_RejectMultiPermitWithPinnedMessage(bool async)
    {
        var limiter = new FixedWindowRateLimiter(1, TimeSpan.FromSeconds(1), 5, new FakeTimeProvider());
        using (limiter)
        {
            // 2 passes the public wrappers' <1 guard; only the core's >1 check refuses,
            // so the equality mutant (permitCount < 1) would silently grant.
            ArgumentOutOfRangeException ex = async
                ? await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => limiter.AcquireAsync(2).AsTask())
                : Assert.Throws<ArgumentOutOfRangeException>(() => limiter.AttemptAcquire(2));

            Assert.Equal("permitCount", ex.ParamName);
            Assert.Contains("This limiter grants one permit at a time.", ex.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task AcquireAsync_PreCancelledTokenCorePath_FailsWithoutQueueSlot()
    {
        // The public AcquireAsync refuses a pre-cancelled token before reaching the
        // core, so the core's race-window branch (:72) is only reachable by calling the
        // core exactly as that race does: past the public check, token already cancelled.
        var time = new FakeTimeProvider();
        using var limiter = new FixedWindowRateLimiter(1, TimeSpan.FromSeconds(1), 5, time);
        Assert.True(limiter.AttemptAcquire(1).IsAcquired);

        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var pending = (ValueTask<RateLimitLease>)AcquireAsyncCore.Invoke(limiter, [1, cts.Token])!;
        using var lease = await pending;

        Assert.False(lease.IsAcquired);
        Assert.True(lease.TryGetMetadata(MetadataName.RetryAfter, out TimeSpan retryAfter));
        Assert.Equal(TimeSpan.FromSeconds(1), retryAfter);
        var statistics = limiter.GetStatistics();
        Assert.Equal(1, statistics.TotalFailedLeases);
        Assert.Equal(0, statistics.CurrentQueuedCount);
    }

    // ---- per-path counters (each path's _totalSuccessful/_totalFailed is its own row) ----

    [Fact]
    public async Task AcquireAsync_FastPath_CountsSuccessful()
    {
        var time = new FakeTimeProvider();
        using var limiter = new FixedWindowRateLimiter(2, TimeSpan.FromSeconds(1), 5, time);

        using var lease = await limiter.AcquireAsync(1);

        Assert.True(lease.IsAcquired);
        var statistics = limiter.GetStatistics();
        Assert.Equal(1, statistics.TotalSuccessfulLeases);
        Assert.Equal(1, statistics.CurrentAvailablePermits);
        Assert.Equal(0, statistics.TotalFailedLeases);
    }

    [Fact]
    public async Task AcquireAsync_QueueFull_DeniesWithWindowRemainingAndCountsFailed()
    {
        var time = new FakeTimeProvider();
        using var limiter = new FixedWindowRateLimiter(1, TimeSpan.FromSeconds(1), 0, time);
        Assert.True(limiter.AttemptAcquire(1).IsAcquired);

        time.Advance(TimeSpan.FromMilliseconds(250));
        using var lease = await limiter.AcquireAsync(1);

        Assert.False(lease.IsAcquired);
        Assert.True(lease.TryGetMetadata(MetadataName.RetryAfter, out TimeSpan retryAfter));
        Assert.Equal(TimeSpan.FromMilliseconds(750), retryAfter);
        var statistics = limiter.GetStatistics();
        Assert.Equal(1, statistics.TotalFailedLeases);
        Assert.Equal(0, statistics.CurrentQueuedCount);
    }

    [Fact]
    public void AttemptAcquire_Denial_CountsFailed()
    {
        var time = new FakeTimeProvider();
        using var limiter = new FixedWindowRateLimiter(1, TimeSpan.FromSeconds(1), 0, time);

        Assert.True(limiter.AttemptAcquire(1).IsAcquired);
        Assert.False(limiter.AttemptAcquire(1).IsAcquired);

        var statistics = limiter.GetStatistics();
        Assert.Equal(1, statistics.TotalSuccessfulLeases);
        Assert.Equal(1, statistics.TotalFailedLeases);
    }

    [Fact]
    public async Task CancelledWaiter_FailureCountAndRetryAfter()
    {
        var time = new FakeTimeProvider();
        using var limiter = new FixedWindowRateLimiter(1, TimeSpan.FromSeconds(1), 5, time);
        Assert.True(limiter.AttemptAcquire(1).IsAcquired);

        using var cts = new CancellationTokenSource();
        var queued = limiter.AcquireAsync(1, cts.Token);
        cts.Cancel();
        using var lease = await queued;

        Assert.False(lease.IsAcquired);
        Assert.True(lease.TryGetMetadata(MetadataName.RetryAfter, out TimeSpan retryAfter));
        Assert.Equal(TimeSpan.FromSeconds(1), retryAfter);
        var statistics = limiter.GetStatistics();
        Assert.Equal(1, statistics.TotalFailedLeases);
        Assert.Equal(1, statistics.TotalSuccessfulLeases);
    }

    // ---- window roll and disposed gates on each entry point ----

    [Fact]
    public async Task AcquireAsync_RollsStaleWindowInFastPath()
    {
        // Without the core's own RollWindowLocked the stale _remaining == 0 survives and
        // the acquire queues instead of granting.
        var time = new FakeTimeProvider();
        using var limiter = new FixedWindowRateLimiter(1, TimeSpan.FromSeconds(1), 5, time);
        Assert.True(limiter.AttemptAcquire(1).IsAcquired);

        time.Advance(TimeSpan.FromSeconds(1));
        var result = limiter.AcquireAsync(1);

        Assert.True(result.IsCompletedSuccessfully);
        using var lease = await result;
        Assert.True(lease.IsAcquired);
    }

    [Fact]
    public async Task BothSurfaces_AfterDispose_ThrowObjectDisposed()
    {
        var time = new FakeTimeProvider();
        var limiter = new FixedWindowRateLimiter(1, TimeSpan.FromSeconds(1), 5, time);
        limiter.Dispose();

        await Assert.ThrowsAsync<ObjectDisposedException>(() => limiter.AcquireAsync(1).AsTask());
        Assert.Throws<ObjectDisposedException>(() => limiter.AttemptAcquire(1));
    }

    // ---- IdleDuration is the stale-window read: queued means "until the boundary" ----

    [Fact]
    public async Task IdleDuration_QueuedWaiterIsWindowRemaining()
    {
        var time = new FakeTimeProvider();
        using var limiter = new FixedWindowRateLimiter(1, TimeSpan.FromSeconds(1), 5, time);
        Assert.True(limiter.AttemptAcquire(1).IsAcquired);
        var queued = limiter.AcquireAsync(1);
        Assert.False(queued.IsCompleted);

        Assert.Equal(TimeSpan.FromSeconds(1), limiter.IdleDuration);
        time.Advance(TimeSpan.FromMilliseconds(400));
        Assert.Equal(TimeSpan.FromMilliseconds(600), limiter.IdleDuration);

        limiter.Dispose();
        await queued;
    }

    // ---- lease metadata surface ----

    [Fact]
    public async Task LeaseMetadata_MatchesAcquisition()
    {
        var time = new FakeTimeProvider();
        using var limiter = new FixedWindowRateLimiter(1, TimeSpan.FromSeconds(1), 0, time);
        using var acquired = await limiter.AcquireAsync(1);

        Assert.Empty(acquired.MetadataNames);
        Assert.False(acquired.TryGetMetadata(MetadataName.RetryAfter, out TimeSpan acquiredMeta));
        Assert.Equal(TimeSpan.Zero, acquiredMeta);

        using var denied = await limiter.AcquireAsync(1);
        Assert.Equal([MetadataName.RetryAfter.Name], denied.MetadataNames);
        Assert.False(denied.TryGetMetadata("Some.Other.Metadata", out object? wrongMeta));
        Assert.Null(wrongMeta);
    }

    // ---- dispose releases the queue and the timer; timers are one per drain cycle ----

    [Fact]
    public async Task Dispose_ClearsQueueAndDisposesLiveTimer()
    {
        var tracking = new TimerTrackingTimeProvider(new FakeTimeProvider());
        var limiter = new FixedWindowRateLimiter(1, TimeSpan.FromSeconds(1), 5, tracking);
        Assert.True(limiter.AttemptAcquire(1).IsAcquired);
        var queued = limiter.AcquireAsync(1);
        Assert.Equal(1, tracking.CreatedTimers);

        limiter.Dispose();

        using var lease = await queued;
        Assert.False(lease.IsAcquired);
        Assert.Equal(0, limiter.GetStatistics().CurrentQueuedCount);
        Assert.Equal(1, tracking.DisposedTimers);
    }

    [Fact]
    public async Task Timer_OnePerDrainCycle_DroppedOnFullDrainRecreatedForNext()
    {
        var time = new FakeTimeProvider();
        var tracking = new TimerTrackingTimeProvider(time);
        using var limiter = new FixedWindowRateLimiter(1, TimeSpan.FromSeconds(1), 5, tracking);
        Assert.True(limiter.AttemptAcquire(1).IsAcquired);

        var first = limiter.AcquireAsync(1);
        var second = limiter.AcquireAsync(1);
        Assert.Equal(1, tracking.CreatedTimers); // a live timer must not be re-created per waiter

        time.Advance(TimeSpan.FromSeconds(1)); // grants the first; the queue stays, timer rearmed
        using (var lease = await first)
        {
            Assert.True(lease.IsAcquired);
        }

        Assert.Equal(0, tracking.DisposedTimers);
        Assert.Equal(1, tracking.CreatedTimers);

        time.Advance(TimeSpan.FromSeconds(1)); // grants the last; the full drain drops the timer
        using (var lease = await second)
        {
            Assert.True(lease.IsAcquired);
        }

        Assert.Equal(1, tracking.DisposedTimers);
        Assert.Equal(1, tracking.CreatedTimers);

        time.Advance(TimeSpan.FromSeconds(1));
        Assert.True(limiter.AttemptAcquire(1).IsAcquired);
        var third = limiter.AcquireAsync(1);
        Assert.Equal(2, tracking.CreatedTimers); // the dropped timer means a fresh one arms

        time.Advance(TimeSpan.FromSeconds(1));
        using var thirdLease = await third;
        Assert.True(thirdLease.IsAcquired);
    }

    // ---- the cancellation registration must die on the cancel path even while the
    // token source stays alive: a leaked registration would root the limiter (the GC
    // witness; GC.KeepAlive(cts) is load-bearing exactly as in the grant-path twin) ----

    [Fact]
    public async Task CancelledWaiter_LiveTokenSourceDoesNotRootLimiter()
    {
        var cts = new CancellationTokenSource(); // deliberately not disposed before the GC
        try
        {
            var weak = await QueueAndCancelNoRegistrationDisposeAsync(cts);

            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
            Assert.False(weak.IsAlive);
        }
        finally
        {
            cts.Dispose();
            GC.KeepAlive(cts);
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static async Task<WeakReference> QueueAndCancelNoRegistrationDisposeAsync(CancellationTokenSource cts)
    {
        var limiter = new FixedWindowRateLimiter(1, TimeSpan.FromSeconds(1), 5, new FakeTimeProvider());
        Assert.True(limiter.AttemptAcquire(1).IsAcquired);
        var queued = limiter.AcquireAsync(1, cts.Token);
        cts.Cancel();
        using var lease = await queued;
        Assert.False(lease.IsAcquired);
        limiter.Dispose();
        return new WeakReference(limiter);
    }

    private static Exception InvokeExpectThrow(MethodInfo core, FixedWindowRateLimiter limiter, object?[] args)
    {
        try
        {
            core.Invoke(limiter, args);
        }
        catch (TargetInvocationException ex)
        {
            return ex.InnerException!;
        }

        throw new Xunit.Sdk.XunitException("core guard returned without throwing");
    }

    /// <summary>Decorates the fake to make timer creation/disposal countable (the fake
    /// exposes no timer-introspection API at its 10.0.0 version).</summary>
    private sealed class TimerTrackingTimeProvider(FakeTimeProvider inner) : TimeProvider
    {
        public int CreatedTimers { get; private set; }

        public int DisposedTimers { get; private set; }

        public override DateTimeOffset GetUtcNow() => inner.GetUtcNow();

        public override long GetTimestamp() => inner.GetTimestamp();

        public override long TimestampFrequency => inner.TimestampFrequency;

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            CreatedTimers++;
            return new Tracked(inner.CreateTimer(callback, state, dueTime, period), () => DisposedTimers++);
        }

        private sealed class Tracked(ITimer inner, Action onDispose) : ITimer
        {
            public bool Change(TimeSpan dueTime, TimeSpan period) => inner.Change(dueTime, period);

            public void Dispose()
            {
                onDispose();
                inner.Dispose();
            }

            public ValueTask DisposeAsync()
            {
                onDispose();
                return inner.DisposeAsync();
            }
        }
    }

    // ---- M31 batch-2 survivors ----

    [Fact]
    public void Ctor_NegativeQueueLimit_ThrowsArgumentOutOfRangeNamingQueueLimit()
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => new FixedWindowRateLimiter(1, TimeSpan.FromSeconds(1), -1, new FakeTimeProvider()));

        Assert.Equal("queueLimit", error.ParamName);
    }

    [Fact]
    public async Task ElapsedWindow_RefillsOnTheNextAcquire()
    {
        // The async path's refill is AcquireAsyncCore's own RollWindowLocked call: with
        // the window timer disarmed only that line can re-admit after the interval
        // elapsed. queueLimit 0 makes the mutant reject at once instead of queueing.
        var time = new SilentTimerTimeProvider();
        using var limiter = new FixedWindowRateLimiter(1, TimeSpan.FromSeconds(1), 0, time);
        using var first = await limiter.AcquireAsync(1);
        Assert.True(first.IsAcquired);

        time.Advance(TimeSpan.FromSeconds(1.1));
        using var second = await limiter.AcquireAsync(1);

        Assert.True(second.IsAcquired, "an elapsed window must refill on the next acquire");
    }

    /// <summary>FakeTimeProvider that never arms the window timer: the acquire path is
    /// the only refiller.</summary>
    private sealed class SilentTimerTimeProvider : FakeTimeProvider
    {
        public override System.Threading.ITimer CreateTimer(
            System.Threading.TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period) =>
            new NoopTimer();

        private sealed class NoopTimer : System.Threading.ITimer
        {
            public bool Change(TimeSpan dueTime, TimeSpan period) => true;

            public void Dispose()
            {
            }

            public ValueTask DisposeAsync() => default;
        }
    }
}
