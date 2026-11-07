using System.Threading.RateLimiting;

namespace CredProx;

/// <summary>
/// A deterministic fixed-window <see cref="RateLimiter"/>: at most
/// <c>PermitsPerInterval</c> permits start each window, waiters queue FIFO (bounded by
/// <c>QueueLimit</c>) and are granted at the next window boundary. The framework's own
/// limiters have no <see cref="TimeProvider"/> hook, so the built-in rate limiter is this
/// subclass — it makes the rate window testable with <c>FakeTimeProvider</c> (§5.1) and
/// keeps the <see cref="RateLimiter"/> abstraction the chained pipeline expects.
/// </summary>
internal sealed class FixedWindowRateLimiter : RateLimiter
{
    private readonly int _permitsPerInterval;
    private readonly TimeSpan _interval;
    private readonly int _queueLimit;
    private readonly TimeProvider _time;
    private readonly object _gate = new();
    private readonly LinkedList<Waiter> _queue = new();
    private ITimer? _timer;
    private DateTimeOffset _windowStart;
    private int _remaining;
    private long _totalSuccessful;
    private long _totalFailed;
    private bool _disposed;

    public FixedWindowRateLimiter(int permitsPerInterval, TimeSpan interval, int queueLimit, TimeProvider time)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(permitsPerInterval, 1);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(interval, TimeSpan.Zero);
        ArgumentOutOfRangeException.ThrowIfLessThan(queueLimit, 0);
        ArgumentNullException.ThrowIfNull(time);

        _permitsPerInterval = permitsPerInterval;
        _interval = interval;
        _queueLimit = queueLimit;
        _time = time;
        _windowStart = time.GetUtcNow();
        _remaining = permitsPerInterval;
    }

    protected override ValueTask<RateLimitLease> AcquireAsyncCore(
        int permitCount,
        CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(permitCount, 1);
        if (permitCount > 1)
        {
            throw new ArgumentOutOfRangeException(nameof(permitCount), "This limiter grants one permit at a time.");
        }

        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            RollWindowLocked(_time.GetUtcNow());

            if (_remaining > 0 && _queue.Count == 0)
            {
                _remaining--;
                _totalSuccessful++;
                return ValueTask.FromResult<RateLimitLease>(new Lease(acquired: true));
            }

            if (_queue.Count >= _queueLimit)
            {
                _totalFailed++;
                return ValueTask.FromResult<RateLimitLease>(
                    new Lease(acquired: false, RetryAfter(_windowStart + _interval, _time)));
            }

            if (cancellationToken.IsCancellationRequested)
            {
                // The public AcquireAsync already throws for a pre-cancelled token; this
                // covers the race where cancellation lands between that check and the
                // Register below, where the callback would fire synchronously and race
                // the Registration assignment. Same lease Cancel produces, no queue slot.
                _totalFailed++;
                return ValueTask.FromResult<RateLimitLease>(
                    new Lease(acquired: false, RetryAfter(_windowStart + _interval, _time)));
            }

            var waiter = new Waiter(new TaskCompletionSource<RateLimitLease>(TaskCreationOptions.RunContinuationsAsynchronously));
            waiter.Node = _queue.AddLast(waiter);
            EnsureTimerLocked();

            if (cancellationToken.CanBeCanceled)
            {
                // The callback (Cancel) takes _gate, so it cannot run before this
                // assignment completes: the field is always set when the callback fires.
                waiter.Registration = cancellationToken.Register(static state =>
                {
                    var (self, w) = ((FixedWindowRateLimiter, Waiter))state!;
                    self.Cancel(w);
                }, (this, waiter));
            }

            return new ValueTask<RateLimitLease>(waiter.Tcs.Task);
        }
    }

    protected override RateLimitLease AttemptAcquireCore(int permitCount)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(permitCount, 1);
        if (permitCount > 1)
        {
            throw new ArgumentOutOfRangeException(nameof(permitCount), "This limiter grants one permit at a time.");
        }

        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            RollWindowLocked(_time.GetUtcNow());

            if (_remaining > 0 && _queue.Count == 0)
            {
                _remaining--;
                _totalSuccessful++;
                return new Lease(acquired: true);
            }

            _totalFailed++;
            return new Lease(acquired: false, RetryAfter(_windowStart + _interval, _time));
        }
    }

    public override RateLimiterStatistics GetStatistics()
    {
        lock (_gate)
        {
            return new RateLimiterStatistics
            {
                CurrentAvailablePermits = _remaining,
                CurrentQueuedCount = _queue.Count,
                TotalSuccessfulLeases = _totalSuccessful,
                TotalFailedLeases = _totalFailed,
            };
        }
    }

    public override TimeSpan? IdleDuration
    {
        get
        {
            lock (_gate)
            {
                return _queue.Count == 0 ? TimeSpan.Zero : RetryAfter(_windowStart + _interval, _time);
            }
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            List<Waiter> pending;
            lock (_gate)
            {
                _disposed = true;
                _timer?.Dispose();
                _timer = null;
                pending = [.. _queue];
                _queue.Clear();
            }

            foreach (var waiter in pending)
            {
                waiter.Tcs.TrySetResult(new Lease(acquired: false));
                waiter.Registration.Dispose();
            }
        }

        base.Dispose(disposing);
    }

    private void Cancel(Waiter waiter)
    {
        TimeSpan retryAfter;
        lock (_gate)
        {
            if (waiter.Node?.List is null)
            {
                return; // already granted or completed by Dispose
            }

            _queue.Remove(waiter.Node);
            waiter.Node = null;
            _totalFailed++;
            retryAfter = RetryAfter(_windowStart + _interval, _time);
        }

        waiter.Tcs.TrySetResult(new Lease(acquired: false, retryAfter));

        // Runs on the callback's own thread: disposing a registration from inside its
        // callback does not wait on itself.
        waiter.Registration.Dispose();
    }

    private void RollWindowLocked(DateTimeOffset now)
    {
        while (now >= _windowStart + _interval)
        {
            _windowStart += _interval;
            _remaining = _permitsPerInterval;
        }
    }

    private void EnsureTimerLocked()
    {
        if (_timer is not null)
        {
            return;
        }

        _timer = _time.CreateTimer(
            static state => ((FixedWindowRateLimiter)state!).Tick(),
            this,
            RetryAfter(_windowStart + _interval, _time),
            Timeout.InfiniteTimeSpan);
    }

    private void Tick()
    {
        List<Waiter> granted = [];
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            RollWindowLocked(_time.GetUtcNow());
            while (_remaining > 0 && _queue.First is { } first)
            {
                _queue.RemoveFirst();
                _remaining--;
                _totalSuccessful++;
                granted.Add(first.Value);
            }

            if (_queue.First is not null)
            {
                _timer!.Change(RetryAfter(_windowStart + _interval, _time), Timeout.InfiniteTimeSpan);
            }
            else
            {
                // Drop the timer entirely so EnsureTimerLocked creates a fresh one for the
                // next waiter: a merely-disarmed timer would never fire again and the
                // queue would stall forever after its first full drain.
                _timer?.Dispose();
                _timer = null;
            }
        }

        foreach (var waiter in granted)
        {
            waiter.Tcs.TrySetResult(new Lease(acquired: true));
            waiter.Registration.Dispose();
        }
    }

    private static TimeSpan RetryAfter(DateTimeOffset windowEnd, TimeProvider time)
    {
        var remaining = windowEnd - time.GetUtcNow();
        return remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero;
    }

    /// <summary>One queued acquirer; <see cref="Node"/> is <see langword="null"/> once it left the queue.</summary>
    private sealed class Waiter(TaskCompletionSource<RateLimitLease> tcs)
    {
        public TaskCompletionSource<RateLimitLease> Tcs { get; } = tcs;

        public LinkedListNode<Waiter>? Node { get; set; }

        /// <summary>
        /// The caller-token registration; disposed on whichever path completes the waiter
        /// (grant, cancel, limiter dispose) so a long-lived token never keeps the waiter
        /// and limiter alive. Only touched after the queue lock is released — disposing a
        /// registration waits for a running callback, and that callback takes the lock.
        /// </summary>
        public CancellationTokenRegistration Registration;
    }

    private sealed class Lease(bool acquired, TimeSpan? retryAfter = null) : RateLimitLease
    {
        public override bool IsAcquired => acquired;

        public override IEnumerable<string> MetadataNames =>
            retryAfter is null ? [] : [MetadataName.RetryAfter.Name];

        public override bool TryGetMetadata(string metadataName, out object? metadata)
        {
            if (retryAfter is { } value && metadataName == MetadataName.RetryAfter.Name)
            {
                metadata = value;
                return true;
            }

            metadata = null;
            return false;
        }
    }
}
