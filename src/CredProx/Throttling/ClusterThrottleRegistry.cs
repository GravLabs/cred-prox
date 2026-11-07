using System.Collections.Concurrent;
using System.Threading.RateLimiting;

namespace CredProx;

/// <summary>
/// Per-cluster outbound throttle state (limiter plus vendor-pause deadline), keyed by YARP
/// cluster id. Singleton: the state survives cluster-client recreation (a config reload
/// rebuilds handlers, not limiters). Options are bound once at startup; changing limits
/// takes a restart.
/// </summary>
internal sealed class ClusterThrottleRegistry(ThrottleOptions options, TimeProvider time)
{
    private readonly ConcurrentDictionary<string, ClusterThrottleState> _states = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>The effective, merged limits for one cluster.</summary>
    internal sealed record Effective(
        int PermitsPerInterval,
        TimeSpan Interval,
        int MaxConcurrency,
        int QueueLimit,
        TimeSpan MaxQueueWait,
        bool PauseOnVendorThrottle,
        TimeSpan MaxPause)
    {
        public bool HasLimits => PermitsPerInterval > 0 || MaxConcurrency > 0;
    }

    /// <summary>Permits the merged options for a cluster (defaults plus its overrides).</summary>
    internal Effective GetEffective(string clusterId)
    {
        var c = options.Clusters.TryGetValue(clusterId, out var o) ? o : null;
        return new Effective(
            c?.PermitsPerInterval ?? options.PermitsPerInterval,
            c?.Interval ?? options.Interval,
            c?.MaxConcurrency ?? options.MaxConcurrency,
            c?.QueueLimit ?? options.QueueLimit,
            c?.MaxQueueWait ?? options.MaxQueueWait,
            c?.PauseOnVendorThrottle ?? options.PauseOnVendorThrottle,
            c?.MaxPause ?? options.MaxPause);
    }

    /// <summary>Gets or creates the cluster's limiter state.</summary>
    public ClusterThrottleState GetOrCreate(string clusterId) =>
        _states.GetOrAdd(clusterId, static (id, reg) => reg.CreateState(id), this);

    private ClusterThrottleState CreateState(string clusterId)
    {
        var effective = GetEffective(clusterId);

        List<RateLimiter> limiters = [];
        if (effective.PermitsPerInterval > 0)
        {
            limiters.Add(new FixedWindowRateLimiter(
                effective.PermitsPerInterval,
                effective.Interval,
                effective.QueueLimit,
                time));
        }

        if (effective.MaxConcurrency > 0)
        {
            limiters.Add(new ConcurrencyLimiter(new ConcurrencyLimiterOptions
            {
                PermitLimit = effective.MaxConcurrency,
                QueueLimit = effective.QueueLimit,
            }));
        }

        var limiter = limiters.Count switch
        {
            0 => null,
            1 => limiters[0],
            _ => RateLimiter.CreateChained(limiters.ToArray()),
        };

        return new ClusterThrottleState(limiter, effective);
    }
}

/// <summary>
/// One cluster's throttle state: the chained limiter (nullable when no limits are
/// configured) and the vendor-pause deadline. The pause extends monotonically — a second
/// vendor 429 during a pause never shortens it.
/// </summary>
internal sealed class ClusterThrottleState(RateLimiter? limiter, ClusterThrottleRegistry.Effective effective)
{
    private long _pauseUntilUtcTicks;

    /// <summary>The cluster's limiter, or <see langword="null"/> when the cluster is unlimited.</summary>
    public RateLimiter? Limiter { get; } = limiter;

    /// <summary>The cluster's effective limits.</summary>
    public ClusterThrottleRegistry.Effective Effective { get; } = effective;

    /// <summary>Time left on the vendor pause, or <see cref="TimeSpan.Zero"/>.</summary>
    public TimeSpan PauseRemaining(TimeProvider time)
    {
        var until = Volatile.Read(ref _pauseUntilUtcTicks);
        if (until == 0)
        {
            return TimeSpan.Zero;
        }

        var remaining = new DateTimeOffset(until, TimeSpan.Zero) - time.GetUtcNow();
        return remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero;
    }

    /// <summary>Pauses the cluster until <paramref name="until"/>, extending any existing pause.</summary>
    public void PauseUntil(DateTimeOffset until)
    {
        while (true)
        {
            var current = Volatile.Read(ref _pauseUntilUtcTicks);
            if (until.UtcTicks <= current)
            {
                return;
            }

            if (Interlocked.CompareExchange(ref _pauseUntilUtcTicks, until.UtcTicks, current) == current)
            {
                return;
            }
        }
    }
}
