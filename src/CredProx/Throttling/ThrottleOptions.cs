using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// Outbound throttling options, bound from <c>CredProx:Throttling</c> at startup
/// (see <c>docs/credprox-plan.md</c> §8.4, §5.2 "Throttling"). The top-level values are
/// the defaults for every cluster; <see cref="Clusters"/> overrides them per YARP cluster
/// id. Limits are per cluster, never global.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class ThrottleOptions
{
    /// <summary>
    /// Permits allowed per <see cref="Interval"/> per cluster; 0 disables the rate limit.
    /// </summary>
    public int PermitsPerInterval { get; set; }

    /// <summary>The rate-limit window; only used when <see cref="PermitsPerInterval"/> is set.</summary>
    public TimeSpan Interval { get; set; } = TimeSpan.FromSeconds(1);

    /// <summary>Maximum in-flight requests per cluster; 0 disables the concurrency limit.</summary>
    public int MaxConcurrency { get; set; }

    /// <summary>
    /// How many requests may queue per cluster waiting for a permit; beyond this a request
    /// is rejected immediately with 429 (<c>credprox.throttled</c>).
    /// </summary>
    public int QueueLimit { get; set; } = 20;

    /// <summary>
    /// How long a queued request waits for a permit (or out of a vendor pause) before it
    /// is rejected with 429. Bounds the limiter's own queue wait.
    /// </summary>
    public TimeSpan MaxQueueWait { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// When <see langword="true"/> (default), a vendor <c>429</c> with <c>Retry-After</c>
    /// pauses the whole cluster for that duration; queued work waits, new work beyond the
    /// wait bound gets 429.
    /// </summary>
    public bool PauseOnVendorThrottle { get; set; } = true;

    /// <summary>Cap on a vendor-advertised pause, so a hostile Retry-After cannot wedge a cluster.</summary>
    public TimeSpan MaxPause { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>Per-cluster overrides keyed by YARP cluster id.</summary>
    public Dictionary<string, ThrottleClusterOptions> Clusters { get; } = new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// Per-cluster throttle overrides; <see langword="null"/> members inherit the default.
/// Bound from <c>CredProx:Throttling:Clusters:&lt;clusterId&gt;</c>.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class ThrottleClusterOptions
{
    /// <summary>Overrides <see cref="ThrottleOptions.PermitsPerInterval"/>.</summary>
    public int? PermitsPerInterval { get; set; }

    /// <summary>Overrides <see cref="ThrottleOptions.Interval"/>.</summary>
    public TimeSpan? Interval { get; set; }

    /// <summary>Overrides <see cref="ThrottleOptions.MaxConcurrency"/>.</summary>
    public int? MaxConcurrency { get; set; }

    /// <summary>Overrides <see cref="ThrottleOptions.QueueLimit"/>.</summary>
    public int? QueueLimit { get; set; }

    /// <summary>Overrides <see cref="ThrottleOptions.MaxQueueWait"/>.</summary>
    public TimeSpan? MaxQueueWait { get; set; }

    /// <summary>Overrides <see cref="ThrottleOptions.PauseOnVendorThrottle"/>.</summary>
    public bool? PauseOnVendorThrottle { get; set; }

    /// <summary>Overrides <see cref="ThrottleOptions.MaxPause"/>.</summary>
    public TimeSpan? MaxPause { get; set; }
}
