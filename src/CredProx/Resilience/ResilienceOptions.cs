using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// Resilience adapter options, bound from <c>CredProx:Resilience</c> at startup
/// (see <c>docs/credprox-plan.md</c> §8.4, §5.2 "Resilience"). The top-level values are
/// the defaults for every cluster; <see cref="Clusters"/> overrides them per YARP cluster
/// id. Each cluster gets its own retry/timeout pipeline over one shared circuit breaker.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class ResilienceOptions
{
    /// <summary>Timeout for a single upstream attempt; a fresh one applies to each retry.</summary>
    public TimeSpan AttemptTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Maximum retry attempts after the first (idempotent methods only unless enabled).</summary>
    public int MaxRetries { get; set; } = 3;

    /// <summary>Base delay between retry attempts (exponential backoff with jitter).</summary>
    public TimeSpan RetryBaseDelay { get; set; } = TimeSpan.FromMilliseconds(500);

    /// <summary>
    /// When <see langword="true"/>, non-idempotent methods (POST and friends) are retried
    /// too — only ever with a buffered body within <see cref="MaxRetriedBodyBytes"/>.
    /// Default <see langword="false"/>: POST is never retried unless you say so.
    /// </summary>
    public bool RetryNonIdempotent { get; set; }

    /// <summary>
    /// Cap on a retried request body. A body of unknown length (streamed) or over the cap
    /// is never buffered and its request is never retried — same rule as refresh-on-401.
    /// </summary>
    public long MaxRetriedBodyBytes { get; set; } = 1024 * 1024;

    /// <summary>Failure ratio (0..1) that opens the circuit within the sampling window.</summary>
    public double FailureRatio { get; set; } = 0.5;

    /// <summary>Minimum requests in the sampling window before the ratio can open the circuit.</summary>
    public int MinimumThroughput { get; set; } = 8;

    /// <summary>Sliding window the failure ratio is measured over.</summary>
    public TimeSpan SamplingDuration { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>How long an open circuit stays open before it half-opens to probe.</summary>
    public TimeSpan BreakDuration { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Per-cluster overrides keyed by YARP cluster id.</summary>
    public Dictionary<string, ResilienceClusterOptions> Clusters { get; } = new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// Per-cluster resilience overrides; <see langword="null"/> members inherit the default.
/// Bound from <c>CredProx:Resilience:Clusters:&lt;clusterId&gt;</c>.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class ResilienceClusterOptions
{
    /// <summary>Overrides <see cref="ResilienceOptions.AttemptTimeout"/>.</summary>
    public TimeSpan? AttemptTimeout { get; set; }

    /// <summary>Overrides <see cref="ResilienceOptions.MaxRetries"/>.</summary>
    public int? MaxRetries { get; set; }

    /// <summary>Overrides <see cref="ResilienceOptions.RetryBaseDelay"/>.</summary>
    public TimeSpan? RetryBaseDelay { get; set; }

    /// <summary>Overrides <see cref="ResilienceOptions.RetryNonIdempotent"/>.</summary>
    public bool? RetryNonIdempotent { get; set; }

    /// <summary>Overrides <see cref="ResilienceOptions.MaxRetriedBodyBytes"/>.</summary>
    public long? MaxRetriedBodyBytes { get; set; }

    /// <summary>Overrides <see cref="ResilienceOptions.FailureRatio"/>.</summary>
    public double? FailureRatio { get; set; }

    /// <summary>Overrides <see cref="ResilienceOptions.MinimumThroughput"/>.</summary>
    public int? MinimumThroughput { get; set; }

    /// <summary>Overrides <see cref="ResilienceOptions.SamplingDuration"/>.</summary>
    public TimeSpan? SamplingDuration { get; set; }

    /// <summary>Overrides <see cref="ResilienceOptions.BreakDuration"/>.</summary>
    public TimeSpan? BreakDuration { get; set; }
}
