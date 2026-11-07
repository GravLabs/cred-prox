using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace CredProx;

/// <summary>
/// The <c>CredProx</c> <see cref="ActivitySource"/> and <see cref="Meter"/> (see
/// <c>docs/credprox-plan.md</c> §3.3). Instruments: token fetch success/failure, token cache
/// hit/miss, token fetch latency, and — since M7 — credential health status and
/// certificate days-to-expiry. Tags carry names only — never a secret value.
/// </summary>
internal static class CredProxDiagnostics
{
    public const string ActivitySourceName = "CredProx";
    public const string MeterName = "CredProx";

    private const string Version = "0.1.0";

    public static readonly ActivitySource ActivitySource = new(ActivitySourceName, Version);
    public static readonly Meter Meter = new(MeterName, Version);

    private static readonly ConcurrentDictionary<string, double> CertificateDaysToExpiry = new();
    private static readonly ConcurrentDictionary<string, (string Name, string Kind, int Status)> HealthStatuses = new();

    static CredProxDiagnostics()
    {
        Meter.CreateObservableGauge(
            "credprox.certificate.days_to_expiry",
            () => CertificateDaysToExpiry.Select(kv => new Measurement<double>(
                kv.Value,
                new KeyValuePair<string, object?>("credprox.connection", kv.Key))),
            unit: "d",
            description: "Days until each connection's client certificate expires (negative once expired).");

        Meter.CreateObservableGauge(
            "credprox.health.status",
            () => HealthStatuses.Select(kv => new Measurement<double>(
                kv.Value.Status,
                new KeyValuePair<string, object?>("credprox.item", kv.Value.Name),
                new KeyValuePair<string, object?>("credprox.kind", kv.Value.Kind))),
            description: "Latest health status (0 healthy, 1 degraded, 2 unhealthy) by item "
                + "(kind: credential, connection or probe).");
    }

    /// <summary>Records a connection's certificate days-to-expiry for the gauge.</summary>
    public static void RecordCertificateDaysToExpiry(string connection, double days) =>
        CertificateDaysToExpiry[connection] = days;

    /// <summary>Records the latest health status of one item (credential/connection/probe).</summary>
    public static void RecordHealthStatus(string kind, string name, int status) =>
        HealthStatuses[$"{kind}:{name}"] = (name, kind, status);

    /// <summary>Token fetch attempts; tags: <c>credprox.credential</c>, <c>outcome</c>.</summary>
    public static readonly Counter<long> TokenFetches = Meter.CreateCounter<long>(
        "credprox.token.fetches",
        description: "Token fetch attempts by credential and outcome (success|failure).");

    /// <summary>Token cache results; tags: <c>credprox.credential</c>, <c>result</c>.</summary>
    public static readonly Counter<long> TokenCacheResults = Meter.CreateCounter<long>(
        "credprox.token.cache",
        description: "Token cache results by credential (hit|miss).");

    /// <summary>Token fetch duration in seconds; tag: <c>credprox.credential</c>.</summary>
    public static readonly Histogram<double> TokenFetchDuration = Meter.CreateHistogram<double>(
        "credprox.token.fetch.duration",
        unit: "s",
        description: "Wall-clock duration of token fetches by credential.");

    /// <summary>Throttle rejections; tag: <c>credprox.cluster</c>.</summary>
    public static readonly Counter<long> ThrottleRejections = Meter.CreateCounter<long>(
        "credprox.throttle.rejected",
        description: "Requests rejected with 429 by the outbound throttle (queue full or wait exceeded).");

    /// <summary>Vendor-429 cluster pauses; tag: <c>credprox.cluster</c>.</summary>
    public static readonly Counter<long> ThrottlePauses = Meter.CreateCounter<long>(
        "credprox.throttle.paused",
        description: "Times a vendor 429 paused its cluster for the advertised Retry-After.");

    /// <summary>
    /// Caller budget rejections (M15, plan §3.7); tags: <c>credprox.caller</c>,
    /// <c>credprox.cluster</c>.
    /// </summary>
    public static readonly Counter<long> CallerBudgetRejections = Meter.CreateCounter<long>(
        "credprox.caller_throttle.rejections",
        description: "Requests rejected with 429 by a caller's per-app request budget.");

    /// <summary>
    /// Kill-switch refusals (M18, plan §8.4); tags: <c>credprox.kind</c>
    /// (<c>caller</c> or <c>cluster</c>) plus the disabled id (<c>credprox.caller</c>
    /// or <c>credprox.cluster</c>).
    /// </summary>
    public static readonly Counter<long> KillSwitchRejections = Meter.CreateCounter<long>(
        "credprox.killswitch.rejections",
        description: "Requests refused by the kill switch with 503 (disabled caller or cluster).");

    /// <summary>Resilience retries; tag: <c>credprox.cluster</c>.</summary>
    public static readonly Counter<long> ResilienceRetries = Meter.CreateCounter<long>(
        "credprox.resilience.retried",
        description: "Outbound attempts retried by the resilience adapter.");

    /// <summary>Circuit-breaker opens; tag: <c>credprox.cluster</c>.</summary>
    public static readonly Counter<long> CircuitOpened = Meter.CreateCounter<long>(
        "credprox.resilience.circuit_opened",
        description: "Times a cluster's circuit breaker opened.");

    /// <summary>
    /// Records one token fetch outcome: the success/failure counter and the duration
    /// histogram. Call with the stopwatch stopped.
    /// </summary>
    public static void RecordFetch(string credential, bool success, double seconds)
    {
        var tags = new KeyValuePair<string, object?>[2]
        {
            new("credprox.credential", credential),
            new("outcome", success ? "success" : "failure"),
        };
        TokenFetches.Add(1, tags);
        TokenFetchDuration.Record(seconds, new KeyValuePair<string, object?>("credprox.credential", credential));
    }

    /// <summary>Records one token cache result (hit or miss) for a credential.</summary>
    public static void RecordCacheResult(string credential, bool hit)
    {
        TokenCacheResults.Add(
            1,
            new KeyValuePair<string, object?>("credprox.credential", credential),
            new KeyValuePair<string, object?>("result", hit ? "hit" : "miss"));
    }
}
