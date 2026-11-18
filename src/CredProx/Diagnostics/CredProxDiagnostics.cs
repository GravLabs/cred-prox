using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace CredProx;

/// <summary>
/// The <c>CredProx</c> <see cref="ActivitySource"/> and <see cref="Meter"/>. Core instruments: token fetch success/failure, token
/// cache hit/miss, token fetch latency, caller budget rejections and kill-switch refusals.
/// The throttle, resilience and health instruments live with their features in
/// CredProx.Operations on a meter of the same name and version — listeners see one meter.
/// Tags carry names only — never a secret value.
/// </summary>
internal static class CredProxDiagnostics
{
    public const string ActivitySourceName = "CredProx";
    public const string MeterName = "CredProx";

    private const string Version = "0.1.0";

    public static readonly ActivitySource ActivitySource = new(ActivitySourceName, Version);
    public static readonly Meter Meter = new(MeterName, Version);

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

    /// <summary>
    /// Caller budget rejections; tags: <c>credprox.caller</c>,
    /// <c>credprox.cluster</c>.
    /// </summary>
    public static readonly Counter<long> CallerBudgetRejections = Meter.CreateCounter<long>(
        "credprox.caller_throttle.rejections",
        description: "Requests rejected with 429 by a caller's per-app request budget.");

    /// <summary>
    /// Kill-switch refusals; tags: <c>credprox.kind</c>
    /// (<c>caller</c> or <c>cluster</c>) plus the disabled id (<c>credprox.caller</c>
    /// or <c>credprox.cluster</c>).
    /// </summary>
    public static readonly Counter<long> KillSwitchRejections = Meter.CreateCounter<long>(
        "credprox.killswitch.rejections",
        description: "Requests refused by the kill switch with 503 (disabled caller or cluster).");

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
