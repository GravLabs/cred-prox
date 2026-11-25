using System.Diagnostics.Metrics;

namespace CredProx;

/// <summary>
/// M50 usage-metering instruments on the shared <see cref="OperationsDiagnostics.Meter"/>
/// (name+version <c>CredProx</c>/<c>0.1.0</c> — ADR-0008: one meter scope per host, no new
/// meter name). The class loads only when the metering leg registers, so an unregistered
/// add-on creates no instruments.
/// Tags carry names only: the caller id from the caller-identity feature, the credential
/// and destination names from route metadata, the YARP route id, and a fixed status-class
/// bucket. Nothing traffic-shaped (no paths, queries, headers, bodies) and nothing secret
/// ever enters a tag; unresolvable values collapse to the fixed <c>anonymous</c> /
/// <c>unknown</c> buckets, so series cardinality is bounded by configuration (§5.2
/// cardinality guard).
/// </summary>
internal static class MeteringDiagnostics
{
    internal const string AnonymousCaller = "anonymous";
    internal const string Unknown = "unknown";

    internal const string CallerTag = "credprox.caller";
    internal const string CredentialTag = "credprox.credential";
    internal const string DestinationTag = "credprox.destination";
    internal const string RouteTag = "credprox.route";
    internal const string StatusClassTag = "credprox.status_class";

    /// <summary>Forwarded requests; tags: <c>credprox.caller</c>, <c>credprox.credential</c>, <c>credprox.destination</c>, <c>credprox.route</c>, <c>credprox.status_class</c>.</summary>
    internal static readonly Counter<long> Requests = OperationsDiagnostics.Meter.CreateCounter<long>(
        "credprox.requests",
        description: "Forwarded requests, tagged by caller, credential, destination, route and status class.");

    /// <summary>Request body bytes forwarded upstream; same tags as <see cref="Requests"/>.</summary>
    internal static readonly Histogram<long> RequestBytes = OperationsDiagnostics.Meter.CreateHistogram<long>(
        "credprox.request.bytes",
        unit: "By",
        description: "Body bytes forwarded upstream per metered request.");

    /// <summary>Response body bytes delivered to the caller; same tags as <see cref="Requests"/>.</summary>
    internal static readonly Histogram<long> ResponseBytes = OperationsDiagnostics.Meter.CreateHistogram<long>(
        "credprox.response.bytes",
        unit: "By",
        description: "Body bytes delivered to the caller per metered request.");

    /// <summary>Input tokens the provider reported; tags: caller, credential, destination, route.</summary>
    internal static readonly Counter<long> InputTokens = OperationsDiagnostics.Meter.CreateCounter<long>(
        "credprox.usage.input_tokens",
        unit: "{token}",
        description: "Input tokens reported by the provider's own usage report (opted-in routes only); a response that reports no usage is not recorded.");

    /// <summary>Output tokens the provider reported; tags: caller, credential, destination, route.</summary>
    internal static readonly Counter<long> OutputTokens = OperationsDiagnostics.Meter.CreateCounter<long>(
        "credprox.usage.output_tokens",
        unit: "{token}",
        description: "Output tokens reported by the provider's own usage report (opted-in routes only); a response that reports no usage is not recorded.");

    /// <summary>The fixed status-class bucket for a status code — one of <c>1xx</c>…<c>5xx</c>.</summary>
    internal static string StatusClass(int statusCode) => statusCode switch
    {
        < 100 or >= 600 => Unknown,
        < 200 => "1xx",
        < 300 => "2xx",
        < 400 => "3xx",
        < 500 => "4xx",
        _ => "5xx",
    };
}
