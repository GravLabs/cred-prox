using System.Collections.Concurrent;
using System.Diagnostics.Metrics;

namespace CredProx;

/// <summary>
/// The instruments of the CredProx.Operations package, on their own <see cref="Meter"/>
/// whose name and version are identical to the core's — readers key meters by name and
/// version, so a host sees one <c>CredProx</c> scope, and every instrument name,
/// description and tag is byte-identical to the core era.
/// Throttle rejections and vendor pauses, resilience retries and circuit opens, and the
/// health gauges. Tags carry names only — never a secret value.
/// </summary>
internal static class OperationsDiagnostics
{
    private const string MeterName = "CredProx";
    private const string Version = "0.1.0";

    internal static readonly Meter Meter = new(MeterName, Version);

    private static readonly ConcurrentDictionary<string, double> CertificateDaysToExpiry = new();
    private static readonly ConcurrentDictionary<string, (string Name, string Kind, int Status)> HealthStatuses = new();

    static OperationsDiagnostics()
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

    /// <summary>Throttle rejections; tag: <c>credprox.cluster</c>.</summary>
    public static readonly Counter<long> ThrottleRejections = Meter.CreateCounter<long>(
        "credprox.throttle.rejected",
        description: "Requests rejected with 429 by the outbound throttle (queue full or wait exceeded).");

    /// <summary>Vendor-429 cluster pauses; tag: <c>credprox.cluster</c>.</summary>
    public static readonly Counter<long> ThrottlePauses = Meter.CreateCounter<long>(
        "credprox.throttle.paused",
        description: "Times a vendor 429 paused its cluster for the advertised Retry-After.");

    /// <summary>Resilience retries; tag: <c>credprox.cluster</c>.</summary>
    public static readonly Counter<long> ResilienceRetries = Meter.CreateCounter<long>(
        "credprox.resilience.retried",
        description: "Outbound attempts retried by the resilience adapter.");

    /// <summary>Circuit-breaker opens; tag: <c>credprox.cluster</c>.</summary>
    public static readonly Counter<long> CircuitOpened = Meter.CreateCounter<long>(
        "credprox.resilience.circuit_opened",
        description: "Times a cluster's circuit breaker opened.");
}
