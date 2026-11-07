using System.Diagnostics.CodeAnalysis;

namespace CredProx.Abstractions;

/// <summary>
/// Receives one audit record per proxied call. Built-ins write to <c>ILogger</c> and
/// OpenTelemetry logs. Redaction happens before the record reaches the sink, so a sink
/// never sees secret values; a failing sink must never fail the proxied request.
/// </summary>
[Experimental("CREDPROX001")]
public interface IAuditSink
{
    /// <summary>
    /// Writes one audit record.
    /// </summary>
    /// <param name="eventName">The record type, for example <c>credprox.proxied_call</c>.</param>
    /// <param name="fields">
    /// The record fields: caller, route, vendor, method, path template, status, latency,
    /// bytes and credential name — never a credential or secret value.
    /// </param>
    /// <param name="cancellationToken">Cancels the write.</param>
    ValueTask WriteAsync(
        string eventName,
        IReadOnlyDictionary<string, object?> fields,
        CancellationToken cancellationToken);
}
