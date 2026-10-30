using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Yarp.ReverseProxy.Model;

namespace CredProx;

/// <summary>
/// Produces the audit record for every CredProx-processed request
/// (<c>docs/credprox-plan.md</c> §4 "Audit log", §5.2 "Audit"). The core transform
/// provider calls <see cref="Begin"/> before the pipeline runs, so requests rejected at
/// any stage — 401, 403, 400, 502 — are recorded too (least-privilege policy is useless
/// if its denials are invisible; E7 asserts the blocked POST's record). The record is
/// written on response completion: status, latency and bytes are final then, and the
/// completion seam covers both the short-circuit path and the forwarded path.
/// </summary>
/// <remarks>
/// Redaction runs before any sink sees the record. Each sink write is bounded by
/// <see cref="CredProxAuditOptions.SinkTimeout"/> and every failure — exception,
/// cancellation or a sink that ignores the token — is logged value-free and abandoned:
/// audit never fails or delays the caller's request beyond that bound.
/// </remarks>
[Experimental("CREDPROX001")]
public sealed class CredProxAuditRecorder
{
    /// <summary>Event name for a request the forwarder sent upstream.</summary>
    public const string ProxiedEvent = "credprox.proxied_call";

    /// <summary>Event name for a request a CredProx feature short-circuited (§3.4).</summary>
    public const string RejectedEvent = "credprox.rejected_call";

    private readonly IReadOnlyList<IAuditSink> _sinks;
    private readonly CredProxAuditOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly IReadOnlySet<string> _redactHeaders;
    private readonly IReadOnlySet<string> _redactJsonFields;

    internal CredProxAuditRecorder(
        IEnumerable<IAuditSink> sinks,
        CredProxAuditOptions options,
        TimeProvider time,
        ILogger<CredProxAuditRecorder> logger,
        CredProxCoreOptions coreOptions,
        CallerKeyOptions? callerKeyOptions)
    {
        ArgumentNullException.ThrowIfNull(sinks);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(time);
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(coreOptions);

        _sinks = sinks.ToArray();
        _options = options;
        _time = time;
        _logger = logger;

        // The configured caller-key header names are sensitive whatever the configuration
        // says about redaction — the record must never carry a key value (§5.2:367).
        var headers = new HashSet<string>(AuditRedactor.DefaultRedactHeaders, StringComparer.OrdinalIgnoreCase);
        AddIfNotEmpty(headers, coreOptions.InboundKeyHeader);
        AddIfNotEmpty(headers, callerKeyOptions?.HeaderName);
        foreach (var name in options.RedactHeaders)
        {
            AddIfNotEmpty(headers, name);
        }

        _redactHeaders = headers;

        var jsonFields = new HashSet<string>(AuditRedactor.DefaultRedactJsonFields, StringComparer.OrdinalIgnoreCase);
        foreach (var name in options.RedactJsonFields)
        {
            AddIfNotEmpty(jsonFields, name);
        }

        _redactJsonFields = jsonFields;
    }

    /// <summary>
    /// Starts observing one request: stamps the clock, captures the trace id while the
    /// request's <see cref="Activity"/> is current, counts response bytes, and schedules
    /// the record write for response completion. A no-op when auditing is disabled or no
    /// sink is registered.
    /// </summary>
    /// <param name="context">The inbound request, before the pipeline runs.</param>
    internal void Begin(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!_options.Enabled || _sinks.Count == 0)
        {
            return;
        }

        // Begin runs once per request: an already-wrapped body means a second Begin on the
        // same context (e.g. a future feature re-running the transform), which must not
        // double-count bytes or schedule a second record (M7 review note d).
        if (context.Response.Body is CountingResponseBodyStream)
        {
            return;
        }

        var start = _time.GetTimestamp();
        var traceId = Activity.Current?.TraceId.ToString() ?? context.TraceIdentifier;

        var counting = new CountingResponseBodyStream(context.Response.Body);
        context.Response.Body = counting;

        context.Response.OnCompleted(() => WriteAsync(context, counting, start, traceId));
    }

    private async Task WriteAsync(
        HttpContext context,
        CountingResponseBodyStream body,
        long start,
        string traceId)
    {
        try
        {
            var state = context.Features.Get<CredProxRequestState>();
            var identity = context.Features.Get<CallerIdentity>();
            var route = context.Features.Get<IReverseProxyFeature>()?.Route?.Config;

            string? credential = null;
            string? vendor = null;
            if (CredProxMetadata.GetRouteMetadata(context) is { } metadata)
            {
                metadata.TryGetValue(CredProxMetadata.Credential, out credential);
                metadata.TryGetValue(CredProxMetadata.Destination, out vendor);
            }

            var fields = new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["caller"] = identity?.CallerId,
                ["keyId"] = identity?.KeyId,
                ["route"] = route?.RouteId,
                ["vendor"] = state?.Destination?.Name ?? vendor,
                ["method"] = context.Request.Method,
                ["pathTemplate"] = route?.Match?.Path,
                ["status"] = context.Response.StatusCode,
                ["latencyMs"] = _time.GetElapsedTime(start).TotalMilliseconds,
                ["bytes"] = body.BytesWritten,
                ["credential"] = credential,
                ["traceId"] = traceId,
            };

            if (_options.IncludeHeaders.Count > 0)
            {
                fields["headers"] = CaptureHeaders(context);
            }

            var eventName = state?.IsAborted == true ? RejectedEvent : ProxiedEvent;
            AuditRedactor.Redact(fields, _redactHeaders, _redactJsonFields);

            foreach (var sink in _sinks)
            {
                await WriteSafeAsync(sink, eventName, fields).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            // The last net: an audit failure never surfaces to the caller (§5.2).
            _logger.LogWarning(ex, "The CredProx audit record for this request could not be written.");
        }
    }

    private Dictionary<string, object?> CaptureHeaders(HttpContext context)
    {
        var captured = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in _options.IncludeHeaders)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                continue;
            }

            captured[name] = context.Request.Headers.TryGetValue(name, out var value)
                ? value.ToString()
                : null;
        }

        return captured;
    }

    private async Task WriteSafeAsync(
        IAuditSink sink,
        string eventName,
        IReadOnlyDictionary<string, object?> fields)
    {
        var sinkName = sink.GetType().Name;
        try
        {
            using var timeout = new CancellationTokenSource(_options.SinkTimeout);
            var write = sink.WriteAsync(eventName, fields, timeout.Token).AsTask();

            // WhenAny against a timer: a sink that ignores the cancellation token still
            // cannot hold the completed request past the bound.
            var completed = await Task.WhenAny(write, Task.Delay(_options.SinkTimeout)).ConfigureAwait(false);
            if (!ReferenceEquals(completed, write))
            {
                _ = write.ContinueWith(
                    static t => _ = t.Exception,
                    CancellationToken.None,
                    TaskContinuationOptions.OnlyOnFaulted,
                    TaskScheduler.Default);
                _logger.LogWarning(
                    "The audit sink '{Sink}' exceeded its {Timeout} bound and was abandoned.",
                    sinkName,
                    _options.SinkTimeout);
                return;
            }

            await write.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning(
                "The audit sink '{Sink}' timed out after {Timeout}.", sinkName, _options.SinkTimeout);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "The audit sink '{Sink}' failed.", sinkName);
        }
    }

    private static void AddIfNotEmpty(HashSet<string> set, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            set.Add(value);
        }
    }
}
