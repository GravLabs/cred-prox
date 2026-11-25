using System.Collections.Concurrent;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Yarp.ReverseProxy.Model;

namespace CredProx;

/// <summary>
/// The metering response-side leg (M50, ADR-0008): at <see cref="Stage.ShapeResponse"/>
/// — before a single response byte reaches the caller — it optionally wraps the upstream
/// content with a byte-preserving usage peek (per-route opt-in by usage format,
/// <see cref="CredProxMetering.UsageRouteMetadata"/>), installs the counting body as
/// <c>context.Response.Body</c>, and schedules the record for response completion
/// (<c>Response.OnCompleted</c>), which covers short-circuit and forwarded paths alike.
/// The scrubber is pinned ahead of it in the stage, so the peek only ever sees
/// already-scrubbed bytes.
/// </summary>
/// <remarks>
/// Tags resolve from public lookups only — the caller-identity feature, route metadata,
/// the YARP route id, and the final status class (§5.2 attribution integrity, cardinality).
/// Recording failure logs and changes nothing on the wire: the response completed before
/// it ran. A metering or reader fault before dispatch degrades to unmetered, never to a
/// refusal of the caller's response.
/// </remarks>
internal sealed class CredProxMeteringResponseFeature(
    IServiceProvider services,
    CredProxMeteringOptions options,
    ILogger<CredProxMeteringResponseFeature> logger) : IResponseFeature
{
    /// <summary>
    /// The metering reload walk (M50 fold LOW-4): resolved here so arming the guard rides
    /// this singleton's construction — the startup validator enumerates response features
    /// at host start, and that is what puts the walk live before the app serves.
    /// </summary>
    internal CredProxMeteringReloadGuard ReloadGuard { get; } =
        services.GetRequiredService<CredProxMeteringReloadGuard>();

    /// <summary>
    /// Ceiling for <see cref="unmatchedFormats"/>: once this many distinct
    /// (route, format, media type) tuples have logged, no further line is emitted. The
    /// guard bounds the set against a hostile stream of distinct media types; a race at
    /// the boundary may let a few extra tuples in, which is still bounded.
    /// </summary>
    private const int UnmatchedFormatCap = 64;

    /// <summary>
    /// Tuples already reported by <see cref="LogUnmatchedFormat"/>. This feature is a
    /// per-host singleton (see <see cref="ReloadGuard"/>), so the dictionary is the right
    /// lifetime for "once per process": the no-reader diagnostic is a configuration
    /// property, not a per-response event.
    /// </summary>
    private readonly ConcurrentDictionary<string, byte> unmatchedFormats = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public async ValueTask ApplyAsync(HttpContext context, CancellationToken cancellationToken)
    {
        var state = context.Features.Get<CredProxRequestState>();
        var response = state?.ProxyResponse;
        var metering = context.Features.Get<MeteringRequestState>();
        if (response is null || metering is null || metering.ResponseBytes is not null)
        {
            return; // no settled upstream response (short circuit) or a re-run of this feature
        }

        if (UsageFormat(context) is { } format && response.Content is { } content)
        {
            var mediaType = content.Headers.ContentType?.MediaType;
            var reader = SelectReader(format, mediaType, out var selectionThrew);
            if (reader is null)
            {
                // A selection that threw has already logged its own Warning naming the
                // failure — nobody was actually asked there, so the no-reader line about
                // the declined tuple would be noise. Only a declined selection logs it.
                if (!selectionThrew)
                {
                    LogUnmatchedFormat(context, format, mediaType);
                }
            }
            else
            {
                try
                {
                    var original = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
                    var peeked = new UsagePeekStream(original, reader, options.MaxUsageParseBytes);
                    var replacement = new StreamContent(peeked);
                    foreach (var (name, values) in content.Headers)
                    {
                        replacement.Headers.TryAddWithoutValidation(name, values);
                    }

                    // The peek forwards every byte, so unlike the scrubber's replacement the
                    // framing stays true: Content-Length (when the vendor sent one) describes
                    // exactly the bytes that will flow.
                    response.Content = replacement;
                    metering.Usage = reader;
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    // M50 fold INFO-1: the fail-closed promise in full — a metering failure
                    // can only lose token counts, never change the response. Same degrade
                    // shape as SelectReader above; the response content was not yet replaced,
                    // so the caller keeps the upstream's bytes untouched (the forwarder still
                    // owns them). A cancellation is the caller's own abort, not a metering
                    // failure: it propagates.
                    logger.LogWarning(ex, "CredProx usage peek could not be installed; the response is metered without token usage.");
                }
            }
        }

        var counting = new CountingWriteStream(context.Response.Body);
        context.Response.Body = counting;
        metering.ResponseBytes = counting;
        context.Response.OnCompleted(() =>
        {
            try
            {
                Record(context, metering);
            }
            catch (Exception ex)
            {
                // The response is already complete; a metering failure reaches the log,
                // never the caller's bytes.
                logger.LogWarning(ex, "CredProx metering could not record this request.");
            }

            return Task.CompletedTask;
        });
    }

    private static void Record(HttpContext context, MeteringRequestState metering)
    {
        var caller = context.Features.Get<CallerIdentity>()?.CallerId ?? MeteringDiagnostics.AnonymousCaller;
        string? credential = null;
        string? destination = null;
        if (CredProxMetadata.GetRouteMetadata(context) is { } metadata)
        {
            metadata.TryGetValue(CredProxMetadata.Credential, out credential);
            metadata.TryGetValue(CredProxMetadata.Destination, out destination);
        }

        credential ??= MeteringDiagnostics.Unknown;
        destination ??= MeteringDiagnostics.Unknown;
        var route = context.Features.Get<IReverseProxyFeature>()?.Route?.Config?.RouteId
            ?? MeteringDiagnostics.Unknown;
        var statusClass = MeteringDiagnostics.StatusClass(context.Response.StatusCode);

        KeyValuePair<string, object?>[] tags =
        [
            new(MeteringDiagnostics.CallerTag, caller),
            new(MeteringDiagnostics.CredentialTag, credential),
            new(MeteringDiagnostics.DestinationTag, destination),
            new(MeteringDiagnostics.RouteTag, route),
            new(MeteringDiagnostics.StatusClassTag, statusClass),
        ];

        MeteringDiagnostics.Requests.Add(1, tags);
        if (metering.RequestBytes is { } requestBytes)
        {
            MeteringDiagnostics.RequestBytes.Record(requestBytes.BytesRead, tags);
        }

        if (metering.ResponseBytes is { } responseBytes)
        {
            MeteringDiagnostics.ResponseBytes.Record(responseBytes.BytesWritten, tags);
        }

        if (metering.Usage is { } usage && (usage.InputTokens.HasValue || usage.OutputTokens.HasValue))
        {
            KeyValuePair<string, object?>[] usageTags =
            [
                new(MeteringDiagnostics.CallerTag, caller),
                new(MeteringDiagnostics.CredentialTag, credential),
                new(MeteringDiagnostics.DestinationTag, destination),
                new(MeteringDiagnostics.RouteTag, route),
            ];

            if (usage.InputTokens is { } input)
            {
                MeteringDiagnostics.InputTokens.Add(input, usageTags);
            }

            if (usage.OutputTokens is { } output)
            {
                MeteringDiagnostics.OutputTokens.Add(output, usageTags);
            }
        }
    }

    // The route's usage format name (M54, ADR-0009): presence of a value opts the route
    // in; the value names the reader family. A value that names no registered format is
    // refused at config load by CredProxUsageFormatConfigValidator — here, the per-request
    // path, an unservable value simply selects no reader and the response stays metered
    // without token usage, never refused.
    private static string? UsageFormat(HttpContext context) =>
        CredProxMetadata.GetRouteMetadata(context) is { } metadata
        && metadata.TryGetValue(CredProxMetering.UsageRouteMetadata, out var value)
        && !string.IsNullOrEmpty(value) ? value : null;

    private IUsageReader? SelectReader(string format, string? mediaType, out bool threw)
    {
        threw = false;
        try
        {
            // Transient registrations: each resolve is a fresh reader for this response.
            // Format first (ordinal, case-insensitive), then media type — a reader for a
            // different vendor's body shape is never considered, whatever media type the
            // response carries.
            foreach (var reader in services.GetServices<IUsageReader>())
            {
                if (string.Equals(reader.Format, format, StringComparison.OrdinalIgnoreCase)
                    && reader.CanRead(mediaType))
                {
                    return reader;
                }
            }
        }
        catch (Exception ex)
        {
            // A host reader that cannot be constructed or cannot answer selection never
            // holds the response hostage: the response is metered without token usage.
            threw = true;
            logger.LogWarning(ex, "CredProx usage-reader selection failed; the response is metered without token usage.");
        }

        return null;
    }

    /// <summary>
    /// The no-reader diagnostic (M54, ADR-0009): the per-request degrade to "metered without token usage"
    /// is silent by design, but a route that can never find a reader (the format names a
    /// family whose readers all decline this media type) is a configuration fact an
    /// operator should be able to see. At most ONE Debug line per (route, format, media
    /// type) tuple per process — the bound is on LINES, not on per-response work: the
    /// early return keeps the matched path allocation-free, an unmatched response with
    /// Debug on pays a key build and a set lookup even after its tuple logged, and past
    /// <see cref="UnmatchedFormatCap"/> distinct tuples only that lookup remains. The
    /// response itself is untouched either way.
    /// </summary>
    private void LogUnmatchedFormat(HttpContext context, string format, string? mediaType)
    {
        if (!logger.IsEnabled(LogLevel.Debug))
        {
            return;
        }

        if (unmatchedFormats.Count >= UnmatchedFormatCap)
        {
            return;
        }

        var route = context.Features.Get<IReverseProxyFeature>()?.Route?.Config?.RouteId
            ?? MeteringDiagnostics.Unknown;
        if (unmatchedFormats.TryAdd(route + "\n" + format + "\n" + (mediaType ?? string.Empty), 0))
        {
            logger.LogDebug(
                "CredProx route {Route} names usage format {Format} but no registered reader accepts the response media type {MediaType}; the response stays metered without token usage.",
                route, format, mediaType ?? "(none)");
        }
    }
}
