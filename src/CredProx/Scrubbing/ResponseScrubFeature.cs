using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace CredProx;

/// <summary>
/// The built-in response secret scrubber: when the upstream reflects
/// a credential the pipeline injected — error pages echoing the request, echo endpoints
/// — the caller must not see it. Runs at <see cref="Stage.ShapeResponse"/>; on by
/// default, opted out with <c>CredProx:Scrubbing:Enabled=false</c>. The scan engages
/// only when the request actually injected a value and the response is text-like, so
/// every other response passes through byte-identical.
/// </summary>
/// <remarks>
/// <para>
/// Headers: response headers and content headers are scrubbed for secret occurrences
/// (an echoed <c>Authorization</c>, a <c>Set-Cookie</c> carry). Body: text-like content
/// types stream through <see cref="ScrubbingStream"/>; gzip (and its <c>x-gzip</c> alias), deflate and br bodies of
/// eligible types are transparently decoded, scrubbed and forwarded decompressed
/// (<c>Content-Encoding</c> dropped) — a secret must not hide behind the encoding
/// header. An encoding this build cannot decode — <c>zstd</c> among them, .NET ships
/// no streaming decompressor for it — is logged once and forwarded untouched:
/// refusing exotic responses would break working traffic for a documented residue.
/// <c>CredProx:Scrubbing:FailClosed=true</c> inverts that stance for every class the
/// scrubber cannot inspect (non-text or missing media type, unknown or chained
/// encoding, a declared charset the byte matcher cannot read, error responses included): the
/// response is refused with a <c>credprox.response_uninspectable</c> problem
/// response — a refused 2xx/3xx answers <c>502</c>, a vendor 4xx/5xx keeps its
/// status, and a response with no body (empty, <c>HEAD</c>, a bodiless redirect) is
/// never refused. A refusal logs one warning that says the body was refused, naming
/// the class and the route; the once-per-route pass-through warnings stay exactly on
/// the paths that forward. The option requires <c>Enabled</c>; the combination with
/// scrubbing switched off is rejected at startup.
/// For JSON bodies the matcher also reads through <c>\uXXXX</c> escapes (four hex
/// digits, either case), replacing the original escaped bytes, so a vendor's JSON
/// encoder cannot echo a credential past the scrubber; a JSON-escaped echo inside a
/// <c>text/event-stream</c> payload is the event framing's documented residue.
/// </para>
/// <para>
/// Scrubbing can change the body length, so a scrubbed response's <c>Content-Length</c>
/// is dropped (the caller sees chunked framing). The matcher works on raw bytes — in a
/// readable ASCII-compatible charset a plain ASCII echo is caught, but non-ASCII
/// characters re-encoded in that charset, or any echo in a charset the matcher cannot
/// read, are a documented residue that carries the value through; with
/// <c>FailClosed</c> on, a response that <i>declares</i> a charset the matcher cannot
/// read is refused rather than forwarded. <c>text/event-stream</c> bodies scrub per event: events flow as they
/// complete, keeping streaming latency, and a secret split across an event boundary is
/// the framing's own documented residue. Values are never logged — the logs say that
/// scrubbing happened, never what it removed.
/// </para>
/// </remarks>
[Experimental("CREDPROX001")]
public sealed class ResponseScrubFeature : IResponseFeature
{
    private readonly CredProxScrubbingOptions _options;
    private readonly ILogger<ResponseScrubFeature> _logger;

    // M45 security finding F-3: the classes of response the scrubber declines to open
    // are now operator-visible, once per route and shape — routes come from
    // configuration, so the key space is the operator's, not the vendor's.
    private readonly ConcurrentDictionary<(string Route, string Shape), byte> _uninspectedWarned = new();

    /// <summary>Creates the feature.</summary>
    /// <param name="options">The scrubbing options (global enable flag).</param>
    /// <param name="logger">Logs scrub events (names outcomes, never values).</param>
    public ResponseScrubFeature(CredProxScrubbingOptions options, ILogger<ResponseScrubFeature> logger)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public Stage Stage => Stage.ShapeResponse;

    /// <inheritdoc />
    public async ValueTask ApplyAsync(HttpContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!_options.Enabled)
        {
            return;
        }

        if (context.Features.Get<CredProxRequestState>() is not ({ ProxyResponse: { } response } state))
        {
            return; // not the proxied-response moment (or no upstream response)
        }

        if (context.Features.Get<CredProxInjectedSecrets>() is not { HasAny: true } secrets)
        {
            return; // nothing was injected on this request — nothing to scrub
        }

        if (ScrubHeaders(response.Headers, secrets.Values)
            || (response.Content is not null && ScrubHeaders(response.Content.Headers, secrets.Values)))
        {
            _logger.LogWarning(
                "The upstream response carried the request's injected credential in a response header; "
                + "the caller received a scrubbed copy.");
        }

        if (response.Content is { } content)
        {
            await ScrubBodyAsync(context, state, response, content, secrets.Values, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private async Task ScrubBodyAsync(
        HttpContext context,
        CredProxRequestState state,
        HttpResponseMessage response,
        HttpContent content,
        IReadOnlyList<string> secrets,
        CancellationToken cancellationToken)
    {
        if (!ResponseBodies.IsTextLike(content.Headers.ContentType))
        {
            // M45 security finding F-3: byte-identical pass-through is still the
            // answer, but the operator hears about the class of response that can
            // carry an echo unopened. M47 F-3 (Low-3): with fail-closed on the
            // decision comes FIRST — a withheld body logs as refused, never as
            // forwarded; the pass-through warning stays exactly where the body
            // really is forwarded (off mode, or a response with no body).
            if (_options.FailClosed && !await IsBodylessAsync(context, response, cancellationToken)
                    .ConfigureAwait(false))
            {
                LogRefused(state, content.Headers.ContentType is null ? "no media type" : "non-text media type");
                RefuseUninspected(context, response, content.Headers.ContentType is null
                    ? "no-media-type"
                    : "non-text-media-type");
                return;
            }

            if (content.Headers.ContentType is null)
            {
                WarnUninspected(state, "no media type",
                    "An upstream response carried no media type; its body cannot be inspected for "
                    + "echoed credentials and was forwarded untouched.");
            }
            else
            {
                WarnUninspected(state, "non-text media type",
                    $"An upstream response used media type '{content.Headers.ContentType}'; its body cannot "
                    + "be inspected for echoed credentials and was forwarded untouched.");
            }

            return; // binary or unknown shape: byte-identical pass-through
        }

        if (content.Headers.ContentLength == 0)
        {
            return; // an empty body holds nothing to scrub
        }

        // The scrubber asks its own charset question, deliberately different from M24's
        // ResponseBodies.IsCharsetUtf8OrAscii: that predicate gates ERROR NORMALISATION,
        // where only utf-8/ascii round-trip as text, while this one asks whether the
        // raw-byte matcher can see an ASCII echo — every single-byte ASCII-compatible
        // charset answers yes. Two features now disagree on the same header by design;
        // do not merge the predicates.
        if (!IsCharsetReadable(content.Headers.ContentType))
        {
            // M47 F-3 (Low-4): a body in a charset the byte matcher genuinely cannot read
            // (utf-16/32 family, stateful names, unknown names) keeps an echoed credential
            // intact, so with the option on it is refused. Readable ASCII-compatible
            // charsets — the exact published names on IsCharsetReadable — are
            // scrubbed and never refused. The class is operator-visible in both modes:
            // forward with the pass-through warning when the option is off, refusal line
            // when it is on. A bodyless response is never refused whatever its charset,
            // and its warning must not claim a search of a body that is not there
            // (log accuracy, same class as the searched-as-is wording). The bodiless
            // message carries its OWN dedupe shape so it cannot swallow the has-body
            // warning on the same route, and the branch then returns: response headers
            // were already scrubbed at the top of ApplyAsync, there is no body to carry
            // to the matcher, and skipping the matcher also skips its framing rewrite
            // (declared Content-Length survives). HEAD is bodiless by this predicate's
            // own rule — free, no probe — so the off mode states the absence too without
            // starting to read bytes (M47 round 3, lead 07:25Z instruction).
            // The HEAD arm rests on the rule that a HEAD response carries no body: the
            // HTTP stack hands back zero bytes for it, so the matcher has nothing to
            // read and is skipped here by design, not by omission.
            var bodiless = HttpMethods.IsHead(context.Request.Method)
                || (_options.FailClosed
                    && await IsBodylessAsync(context, response, cancellationToken).ConfigureAwait(false));
            if (_options.FailClosed && !bodiless)
            {
                LogRefused(state, "non-UTF-8 charset");
                RefuseUninspected(context, response, "non-utf8-charset");
                return;
            }

            if (bodiless)
            {
                WarnUninspected(state, "non-UTF-8 charset, no body",
                    $"An upstream response declared charset '{content.Headers.ContentType?.CharSet}', which the "
                    + "scrubber cannot read; no response body was present to search for echoed credentials, so "
                    + "the response was forwarded untouched.");
                return;
            }

            // The has-body branch falls through and still searches the raw bytes, so its
            // message must not claim the outcome of a pass-through: media-type and
            // encoding warnings above really return before the scrub and keep their
            // wording.
            WarnUninspected(state, "non-UTF-8 charset",
                $"An upstream response declared charset '{content.Headers.ContentType?.CharSet}', which the "
                + "scrubber cannot read; its body was searched as-is for echoed credentials, so an echo "
                + "encoded in that charset would not be found.");
        }

        switch (ResponseBodies.ResolveDecoding(content, out var decoder, out var encoding))
        {
            case ResponseBodies.Decoding.Unsupported:
                if (_options.FailClosed && !await IsBodylessAsync(context, response, cancellationToken)
                        .ConfigureAwait(false))
                {
                    // M47 F-3 (Low-3): decide before logging — see the media-type branch.
                    LogRefused(state, "unknown content encoding");
                    RefuseUninspected(context, response, "unknown-content-encoding");
                    return;
                }

                _logger.LogWarning(
                    "The upstream response used content encoding '{Encoding}', which cannot be "
                    + "scrubbed; the body was forwarded untouched.",
                    encoding);
                return;
            case ResponseBodies.Decoding.Chained:
                if (_options.FailClosed && !await IsBodylessAsync(context, response, cancellationToken)
                        .ConfigureAwait(false))
                {
                    LogRefused(state, "chained content encodings");
                    RefuseUninspected(context, response, "chained-content-encoding");
                    return;
                }

                _logger.LogWarning(
                    "The upstream response chained content encodings ({Encodings}), which cannot be "
                    + "scrubbed; the body was forwarded untouched.",
                    encoding);
                return;
        }

        var original = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        var decoded = decoder is null ? original : decoder(original);

        // Event-streams scrub per event so streaming latency survives (M22): the
        // byte-stream hold-back would otherwise delay every event by the longest
        // secret's look-ahead.
        Stream scrubbed = ResponseBodies.IsEventStream(content.Headers.ContentType)
            ? new EventScrubbingStream(decoded, secrets)
            : new ScrubbingStream(decoded, secrets, ResponseBodies.IsJsonLike(content.Headers.ContentType));
        var replacement = new StreamContent(scrubbed);

        // Carry the content headers over — the old framing described bytes that no
        // longer exist on the wire, so drop it (unknown length → chunked).
        foreach (var (name, values) in content.Headers)
        {
            replacement.Headers.TryAddWithoutValidation(name, values);
        }

        replacement.Headers.ContentEncoding.Clear();
        replacement.Headers.ContentLength = null;

        response.Content = replacement;
        _logger.LogDebug("The proxied response body passed the credential scrubber.");
    }

    /// <summary>
    /// M47 finding F-3: fail-closed mode (<c>CredProx:Scrubbing:FailClosed</c>). Replaces
    /// the uninspectable body with the refusal document. Honest status: a refused 2xx/3xx
    /// is answered 502 — CredProx never reports success for bytes it withheld — and a
    /// vendor 4xx/5xx keeps its status, the vendor's own error class staying visible.
    /// The document names the response class, never a value.
    /// </summary>
    private static void RefuseUninspected(HttpContext context, HttpResponseMessage response, string responseClass)
    {
        context.Features.Set(ScrubRefusalMarker.Shared);
        var vendorStatus = (int)response.StatusCode;
        var refusalStatus = vendorStatus < 400 ? HttpStatusCode.BadGateway : (HttpStatusCode)vendorStatus;
        response.StatusCode = refusalStatus;
        var document = CredProxProblemResponses.CreateProblemBytes(
            CredProxProblemResponses.ProxyErrorType,
            (int)refusalStatus,
            "The upstream response was withheld",
            new Dictionary<string, object?>
            {
                ["code"] = "credprox.response_uninspectable",
                ["response_class"] = responseClass,
            });
        var replacement = new ByteArrayContent(document);
        replacement.Headers.ContentType = new MediaTypeHeaderValue("application/problem+json") { CharSet = "utf-8" };
        response.Content = replacement;
    }

    /// <summary>
    /// M47 F-3 (Low-3): the refusal's only log line. The pass-through warning it
    /// replaces claimed the body "was forwarded untouched" — the opposite of what
    /// happened to a refused response. One warning per refusal (the once-per-route
    /// shape census is about forwards; a refusal is an event), naming the response
    /// class and the route, never a value.
    /// </summary>
    private void LogRefused(CredProxRequestState state, string shape)
    {
        var route = state.Destination?.Name ?? "(unbound)";
        _logger.LogWarning(
            "An upstream response was refused without inspection (class '{Shape}', route '{Route}'); "
            + "the caller received a credprox.response_uninspectable problem response instead of the body.",
            shape,
            route);
    }

    /// <summary>
    /// M47 F-3: a response with no body is never refused — there is nothing to inspect.
    /// An empty <c>Content-Length</c> and a <c>HEAD</c> response are bodyless by
    /// definition; a bodiless redirect (and every other empty response) rides the same
    /// rule, which is what keeps redirects working with the option on. A chunked or
    /// unknown-length body is decided by whether any body byte arrives: one byte is read
    /// as the witness — zero bytes means bodyless, any byte means a body that could
    /// carry an echo. The probe byte is dropped, not replayed: it is read only on paths
    /// the refusal replaces outright or the forward leaves empty.
    /// </summary>
    private static async ValueTask<bool> IsBodylessAsync(
        HttpContext context,
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        if (HttpMethods.IsHead(context.Request.Method))
        {
            return true; // a HEAD response carries no body whatever its headers claim
        }

        var content = response.Content;
        if (content is null)
        {
            return true;
        }

        var length = content.Headers.ContentLength;
        if (length == 0)
        {
            return true;
        }

        if (length is not null)
        {
            return false; // the vendor claims bytes: there is something to inspect
        }

        try
        {
            var stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            return await stream.ReadAsync(new byte[1], 0, 1, cancellationToken).ConfigureAwait(false) == 0;
        }
        catch (IOException)
        {
            return false; // a stream that cannot answer the probe is not "no body"
        }
    }

    /// <summary>
    /// The readable charsets: the EXACT published single-byte, ASCII-compatible
    /// names whose bodies the byte matcher can read.
    /// </summary>
    private static readonly string[] ReadableCharsets =
    [
        "utf-8", "utf8", "us-ascii", "ascii",
        "iso-8859-1", "iso-8859-2", "iso-8859-3", "iso-8859-4", "iso-8859-5",
        "iso-8859-6", "iso-8859-7", "iso-8859-8", "iso-8859-9", "iso-8859-10",
        "iso-8859-11", "iso-8859-13", "iso-8859-14", "iso-8859-15", "iso-8859-16",
        "windows-1250", "windows-1251", "windows-1252", "windows-1253",
        "windows-1254", "windows-1255", "windows-1256", "windows-1257",
        "windows-1258",
    ];

    /// <summary>
    /// Whether the scrubber's byte matcher can find an ASCII credential echo in a body
    /// declaring this charset: only the exact names in <see cref="ReadableCharsets"/>
    /// — <c>utf-8</c>/<c>utf8</c>, <c>us-ascii</c>/<c>ascii</c>, <c>iso-8859-1</c>
    /// through <c>iso-8859-11</c> and <c>iso-8859-13</c> through <c>iso-8859-16</c>
    /// (there is no iso-8859-12: reserved and withdrawn, so its refusal is the
    /// permanent record), and <c>windows-1250</c> through <c>windows-1258</c>, the
    /// complete published set. Nothing else is readable: not prefix extensions of a
    /// family (<c>iso-8859-99</c>) and not alias spellings (<c>latin1</c>, <c>l1</c>,
    /// <c>iso8859-1</c>, <c>cp1252</c>) — declare the canonical name. Deliberately not
    /// the error-normalisation predicate in ResponseBodies — that admits only utf-8 and
    /// ascii because it embeds the payload as text; this one asks a byte-matching
    /// question and stays wider while still refusing the utf-16/32 family, stateful
    /// names (iso-2022-*) and unknown names. Matching is by name: trimmed, with ONE
    /// pair of surrounding double quotes stripped (the RFC 9110 quoted form keeps its
    /// quotes through MediaTypeHeaderValue), case-insensitive. The gate reads the
    /// DECLARED charset, never the bytes: a response that misreports its charset is
    /// not detected. No name ever resolves a .NET Encoding, so a bogus name answers
    /// unreadable instead of throwing.
    /// </summary>
    private static bool IsCharsetReadable(MediaTypeHeaderValue? contentType)
    {
        var charset = contentType?.CharSet;
        if (string.IsNullOrWhiteSpace(charset))
        {
            return true; // no declared charset: the media-type default is readable text
        }

        var name = charset.Trim();
        if (name.Length >= 2 && name[0] == '"' && name[^1] == '"')
        {
            name = name[1..^1].Trim();
        }

        foreach (var readable in ReadableCharsets)
        {
            if (name.Equals(readable, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false; // unknown, stateful, alias, or prefixed-extension names are unreadable
    }

    private void WarnUninspected(CredProxRequestState state, string shape, string message)
    {
        var route = state.Destination?.Name ?? "(unbound)";
        if (_uninspectedWarned.TryAdd((route, shape), 0))
        {
            // Names the class of response, never the body and never a URL.
            _logger.LogWarning(
                "{Message} This warning is logged once per route and shape; the class list "
                + "is in the README's Security section.",
                message);
        }
    }

    /// <summary>
    /// Replaces every occurrence of every registered value in each header value with
    /// the redaction marker, rebuilding the header in place. Returns whether anything
    /// changed. Values are matched case-sensitively (credentials are case-sensitive).
    /// </summary>
    internal static bool ScrubHeaders(HttpHeaders headers, IReadOnlyList<string> secrets)
    {
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentNullException.ThrowIfNull(secrets);

        List<KeyValuePair<string, List<string>>>? changed = null;
        foreach (var (name, values) in headers)
        {
            var valueList = values as IList<string> ?? values.ToList();
            List<string>? replacements = null;
            for (var i = 0; i < valueList.Count; i++)
            {
                var value = valueList[i];
                if (value is not { Length: > 0 })
                {
                    continue;
                }

                var updated = ScrubValue(value, secrets);
                if (ReferenceEquals(updated, value))
                {
                    continue;
                }

                if (replacements is null)
                {
                    replacements = new List<string>(valueList.Count);
                    foreach (var original in valueList)
                    {
                        replacements.Add(original);
                    }
                }

                replacements[i] = updated;
            }

            if (replacements is not null)
            {
                (changed ??= []).Add(new KeyValuePair<string, List<string>>(name, replacements));
            }
        }

        if (changed is null)
        {
            return false;
        }

        foreach (var (name, replacements) in changed)
        {
            headers.Remove(name);
            foreach (var value in replacements)
            {
                headers.TryAddWithoutValidation(name, value);
            }
        }


        return true;
    }

    private static string ScrubValue(string value, IReadOnlyList<string> secrets)
    {
        foreach (var secret in secrets)
        {
            if (value.Contains(secret, StringComparison.Ordinal))
            {
                value = value.Replace(secret, AuditRedactor.Masked, StringComparison.Ordinal);
            }
        }

        return value;
    }

}
