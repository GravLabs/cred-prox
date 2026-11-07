using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace CredProx;

/// <summary>
/// Vendor error normalisation (M24, plan §8.5): a vendor's 4xx/5xx error body becomes
/// an RFC 7807 <c>application/problem+json</c> document so the caller speaks one error
/// dialect for the whole endpoint — the proxy's own failures already did. The document
/// is lossless: the vendor's payload rides along in the <c>vendor_detail</c> extension
/// member (parsed JSON when it parses, raw text otherwise), next to
/// <c>vendor_content_type</c>, so nothing a caller or a vendor's support desk needs is
/// discarded. Runs at <see cref="Stage.ShapeResponse"/> <b>after</b> the scrubber, so
/// an injected credential a vendor reflects inside its error body is already
/// <c>[redacted]</c> before anything is embedded. On by default
/// (<c>CredProx:Errors:Enabled=false</c> globally, route metadata
/// <c>CredProx.ErrorNormalisation = "off"</c> per route).
/// </summary>
/// <remarks>
/// <para>
/// Deliberate pass-throughs, each byte-identical: non-error statuses, <c>HEAD</c>
/// responses, <c>text/event-stream</c> bodies, non-text or unknown content types, a
/// declared charset outside the losslessly-decodable set (anything but absent,
/// UTF-8 or US-ASCII — decoding those to text would corrupt the embed), undecodable
/// or chained content encodings, and — with a warning — bodies beyond
/// <c>MaxNormalisedBodyBytes</c> (never truncated into the document, never buffered
/// without bound; a compressed body's decompressed form is capped the same way, so a
/// compression bomb cannot bypass the cap). An empty error body is rewritten: the
/// caller still gets the uniform document, without the <c>vendor_detail</c> member.
/// </para>
/// <para>
/// The response's <c>Content-Length</c> is set to the document's exact length; the
/// vendor's content headers describe bytes that no longer exist and are dropped
/// (response-level headers such as <c>Retry-After</c> are untouched). Status is
/// preserved verbatim — normalisation reframes, it never re-decides.
/// </para>
/// </remarks>
[Experimental("CREDPROX001")]
public sealed class ErrorNormalisationFeature : IResponseFeature
{
    /// <summary>The only route-metadata value that opts a route out (§8.5).</summary>
    public const string OptOutValue = "off";

    /// <summary>RFC 7807 <c>type</c> identifying a problem whose origin is the vendor.</summary>
    internal const string VendorErrorType = "urn:credprox:errors:vendor";

    /// <summary>Uniform extension code for every normalised vendor error.</summary>
    internal const string VendorErrorCode = "credprox.vendor_error";

    internal const string VendorTitle = "The upstream vendor returned an error.";

    private static readonly JsonDocumentOptions LooseJson = new()
    {
        AllowTrailingCommas = true,
        CommentHandling = JsonCommentHandling.Skip,
    };

    private readonly CredProxErrorsOptions _options;
    private readonly ILogger<ErrorNormalisationFeature> _logger;

    /// <summary>Creates the feature.</summary>
    /// <param name="options">The errors options (global enable flag and body cap).</param>
    /// <param name="logger">Logs normalisation outcomes (statuses and reasons, never bodies).</param>
    public ErrorNormalisationFeature(CredProxErrorsOptions options, ILogger<ErrorNormalisationFeature> logger)
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

        if (context.Features.Get<CredProxRequestState>() is not { ProxyResponse: { } response })
        {
            return; // not the proxied-response moment (or no upstream response)
        }

        if ((int)response.StatusCode < 400)
        {
            return; // only errors get normalised; successes flow untouched
        }

        if (HttpMethods.IsHead(context.Request.Method))
        {
            return; // a HEAD response must not gain a body
        }

        if (CredProxMetadata.GetRouteMetadata(context) is { } metadata
            && metadata.TryGetValue(CredProxMetadata.ErrorNormalisation, out var optOut)
            && string.Equals(optOut, OptOutValue, StringComparison.OrdinalIgnoreCase))
        {
            return; // the route asked for the vendor's own error shape
        }

        var content = response.Content;
        var contentType = content?.Headers.ContentType;
        if (ResponseBodies.IsEventStream(contentType))
        {
            return; // streaming framing is never buffered wholesale
        }

        var empty = content is null || content.Headers.ContentLength == 0;
        if (!empty && !ResponseBodies.IsTextLike(contentType))
        {
            return; // binary or unknown shape: byte-identical pass-through
        }

        if (!empty && !ResponseBodies.IsCharsetUtf8OrAscii(contentType))
        {
            // The embed decodes to text; a body in any other charset would arrive in
            // vendor_detail corrupted (U+FFFD or NUL-interleaved), and corruption the
            // caller can act on beats corruption the caller trusts. An empty body has
            // nothing to corrupt, so it still takes the uniform document.
            _logger.LogWarning(
                "The upstream error response declared charset '{Charset}', which cannot be "
                + "decoded to text without corruption; the body was forwarded untouched.",
                contentType!.CharSet);
            return;
        }

        Func<Stream, Stream>? decoder = null;
        if (!empty)
        {
            switch (ResponseBodies.ResolveDecoding(content!, out decoder, out var encoding))
            {
                case ResponseBodies.Decoding.Unsupported:
                    _logger.LogWarning(
                        "The upstream error response used content encoding '{Encoding}', which cannot "
                        + "be normalised; the body was forwarded untouched.",
                        encoding);
                    return;
                case ResponseBodies.Decoding.Chained:
                    _logger.LogWarning(
                        "The upstream error response chained content encodings ({Encodings}), which "
                        + "cannot be normalised; the body was forwarded untouched.",
                        encoding);
                    return;
            }
        }

        var vendorText = empty ? null : await ReadCappedAsync(response, content!, decoder, cancellationToken)
            .ConfigureAwait(false);
        if (empty is false && vendorText is null)
        {
            return; // ReadCappedAsync already passed the body through byte-identical
        }

        ReplaceWithErrorDocument(response, vendorText, contentType);
        _logger.LogDebug(
            "The vendor's {Status} error body was normalised to application/problem+json.",
            (int)response.StatusCode);
    }

    /// <summary>
    /// Reads the (decoded) vendor body up to the configured cap. Returns the text, or
    /// <see langword="null"/> when the body exceeded the cap — in that case the response
    /// content has been rebuilt to hand the caller the untouched bytes (buffered prefix
    /// plus the unread remainder, original content headers), never a truncated body.
    /// </summary>
    private async Task<string?> ReadCappedAsync(
        HttpResponseMessage response,
        HttpContent content,
        Func<Stream, Stream>? decoder,
        CancellationToken cancellationToken)
    {
        var cap = _options.MaxNormalisedBodyBytes;
        var declared = content.Headers.ContentLength ?? -1;
        if (declared > cap)
        {
            // Nothing read yet: the untouched content object simply stays in place.
            LogTooLarge();
            return null;
        }

        var original = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);

        using var rawPrefix = new MemoryStream();
        var chunk = new byte[8192];
        long total = 0;
        int read;
        while ((read = await original.ReadAsync(chunk, cancellationToken).ConfigureAwait(false)) > 0)
        {
            rawPrefix.Write(chunk, 0, read);
            total += read;
            if (total > cap)
            {
                return PassthroughFrom(response, content, original, rawPrefix);
            }
        }

        if (decoder is null)
        {
            return Encoding.UTF8.GetString(rawPrefix.ToArray());
        }

        // Cap the DECOMPRESSED form the same way: an 8 KiB gzip bomb must not decode
        // into a document (or memory) the cap was supposed to prevent. The decoder
        // reads only from the fully buffered rawPrefix (rewound to its start — the
        // write loop left the position at the end), so on overflow the prefix plus the
        // (possibly already drained) underlying stream still replay the vendor's exact
        // compressed bytes.
        rawPrefix.Position = 0;
        using var decodedStream = decoder(rawPrefix);
        using var decodedPrefix = new MemoryStream();
        while ((read = await decodedStream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false)) > 0)
        {
            decodedPrefix.Write(chunk, 0, read);
            if (decodedPrefix.Length > cap)
            {
                return PassthroughFrom(response, content, original, rawPrefix);
            }
        }

        return Encoding.UTF8.GetString(decodedPrefix.ToArray());
    }

    private string? PassthroughFrom(
        HttpResponseMessage response,
        HttpContent content,
        Stream original,
        MemoryStream rawPrefix)
    {
        LogTooLarge();
        var passthrough = new StreamContent(new PrefixThenRestStream(rawPrefix.ToArray(), original));
        foreach (var (name, values) in content.Headers)
        {
            passthrough.Headers.TryAddWithoutValidation(name, values);
        }

        response.Content = passthrough;
        return null;
    }

    private void LogTooLarge() => _logger.LogWarning(
        "A vendor error body exceeded the {Cap}-byte normalisation limit; the caller "
        + "received the vendor's own body untouched. Raise CredProx:Errors:MaxNormalisedBodyBytes to normalise larger bodies.",
        _options.MaxNormalisedBodyBytes);

    private static void ReplaceWithErrorDocument(
        HttpResponseMessage response,
        string? vendorText,
        MediaTypeHeaderValue? vendorContentType)
    {
        var extensions = new Dictionary<string, object?> { ["code"] = VendorErrorCode };
        if (vendorText is { Length: > 0 })
        {
            if (vendorContentType is not null)
            {
                extensions["vendor_content_type"] = vendorContentType.ToString();
            }

            extensions["vendor_detail"] = (object?)TryParseJson(vendorText) ?? vendorText;
        }

        var document = CredProxProblemResponses.CreateProblemBytes(
            VendorErrorType, (int)response.StatusCode, VendorTitle, extensions);

        var replacement = new ByteArrayContent(document);
        replacement.Headers.ContentType = new MediaTypeHeaderValue("application/problem+json") { CharSet = "utf-8" };
        response.Content = replacement;
    }

    /// <summary>
    /// Embeds the vendor payload as structured JSON when it is JSON — lenient parsing,
    /// and any failure degrades to the raw text member (never an error, never a
    /// mangled lie). Only obvious JSON documents are attempted; text and HTML stay text.
    /// </summary>
    private static JsonElement? TryParseJson(string text)
    {
        var trimmed = text.AsSpan().TrimStart();
        if (trimmed.IsEmpty || (trimmed[0] != '{' && trimmed[0] != '['))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(text, LooseJson);
            return document.RootElement.Clone();
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
