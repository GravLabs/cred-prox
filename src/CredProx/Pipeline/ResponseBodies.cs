using System.IO.Compression;
using System.Net.Http.Headers;

namespace CredProx;

/// <summary>
/// The shared response-body eligibility rules of the outbound pipeline: which media
/// types a body rewriter may touch without mangling it, and how the content encoding
/// gates the rewrite. Extracted from the scrubber (M20/M22) so the scrubber and the
/// error normaliser (M24) run one audited classifier, not two that can drift.
/// </summary>
internal static class ResponseBodies
{
    /// <summary>How the response's <c>Content-Encoding</c> gates a body rewrite.</summary>
    internal enum Decoding
    {
        /// <summary>No decoding needed (absent or <c>identity</c>) — the body can be read as-is.</summary>
        UsableIdentity,

        /// <summary>A single supported encoding — read through the decoder, forward decompressed.</summary>
        UsableDecoded,

        /// <summary>One encoding this build cannot decode — forward the body untouched.</summary>
        Unsupported,

        /// <summary>Chained encodings — decoding order cannot be assumed; forward untouched.</summary>
        Chained,
    }

    /// <summary>
    /// Whether the media type is <c>text/event-stream</c>, which takes the event
    /// framing (<see cref="EventScrubbingStream"/>) instead of the byte-stream one, and
    /// is never buffered wholesale.
    /// </summary>
    internal static bool IsEventStream(MediaTypeHeaderValue? contentType) =>
        string.Equals(contentType?.MediaType, "text/event-stream", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Whether the media type is text-like enough that byte-level rewriting cannot
    /// mangle it: <c>text/*</c>, the structured text types, and the <c>+json</c> /
    /// <c>+xml</c> / <c>+javascript</c> suffixed forms. Everything else — including a
    /// missing content type — is left byte-identical.
    /// </summary>
    internal static bool IsTextLike(MediaTypeHeaderValue? contentType)
    {
        if (contentType?.MediaType is not { Length: > 0 } mediaType)
        {
            return false;
        }

        if (mediaType.StartsWith("text/", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var separator = mediaType.IndexOf('/');
        if (separator < 0)
        {
            return false;
        }

        var subtype = mediaType[(separator + 1)..];
        if (subtype.EndsWith("+json", StringComparison.OrdinalIgnoreCase)
            || subtype.EndsWith("+xml", StringComparison.OrdinalIgnoreCase)
            || subtype.EndsWith("+javascript", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return subtype.Equals("json", StringComparison.OrdinalIgnoreCase)
            || subtype.Equals("xml", StringComparison.OrdinalIgnoreCase)
            || subtype.Equals("xhtml+xml", StringComparison.OrdinalIgnoreCase)
            || subtype.Equals("javascript", StringComparison.OrdinalIgnoreCase)
            || subtype.Equals("x-javascript", StringComparison.OrdinalIgnoreCase)
            || subtype.Equals("ecmascript", StringComparison.OrdinalIgnoreCase)
            || subtype.Equals("x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)
            || subtype.Equals("yaml", StringComparison.OrdinalIgnoreCase)
            || subtype.Equals("x-yaml", StringComparison.OrdinalIgnoreCase)
            || subtype.Equals("ndjson", StringComparison.OrdinalIgnoreCase)
            || subtype.Equals("x-ndjson", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Whether a declared charset is one a UTF-8 reader decodes without loss: absent
    /// (the media-type default), or <c>utf-8</c> / <c>utf8</c> / <c>us-ascii</c> /
    /// <c>ascii</c> by name. Any other declared charset (<c>iso-8859-*</c>,
    /// <c>windows-*</c>, <c>utf-16</c>, …) is refused for callers that decode the body
    /// to text — reading those bytes as UTF-8 would replace them with U+FFFD or
    /// interleave NULs and destroy them. Byte-level rewriters do not need this gate:
    /// their matcher is charset-indifferent. (F1, M24 review: the normaliser embeds the
    /// vendor's payload as text, so the "lossless" claim only holds within this set.)
    /// </summary>
    internal static bool IsCharsetUtf8OrAscii(MediaTypeHeaderValue? contentType)
    {
        var charset = contentType?.CharSet;
        if (string.IsNullOrWhiteSpace(charset))
        {
            return true;
        }

        var trimmed = charset.Trim();
        return trimmed.Equals("utf-8", StringComparison.OrdinalIgnoreCase)
            || trimmed.Equals("utf8", StringComparison.OrdinalIgnoreCase)
            || trimmed.Equals("us-ascii", StringComparison.OrdinalIgnoreCase)
            || trimmed.Equals("ascii", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Classifies the response's <c>Content-Encoding</c> for a body rewrite and, when a
    /// single supported encoding is present, returns its decoder. A non-null
    /// <paramref name="encoding"/> accompanies the <see cref="Decoding.Unsupported"/>
    /// (the offending encoding) and <see cref="Decoding.Chained"/> (the joined list)
    /// outcomes so the caller can log what it could not touch; the reason is
    /// deliberately phrased by the caller, which knows what it was trying to do.
    /// </summary>
    internal static Decoding ResolveDecoding(HttpContent content, out Func<Stream, Stream>? decoder, out string encoding)
    {
        ArgumentNullException.ThrowIfNull(content);

        decoder = null;
        encoding = string.Empty;

        var encodings = content.Headers.ContentEncoding;
        if (encodings.Count == 0)
        {
            return Decoding.UsableIdentity;
        }

        if (encodings.Count == 1)
        {
            var single = encodings.First() ?? string.Empty;
            if (single.Trim().Equals("identity", StringComparison.OrdinalIgnoreCase))
            {
                return Decoding.UsableIdentity;
            }

            decoder = CreateDecoder(single);
            if (decoder is not null)
            {
                return Decoding.UsableDecoded;
            }

            encoding = single;
            return Decoding.Unsupported;
        }

        encoding = string.Join(",", encodings);
        return Decoding.Chained;
    }

    private static Func<Stream, Stream>? CreateDecoder(string encoding) => encoding.Trim().ToLowerInvariant() switch
    {
        "gzip" or "x-gzip" => stream => new GZipStream(stream, CompressionMode.Decompress),
        "deflate" => stream => new DeflateStream(stream, CompressionMode.Decompress),
        "br" => stream => new BrotliStream(stream, CompressionMode.Decompress),
        _ => null,
    };
}
