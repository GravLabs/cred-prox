using System.Diagnostics.CodeAnalysis;
using System.IO.Compression;
using System.Net.Http.Headers;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace CredProx;

/// <summary>
/// The built-in response secret scrubber (M20, plan §8.2): when the upstream reflects
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
/// types stream through <see cref="ScrubbingStream"/>; gzip/deflate/br/zstd bodies of
/// eligible types are transparently decoded, scrubbed and forwarded decompressed
/// (<c>Content-Encoding</c> dropped) — a secret must not hide behind the encoding
/// header. An encoding this build cannot decode is logged once and forwarded untouched:
/// refusing exotic responses would break working traffic for a documented residue.
/// </para>
/// <para>
/// Scrubbing can change the body length, so a scrubbed response's <c>Content-Length</c>
/// is dropped (the caller sees chunked framing). The matcher works on UTF-8 bytes — a
/// body in a non-UTF-8 character set is a documented residue that carries the value
/// through. <c>text/event-stream</c> bodies scrub per event (M22): events flow as they
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

        if (context.Features.Get<CredProxRequestState>() is not { ProxyResponse: { } response })
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
            await ScrubBodyAsync(response, content, secrets.Values, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private async Task ScrubBodyAsync(
        HttpResponseMessage response,
        HttpContent content,
        IReadOnlyList<string> secrets,
        CancellationToken cancellationToken)
    {
        if (!ResponseBodies.IsTextLike(content.Headers.ContentType))
        {
            return; // binary or unknown shape: byte-identical pass-through
        }

        if (content.Headers.ContentLength == 0)
        {
            return; // an empty body holds nothing to scrub
        }

        switch (ResponseBodies.ResolveDecoding(content, out var decoder, out var encoding))
        {
            case ResponseBodies.Decoding.Unsupported:
                _logger.LogWarning(
                    "The upstream response used content encoding '{Encoding}', which cannot be "
                    + "scrubbed; the body was forwarded untouched.",
                    encoding);
                return;
            case ResponseBodies.Decoding.Chained:
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
            : new ScrubbingStream(decoded, secrets);
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
        _logger.LogDebug("The proxied response body was scrubbed for injected credentials.");
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
