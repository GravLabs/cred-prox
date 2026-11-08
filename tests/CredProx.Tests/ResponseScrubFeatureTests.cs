using System.IO.Compression;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// §5.2 "Response scrubbing (M20, §8.2)": the feature's gate chain (disabled / no
/// registry / content-type / encoding), header scrubbing, and the decode-scrub-forward
/// path — each outcome asserted where the caller would feel it.
/// </summary>
public sealed class ResponseScrubFeatureTests
{
    private const string Secret = "tok-9f2a-4711";

    private static ResponseScrubFeature Feature(bool enabled = true) =>
        new(new CredProxScrubbingOptions { Enabled = enabled }, NullLogger<ResponseScrubFeature>.Instance);

    private static DefaultHttpContext Context(HttpResponseMessage? response, out CredProxInjectedSecrets registry)
    {
        var context = new DefaultHttpContext();
        var state = new CredProxRequestState(context, new HttpRequestMessage(HttpMethod.Get, "http://upstream/api"));
        if (response is not null)
        {
            state.ProxyResponse = response;
        }

        context.Features.Set(state);
        registry = CredProxInjectedSecrets.GetOrCreate(context);
        return context;
    }

    private static HttpResponseMessage ResponseWith(string body, string? contentType)
    {
        var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK)
        {
            Content = new StringContent(body),
        };
        if (contentType is null)
        {
            response.Content.Headers.ContentType = null;
        }
        else
        {
            response.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType);
        }

        return response;
    }

    private static byte[] Compress<TStream>(byte[] data, CompressionMode mode)
        where TStream : Stream
    {
        using var compressed = new MemoryStream();
        using (var stream = (TStream)Activator.CreateInstance(typeof(TStream), compressed, mode, true)!)
        {
            stream.Write(data);
        }

        return compressed.ToArray();
    }

    // ---- the happy path: a text body that echoes the secret ----

    [Fact]
    public async Task TextBodyEchoingSecret_Scrubbed_FramingUpdated()
    {
        var response = ResponseWith($"error: rejected {Secret}", "text/plain");
        var context = Context(response, out var registry);
        registry.Register(Secret);

        await Feature().ApplyAsync(context, CancellationToken.None);

        Assert.Equal("error: rejected [redacted]", await response.Content.ReadAsStringAsync());
        Assert.Equal("text/plain", response.Content.Headers.ContentType?.MediaType);
        Assert.Null(response.Content.Headers.ContentLength); // old length described old bytes
        Assert.Empty(response.Content.Headers.ContentEncoding);
    }

    [Fact]
    public async Task JsonSuffixType_Scrubbed()
    {
        var response = ResponseWith($$"""{"echo":"{{Secret}}"}""", "application/vnd.api+json");
        var context = Context(response, out var registry);
        registry.Register(Secret);

        await Feature().ApplyAsync(context, CancellationToken.None);

        Assert.Contains("[redacted]", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task UrlEncodedFormOfSecret_Scrubbed()
    {
        // Query-placement credentials reflect in their encoded shape (§8.2).
        var response = ResponseWith("failed url: ?key=a%20b%2Fc", "text/plain");
        var context = Context(response, out var registry);
        registry.Register("a b/c");

        await Feature().ApplyAsync(context, CancellationToken.None);

        Assert.Equal("failed url: ?key=[redacted]", await response.Content.ReadAsStringAsync());
    }

    // ---- M22: text/event-stream takes the event framing ----

    [Fact]
    public async Task EventStreamBody_ScrubbedPerEvent()
    {
        var response = ResponseWith($"event: error\ndata: you sent {Secret}\n\ndata: done\n\n", "text/event-stream");
        var context = Context(response, out var registry);
        registry.Register(Secret);

        await Feature().ApplyAsync(context, CancellationToken.None);

        Assert.Equal(
            "event: error\ndata: you sent [redacted]\n\ndata: done\n\n",
            await response.Content.ReadAsStringAsync());
        Assert.Equal("text/event-stream", response.Content.Headers.ContentType?.MediaType);
        Assert.Null(response.Content.Headers.ContentLength);
    }

    [Fact]
    public async Task EventStreamWithCharsetParameter_StillEventFramed()
    {
        var response = ResponseWith($"data: {Secret}\n\n", "text/event-stream; charset=utf-8");
        var context = Context(response, out var registry);
        registry.Register(Secret);

        await Feature().ApplyAsync(context, CancellationToken.None);

        Assert.Equal($"data: [redacted]\n\n", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task GzippedEventStream_DecodedThenScrubbedPerEvent()
    {
        var gzipped = Compress<GZipStream>(Encoding.UTF8.GetBytes($"data: {Secret}\n\ndata: fine\n\n"), CompressionMode.Compress);
        var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(gzipped),
        };
        response.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("text/event-stream");
        response.Content.Headers.ContentEncoding.Add("gzip");
        var context = Context(response, out var registry);
        registry.Register(Secret);

        await Feature().ApplyAsync(context, CancellationToken.None);

        Assert.Equal("data: [redacted]\n\ndata: fine\n\n", await response.Content.ReadAsStringAsync());
        Assert.Empty(response.Content.Headers.ContentEncoding);
    }

    [Theory]
    [InlineData("text/event-stream", true)]
    [InlineData("TEXT/Event-Stream", true)]
    [InlineData("text/event-stream; charset=utf-8", true)]
    [InlineData("text/plain", false)]
    [InlineData("application/json", false)]
    public void IsEventStream_RecognizesOnlyEventStreams(string mediaType, bool expected) =>
        Assert.Equal(expected, ResponseBodies.IsEventStream(MediaTypeHeaderValue.Parse(mediaType)));

    [Fact]
    public void IsEventStream_MissingContentType_IsFalse() =>
        Assert.False(ResponseBodies.IsEventStream(null));

    // ---- the gate chain: everything else passes through byte-identical ----

    [Fact]
    public async Task Disabled_PassesThroughUntouched()
    {
        var response = ResponseWith($"error: rejected {Secret}", "text/plain");
        var context = Context(response, out var registry);
        registry.Register(Secret);

        await Feature(enabled: false).ApplyAsync(context, CancellationToken.None);

        Assert.Equal($"error: rejected {Secret}", await response.Content.ReadAsStringAsync());
        Assert.NotNull(response.Content.Headers.ContentLength);
    }

    [Fact]
    public async Task NoRegistry_PassesThrough()
    {
        var response = ResponseWith($"even {Secret} here", "text/plain");
        var context = Context(response, out _);
        // Deliberately no Register and no feature publication:
        context.Features.Set<CredProxInjectedSecrets?>(null);

        await Feature().ApplyAsync(context, CancellationToken.None);

        Assert.Equal($"even {Secret} here", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task EmptyRegistry_PassesThrough()
    {
        var response = ResponseWith($"even {Secret} here", "text/plain");
        var context = Context(response, out _); // GetOrCreate, nothing registered

        await Feature().ApplyAsync(context, CancellationToken.None);

        Assert.Equal($"even {Secret} here", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task NoProxyResponse_IsANoOp()
    {
        var context = Context(response: null, out var registry);
        registry.Register(Secret);

        await Feature().ApplyAsync(context, CancellationToken.None); // must not throw
    }

    [Fact]
    public async Task BinaryContentType_PassesThroughByteIdentical()
    {
        var payload = Encoding.UTF8.GetBytes($"binary says {Secret}");
        var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(payload),
        };
        response.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/octet-stream");
        var context = Context(response, out var registry);
        registry.Register(Secret);

        await Feature().ApplyAsync(context, CancellationToken.None);

        Assert.Equal(payload, await response.Content.ReadAsByteArrayAsync());
        Assert.Equal(payload.LongLength, response.Content.Headers.ContentLength);
    }

    [Fact]
    public async Task MissingContentType_PassesThroughByteIdentical()
    {
        var response = ResponseWith($"echo {Secret}", contentType: null);
        var context = Context(response, out var registry);
        registry.Register(Secret);

        await Feature().ApplyAsync(context, CancellationToken.None);

        Assert.Equal($"echo {Secret}", await response.Content.ReadAsStringAsync());
        Assert.NotNull(response.Content.Headers.ContentLength);
    }

    [Fact]
    public async Task EmptyBody_PassesThrough()
    {
        var response = ResponseWith(string.Empty, "application/json");
        var context = Context(response, out var registry);
        registry.Register(Secret);

        await Feature().ApplyAsync(context, CancellationToken.None);

        Assert.Equal(0, response.Content.Headers.ContentLength);
        Assert.Equal(string.Empty, await response.Content.ReadAsStringAsync());
    }

    // ---- compressed eligible bodies: decode, scrub, forward plain ----

    [Theory]
    [InlineData("gzip")]
    [InlineData("x-gzip")]
    [InlineData("deflate")]
    [InlineData("br")]
    public async Task CompressedTextBody_DecodedScrubbed_ForwardedPlain(string encoding)
    {
        var plain = Encoding.UTF8.GetBytes($"traceback: {Secret} threw");
        byte[] compressed = encoding switch
        {
            "gzip" or "x-gzip" => Compress<GZipStream>(plain, CompressionMode.Compress),
            "deflate" => Compress<DeflateStream>(plain, CompressionMode.Compress),
            _ => Compress<BrotliStream>(plain, CompressionMode.Compress),
        };

        var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(compressed),
        };
        response.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("text/plain");
        response.Content.Headers.TryAddWithoutValidation("Content-Encoding", encoding);
        var context = Context(response, out var registry);
        registry.Register(Secret);

        await Feature().ApplyAsync(context, CancellationToken.None);

        Assert.Equal("traceback: [redacted] threw", await response.Content.ReadAsStringAsync());
        Assert.Empty(response.Content.Headers.ContentEncoding);
        Assert.Null(response.Content.Headers.ContentLength);
    }

    [Fact]
    public async Task IdentityEncoding_StillScrubbed()
    {
        var response = ResponseWith($"echo {Secret}", "text/plain");
        response.Content.Headers.TryAddWithoutValidation("Content-Encoding", "identity");
        var context = Context(response, out var registry);
        registry.Register(Secret);

        await Feature().ApplyAsync(context, CancellationToken.None);

        Assert.Equal("echo [redacted]", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task UndecodableEncoding_Zstd_ForwardsUntouched()
    {
        // Documented residue: an encoding without a streaming decompressor is warned
        // about and forwarded — never silently half-processed.
        var payload = Encoding.UTF8.GetBytes($"echo {Secret}");
        var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(payload),
        };
        response.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("text/plain");
        response.Content.Headers.TryAddWithoutValidation("Content-Encoding", "zstd");
        var context = Context(response, out var registry);
        registry.Register(Secret);

        await Feature().ApplyAsync(context, CancellationToken.None);

        Assert.Equal(payload, await response.Content.ReadAsByteArrayAsync());
        Assert.Equal(["zstd"], response.Content.Headers.ContentEncoding);
    }

    [Fact]
    public async Task ChainedEncodings_ForwardedUntouched()
    {
        var payload = Encoding.UTF8.GetBytes($"echo {Secret}");
        var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(payload),
        };
        response.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("text/plain");
        response.Content.Headers.TryAddWithoutValidation("Content-Encoding", "gzip, br");
        var context = Context(response, out var registry);
        registry.Register(Secret);

        await Feature().ApplyAsync(context, CancellationToken.None);

        Assert.Equal(payload, await response.Content.ReadAsByteArrayAsync());
    }

    // ---- response headers (§8.2 signed decision 2) ----

    [Fact]
    public async Task EchoedSecretInResponseHeader_Scrubbed()
    {
        var response = ResponseWith("ok", "text/plain");
        response.Headers.TryAddWithoutValidation("X-Echo", $"Bearer {Secret}");
        var context = Context(response, out var registry);
        registry.Register(Secret);

        await Feature().ApplyAsync(context, CancellationToken.None);

        Assert.Equal("Bearer [redacted]", Assert.Single(response.Headers.GetValues("X-Echo")));
    }

    [Fact]
    public async Task MultiValueHeader_SecretValueReplaced_OthersKept()
    {
        var response = ResponseWith("ok", "text/plain");
        response.Headers.TryAddWithoutValidation("Set-Cookie", "a=1; Path=/");
        response.Headers.TryAddWithoutValidation("Set-Cookie", $"sid={Secret}; HttpOnly");
        response.Headers.TryAddWithoutValidation("Set-Cookie", "b=2; Secure");
        var context = Context(response, out var registry);
        registry.Register(Secret);

        await Feature().ApplyAsync(context, CancellationToken.None);

        Assert.Equal(
            ["a=1; Path=/", "sid=[redacted]; HttpOnly", "b=2; Secure"],
            response.Headers.GetValues("Set-Cookie"));
    }

    [Fact]
    public async Task SecretInContentHeader_Scrubbed()
    {
        var response = ResponseWith("ok", "text/plain");
        response.Content.Headers.TryAddWithoutValidation("X-Debug", Secret);
        var context = Context(response, out var registry);
        registry.Register(Secret);

        await Feature().ApplyAsync(context, CancellationToken.None);

        Assert.Equal("[redacted]", Assert.Single(response.Content.Headers.GetValues("X-Debug")));
    }

    // ---- the two internal helpers, directly ----

    [Theory]
    [InlineData("text/plain", true)]
    [InlineData("text/html; charset=utf-8", true)]
    [InlineData("application/json", true)]
    [InlineData("application/problem+json", true)]
    [InlineData("application/xml", true)]
    [InlineData("application/atom+xml", true)]
    [InlineData("application/javascript", true)]
    [InlineData("application/x-www-form-urlencoded", true)]
    [InlineData("application/yaml", true)]
    [InlineData("application/x-ndjson", true)]
    [InlineData("application/octet-stream", false)]
    [InlineData("image/png", false)]
    [InlineData("application/pdf", false)]
    [InlineData("application/zip", false)]
    [InlineData("multipart/form-data", false)]
    public void IsTextLike_ClassifiesEligibleTypes(string mediaType, bool expected) =>
        Assert.Equal(expected, ResponseBodies.IsTextLike(MediaTypeHeaderValue.Parse(mediaType)));

    [Fact]
    public void IsTextLike_MissingContentType_IsFalse() =>
        Assert.False(ResponseBodies.IsTextLike(null));

    [Fact]
    public void ScrubHeaders_NoMatch_LeavesHeadersAndReturnsFalse()
    {
        var headers = new HttpResponseMessage().Headers;
        headers.TryAddWithoutValidation("X-Keep", "value");

        Assert.False(ResponseScrubFeature.ScrubHeaders(headers, ["NOPE"]));
        Assert.Equal("value", Assert.Single(headers.GetValues("X-Keep")));
    }

    [Fact]
    public void ScrubHeaders_CaseSensitive_MatchesOrdinalOnly()
    {
        // Credentials are case-sensitive bytes; a case-folded "match" would redact
        // innocent text.
        var headers = new HttpResponseMessage().Headers;
        headers.TryAddWithoutValidation("X-Keep", "Token differs in case");

        Assert.False(ResponseScrubFeature.ScrubHeaders(headers, ["token"]));
        Assert.Equal("Token differs in case", Assert.Single(headers.GetValues("X-Keep")));
    }

    [Fact]
    public void ScrubHeaders_NullArguments_Throw_NamingEach()
    {
        var headers = new HttpResponseMessage().Headers;

        var nullHeaders = Assert.Throws<ArgumentNullException>(() => ResponseScrubFeature.ScrubHeaders(null!, ["s"]));
        Assert.Equal("headers", nullHeaders.ParamName);

        var nullSecrets = Assert.Throws<ArgumentNullException>(() => ResponseScrubFeature.ScrubHeaders(headers, null!));
        Assert.Equal("secrets", nullSecrets.ParamName);
    }

    [Fact]
    public void ScrubHeaders_ReturnsTrue_OnlyWhenAValueChanged()
    {
        var clean = new HttpResponseMessage().Headers;
        clean.TryAddWithoutValidation("X-Keep", "value");
        Assert.False(ResponseScrubFeature.ScrubHeaders(clean, ["NOPE"]));

        var dirty = new HttpResponseMessage().Headers;
        dirty.TryAddWithoutValidation("X-Echo", Secret);
        Assert.True(ResponseScrubFeature.ScrubHeaders(dirty, [Secret]));
    }

    // ---- operator-visible outcomes of the two forward-untouched paths (M31 triage) ----

    [Fact]
    public async Task UndecodableEncoding_LogsWarning_NamingTheEncoding()
    {
        var logs = new CapturingLoggerFactory();
        var payload = Encoding.UTF8.GetBytes($"echo {Secret}");
        var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(payload),
        };
        response.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("text/plain");
        response.Content.Headers.TryAddWithoutValidation("Content-Encoding", "zstd");
        var context = Context(response, out var registry);
        registry.Register(Secret);

        await new ResponseScrubFeature(
            new CredProxScrubbingOptions { Enabled = true },
            new Logger<ResponseScrubFeature>(logs)).ApplyAsync(context, CancellationToken.None);

        var warning = Assert.Single(logs.Entries, e => e.Level == LogLevel.Warning);
        Assert.Contains("zstd", warning.Message);
        Assert.Contains("forwarded untouched", warning.Message);
    }

    [Fact]
    public async Task ChainedEncodings_LogsWarning_NamingTheChain()
    {
        var logs = new CapturingLoggerFactory();
        var payload = Encoding.UTF8.GetBytes($"echo {Secret}");
        var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(payload),
        };
        response.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("text/plain");
        response.Content.Headers.TryAddWithoutValidation("Content-Encoding", "gzip, br");
        var context = Context(response, out var registry);
        registry.Register(Secret);

        await new ResponseScrubFeature(
            new CredProxScrubbingOptions { Enabled = true },
            new Logger<ResponseScrubFeature>(logs)).ApplyAsync(context, CancellationToken.None);

        var warning = Assert.Single(logs.Entries, e => e.Level == LogLevel.Warning);
        Assert.Contains("gzip", warning.Message);
        Assert.Contains("forwarded untouched", warning.Message);
    }

    [Fact]
    public async Task ScrubbedBody_LogsDebug_ConfirmingReplacement()
    {
        var logs = new CapturingLoggerFactory();
        var response = ResponseWith($"echo {Secret}", "text/plain");
        var context = Context(response, out var registry);
        registry.Register(Secret);

        await new ResponseScrubFeature(
            new CredProxScrubbingOptions { Enabled = true },
            new Logger<ResponseScrubFeature>(logs)).ApplyAsync(context, CancellationToken.None);

        Assert.Contains(logs.Entries, e => e.Level == LogLevel.Debug && e.Message.Contains("scrubbed"));
    }

    // ---- M31 batch-4b survivors: the framing gate and the empty-value guard ----

    [Fact]
    public async Task EventStreamBody_KeepsBoundarySpanningSecretResidue_ByteFramingWouldRedactIt()
    {
        // A secret whose bytes straddle the blank line matches in the joined byte
        // stream but in no single event. The documented event-framing residue means this
        // body must pass verbatim — the feature-level witness that SSE bodies really
        // take the event stream (the gate's conditional was otherwise unobserved).
        const string CrossBoundarySecret = "he\n\nlo";
        var input = $"data: x{CrossBoundarySecret[..2]}\n\n{CrossBoundarySecret[4..]} y\n\n";
        var response = ResponseWith(input, "text/event-stream");
        var context = Context(response, out var registry);
        registry.Register(CrossBoundarySecret);

        await Feature().ApplyAsync(context, CancellationToken.None);

        Assert.Equal(input, await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task ByteFramedBody_RedactsBoundaryStraddlingSecret_EventFramingWouldNot()
    {
        // The byte/framing switch seen from the other side: the same secret that the
        // event framing must miss (straddling the blank line) must REDACT on a plain
        // body — the witness that byte bodies really take the byte stream (M31 :129
        // triage: the always-event variant was otherwise unobserved).
        const string CrossBoundarySecret = "he\n\nlo";
        var input = $"x{CrossBoundarySecret[..2]}\n\n{CrossBoundarySecret[4..]} y";
        var response = ResponseWith(input, "application/json");
        var context = Context(response, out var registry);
        registry.Register(CrossBoundarySecret);

        await Feature().ApplyAsync(context, CancellationToken.None);

        Assert.Equal("x[redacted] y", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public void ScrubHeaders_NoValueMatches_ReportsUnchanged_KeepingEveryValue()
    {
        // "Nothing changed" is an observable answer: the caller only logs the
        // credential-leak warning when this returns true (M31 :168 triage — a dropped
        // not-changed continue turns every untouched header into a false change).
        var headers = new HttpResponseMessage().Headers;
        headers.TryAddWithoutValidation("X-A", "plain");
        headers.TryAddWithoutValidation("X-B", "other");

        Assert.False(ResponseScrubFeature.ScrubHeaders(headers, [Secret]));

        var seen = new Dictionary<string, string>();
        foreach (var (name, values) in headers)
        {
            seen[name] = string.Join("|", values);
        }

        Assert.Equal("plain", seen["X-A"]);
        Assert.Equal("other", seen["X-B"]);
    }

    [Fact]
    public void ScrubHeaders_EmptyValueHeader_IsEnumeratedButNeverAScrubSite()
    {
        // The BCL does enumerate an empty header value; the guard must pass it through
        // untouched (nothing matches, nothing reports changed) while a real secret in
        // the same header set still redacts (M31 :166 triage).
        var headers = new HttpResponseMessage().Headers;
        headers.TryAddWithoutValidation("X-Empty", string.Empty);
        headers.TryAddWithoutValidation("X-Echo", Secret);

        Assert.True(ResponseScrubFeature.ScrubHeaders(headers, [Secret]));

        var seen = new Dictionary<string, string>();
        foreach (var (name, values) in headers)
        {
            seen[name] = string.Join("|", values);
        }

        Assert.Equal(string.Empty, seen["X-Empty"]);
        Assert.Equal("[redacted]", seen["X-Echo"]);
    }
}
