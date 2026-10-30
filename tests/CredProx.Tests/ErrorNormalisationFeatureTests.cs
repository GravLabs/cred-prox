using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// §8.5 vendor error normalisation (M24): the gate chain (global flag / status / HEAD /
/// route opt-out / content-type / encoding), the problem document's shape, the lossless
/// <c>vendor_detail</c> embed (parsed JSON, raw text, malformed fallback), and the cap —
/// overflow forwards byte-identical, never a truncated body.
/// </summary>
public sealed class ErrorNormalisationFeatureTests
{
    private static ErrorNormalisationFeature Feature(
        bool enabled = true,
        long cap = 8192,
        List<string?>? logs = null)
    {
        ILoggerFactory loggerFactory = logs is null
            ? NullLoggerFactory.Instance
            : new LoggerFactory([new CapturingLoggerProvider(logs)]);
        return new ErrorNormalisationFeature(
            new CredProxErrorsOptions { Enabled = enabled, MaxNormalisedBodyBytes = cap },
            loggerFactory.CreateLogger<ErrorNormalisationFeature>());
    }

    private static HttpResponseMessage VendorError(
        HttpStatusCode status,
        HttpContent content) =>
        new(status) { Content = content };

    private static StringContent Content(string body, string? contentType)
    {
        var content = new StringContent(body);
        content.Headers.ContentType = contentType is null
            ? null
            : MediaTypeHeaderValue.Parse(contentType);
        return content;
    }

    private static DefaultHttpContext Context(
        HttpResponseMessage? response,
        string method = "GET",
        Dictionary<string, string>? routeMetadata = null)
    {
        var context = M4Contexts.Create(out _, routeMetadata);
        context.Request.Method = method;
        if (response is not null)
        {
            context.Features.Get<CredProxRequestState>()!.ProxyResponse = response;
        }

        return context;
    }

    private static async Task<JsonDocument> ApplyAndReadProblem(
        ErrorNormalisationFeature feature,
        HttpResponseMessage response,
        Dictionary<string, string>? routeMetadata = null)
    {
        await feature.ApplyAsync(Context(response, routeMetadata: routeMetadata), CancellationToken.None);
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync());
    }

    // ---- the rewrite: shape, status preservation, framing ----

    [Fact]
    public async Task VendorJsonError_Rewritten_ProblemDocumentWithParsedVendorDetail()
    {
        var response = VendorError(
            HttpStatusCode.BadRequest,
            Content("""{"error":"bad_widget","ref":"R-42"}""", "application/json"));

        using var problem = await ApplyAndReadProblem(Feature(), response);
        var root = problem.RootElement;

        Assert.Equal("urn:credprox:errors:vendor", root.GetProperty("type").GetString());
        Assert.Equal(400, root.GetProperty("status").GetInt32());
        Assert.Equal("The upstream vendor returned an error.", root.GetProperty("title").GetString());
        Assert.False(root.TryGetProperty("detail", out _));
        Assert.False(root.TryGetProperty("instance", out _));

        var extensions = root.GetProperty("extensions");
        Assert.Equal("credprox.vendor_error", extensions.GetProperty("code").GetString());
        Assert.StartsWith("application/json", extensions.GetProperty("vendor_content_type").GetString());
        var detail = extensions.GetProperty("vendor_detail");
        Assert.Equal(JsonValueKind.Object, detail.ValueKind);
        Assert.Equal("bad_widget", detail.GetProperty("error").GetString());
        Assert.Equal("R-42", detail.GetProperty("ref").GetString());
    }

    [Fact]
    public async Task Rewrite_StatusFramingUpdated_ExactContentLength()
    {
        var response = VendorError(HttpStatusCode.InternalServerError, Content("boom", "text/plain"));

        await Feature().ApplyAsync(Context(response), CancellationToken.None);

        var bytes = await response.Content.ReadAsByteArrayAsync();
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal(bytes.Length, response.Content.Headers.ContentLength);
        Assert.Empty(response.Content.Headers.ContentEncoding);
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
    }

    [Fact]
    public async Task VendorErrorPreservesResponseLevelHeaders()
    {
        var response = VendorError(HttpStatusCode.TooManyRequests, Content("slow down", "text/plain"));
        response.Headers.TryAddWithoutValidation("Retry-After", "30");

        await Feature().ApplyAsync(Context(response), CancellationToken.None);

        Assert.Equal("30", response.Headers.RetryAfter?.ToString());
    }

    [Theory]
    [InlineData("text/plain")]
    [InlineData("text/html")]
    [InlineData("application/problem+json")]
    [InlineData("application/vnd.api+json")]
    public async Task TextLikeErrorBodies_AreNormalised(string contentType)
    {
        var response = VendorError(HttpStatusCode.BadGateway, Content("vendor said no", contentType));

        using var problem = await ApplyAndReadProblem(Feature(), response);

        Assert.Equal("urn:credprox:errors:vendor", problem.RootElement.GetProperty("type").GetString());
    }

    [Theory]
    [InlineData(HttpStatusCode.OK)]
    [InlineData(HttpStatusCode.NoContent)]
    [InlineData(HttpStatusCode.Moved)]
    [InlineData((HttpStatusCode)399)] // the boundary: 400 is the first normalised status
    public async Task NonErrorStatuses_FlowUntouched(HttpStatusCode status)
    {
        var response = VendorError(status, Content("body", "text/plain"));

        await Feature().ApplyAsync(Context(response), CancellationToken.None);

        Assert.Equal("body", await response.Content.ReadAsStringAsync());
        Assert.Equal("text/plain", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task HeadResponse_NeverGainsABody()
    {
        var response = VendorError(HttpStatusCode.NotFound, Content("not found", "text/plain"));

        await Feature().ApplyAsync(Context(response, method: "HEAD"), CancellationToken.None);

        Assert.Equal("not found", await response.Content.ReadAsStringAsync());
    }

    // ---- the embed: raw text, malformed JSON fallback, arrays, empty ----

    [Fact]
    public async Task TextError_EmbeddedAsRawText()
    {
        var response = VendorError(HttpStatusCode.InternalServerError, Content("disk on fire", "text/plain"));

        using var problem = await ApplyAndReadProblem(Feature(), response);
        var detail = problem.RootElement.GetProperty("extensions").GetProperty("vendor_detail");

        Assert.Equal(JsonValueKind.String, detail.ValueKind);
        Assert.Equal("disk on fire", detail.GetString());
    }

    [Fact]
    public async Task MalformedJsonBody_FallsBackToRawText()
    {
        // Starts like JSON but isn't: the embed degrades to the exact text, never an error.
        var response = VendorError(HttpStatusCode.BadRequest, Content("{oops", "application/json"));

        using var problem = await ApplyAndReadProblem(Feature(), response);
        var detail = problem.RootElement.GetProperty("extensions").GetProperty("vendor_detail");

        Assert.Equal(JsonValueKind.String, detail.ValueKind);
        Assert.Equal("{oops", detail.GetString());
    }

    [Fact]
    public async Task JsonArrayBody_EmbeddedAsArray()
    {
        var response = VendorError(
            HttpStatusCode.UnprocessableEntity,
            Content("""[{"field":"name","why":"missing"}]""", "application/json"));

        using var problem = await ApplyAndReadProblem(Feature(), response);
        var detail = problem.RootElement.GetProperty("extensions").GetProperty("vendor_detail");

        Assert.Equal(JsonValueKind.Array, detail.ValueKind);
        Assert.Equal("name", detail[0].GetProperty("field").GetString());
    }

    [Fact]
    public async Task EmptyErrorBody_StillNormalised_WithoutVendorMembers()
    {
        // A 503 with no body: the caller still gets the uniform document; there is just
        // nothing to embed.
        var response = VendorError(HttpStatusCode.ServiceUnavailable, new StringContent(""));

        using var problem = await ApplyAndReadProblem(Feature(), response);
        var extensions = problem.RootElement.GetProperty("extensions");

        Assert.Equal(503, problem.RootElement.GetProperty("status").GetInt32());
        Assert.Equal("credprox.vendor_error", extensions.GetProperty("code").GetString());
        Assert.False(extensions.TryGetProperty("vendor_detail", out _));
        Assert.False(extensions.TryGetProperty("vendor_content_type", out _));
    }

    // ---- content the framing must never touch ----

    [Fact]
    public async Task EventStreamError_StaysByteIdentical()
    {
        var response = VendorError(
            HttpStatusCode.InternalServerError,
            Content("event: error\ndata: fatal\n\n", "text/event-stream"));

        await Feature().ApplyAsync(Context(response), CancellationToken.None);

        Assert.Equal("event: error\ndata: fatal\n\n", await response.Content.ReadAsStringAsync());
        Assert.Equal("text/event-stream", response.Content.Headers.ContentType?.MediaType);
    }

    [Theory]
    [InlineData("application/octet-stream")]
    [InlineData("image/png")]
    [InlineData(null)] // unknown shape: not text-like, not touched
    public async Task BinaryOrUnknownContent_StaysByteIdentical(string? contentType)
    {
        var response = VendorError(HttpStatusCode.UnsupportedMediaType, Content("PNGPNG", contentType));

        await Feature().ApplyAsync(Context(response), CancellationToken.None);

        Assert.Equal("PNGPNG", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task UnsupportedEncoding_StaysByteIdentical()
    {
        var response = VendorError(HttpStatusCode.InternalServerError, Content("legacy", "text/plain"));
        response.Content.Headers.TryAddWithoutValidation("Content-Encoding", "compress");

        var logs = new List<string?>();
        await Feature(logs: logs).ApplyAsync(Context(response), CancellationToken.None);

        Assert.Equal("legacy", await response.Content.ReadAsStringAsync());
        Assert.Contains(logs, l => l is not null && l.Contains("compress", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ChainedEncoding_StaysByteIdentical()
    {
        var response = VendorError(HttpStatusCode.InternalServerError, Content("layered", "text/plain"));
        response.Content.Headers.TryAddWithoutValidation("Content-Encoding", "gzip, br");

        var logs = new List<string?>();
        await Feature(logs: logs).ApplyAsync(Context(response), CancellationToken.None);

        Assert.Equal("layered", await response.Content.ReadAsStringAsync());
        // The two entries are joined by ResolveDecoding as "gzip,br".
        Assert.Contains(logs, l => l is not null && l.Contains("gzip,br", StringComparison.Ordinal));
    }

    [Fact]
    public async Task GzipEncodedError_NormalisedFromDecodedBytes()
    {
        using var compressed = new MemoryStream();
        using (var gzip = new GZipStream(compressed, CompressionMode.Compress, leaveOpen: true))
        {
            gzip.Write(Encoding.UTF8.GetBytes("""{"error":"gzipped_bad"}"""));
        }

        var raw = new ByteArrayContent(compressed.ToArray());
        raw.Headers.ContentType = MediaTypeHeaderValue.Parse("application/json");
        raw.Headers.TryAddWithoutValidation("Content-Encoding", "gzip");
        var response = VendorError(HttpStatusCode.BadRequest, raw);

        using var problem = await ApplyAndReadProblem(Feature(), response);

        Assert.Equal(
            "gzipped_bad",
            problem.RootElement.GetProperty("extensions")
                .GetProperty("vendor_detail").GetProperty("error").GetString());
        Assert.Empty(response.Content.Headers.ContentEncoding); // the body is now plain JSON
    }

    // ---- the cap: overflow never truncates, never explodes ----

    [Fact]
    public async Task DeclaredLengthBeyondCap_ForwardsUntouched_WithWarning()
    {
        var body = new string('x', 100);
        var response = VendorError(HttpStatusCode.InternalServerError, Content(body, "text/plain"));

        var logs = new List<string?>();
        await Feature(cap: 32, logs: logs).ApplyAsync(Context(response), CancellationToken.None);

        Assert.Equal(body, await response.Content.ReadAsStringAsync());
        Assert.Equal("text/plain", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal(100, response.Content.Headers.ContentLength);
        Assert.Contains(logs, l => l is not null && l.Contains("MaxNormalisedBodyBytes", StringComparison.Ordinal));
    }

    [Fact]
    public async Task UndeclaredLengthBeyondCap_ReplaysPrefixPlusRestByteIdentical()
    {
        // Vendor lied (or chunked): nothing declared, bytes keep coming past the cap.
        // The buffered prefix plus the unread remainder must still be the exact body.
        var bytes = Encoding.UTF8.GetBytes(new string('y', 5000));
        var raw = new StreamContent(new MemoryStream(bytes));
        raw.Headers.ContentType = MediaTypeHeaderValue.Parse("text/plain");
        raw.Headers.ContentLength = null;
        var response = VendorError(HttpStatusCode.InternalServerError, raw);

        await Feature(cap: 64).ApplyAsync(Context(response), CancellationToken.None);

        Assert.Equal(bytes, await response.Content.ReadAsByteArrayAsync());
        Assert.Equal("text/plain", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task GzipBomb_DecodedFormCapped_CompressedBytesForwardedIntact()
    {
        // 200 KB of 'z' compresses to a few hundred bytes — under the cap compressed,
        // over it decoded. The cap must apply to the decoded form too; the caller gets
        // the vendor's compressed bytes, never the bomb's content or a truncated body.
        using var compressed = new MemoryStream();
        using (var gzip = new GZipStream(compressed, CompressionMode.Compress, leaveOpen: true))
        {
            gzip.Write(Encoding.UTF8.GetBytes(new string('z', 200_000)));
        }

        var payload = compressed.ToArray();
        // The cap must sit between the compressed and the decoded size: this is the
        // decode-stage overflow, not the raw-read overflow the other tests cover.
        Assert.True(payload.Length < 4096);

        var raw = new ByteArrayContent(payload);
        raw.Headers.ContentType = MediaTypeHeaderValue.Parse("text/plain");
        raw.Headers.TryAddWithoutValidation("Content-Encoding", "gzip");
        var response = VendorError(HttpStatusCode.InternalServerError, raw);

        var logs = new List<string?>();
        await Feature(cap: 4096, logs: logs).ApplyAsync(Context(response), CancellationToken.None);

        Assert.Equal(payload, await response.Content.ReadAsByteArrayAsync());
        Assert.Equal("gzip", Assert.Single(response.Content.Headers.ContentEncoding));
        Assert.Contains(logs, l => l is not null && l.Contains("MaxNormalisedBodyBytes", StringComparison.Ordinal));
    }

    [Fact]
    public async Task BodyExactlyAtCap_IsNormalised()
    {
        var body = new string('e', 64);
        var response = VendorError(HttpStatusCode.BadRequest, Content(body, "text/plain"));

        using var problem = await ApplyAndReadProblem(Feature(cap: 64), response);

        Assert.Equal(body, problem.RootElement.GetProperty("extensions").GetProperty("vendor_detail").GetString());
    }

    // ---- the opt-outs ----

    [Fact]
    public async Task GlobalDisable_FlowsUntouched()
    {
        var response = VendorError(HttpStatusCode.InternalServerError, Content("boom", "text/plain"));

        await Feature(enabled: false).ApplyAsync(Context(response), CancellationToken.None);

        Assert.Equal("boom", await response.Content.ReadAsStringAsync());
        Assert.Equal("text/plain", response.Content.Headers.ContentType?.MediaType);
    }

    [Theory]
    [InlineData("off")]
    [InlineData("OFF")] // the one documented value, matched case-insensitively
    public async Task RouteOptOut_FlowsByteIdentical(string value)
    {
        var response = VendorError(HttpStatusCode.BadRequest, Content("vendor's own shape", "text/plain"));

        await Feature().ApplyAsync(
            Context(response, routeMetadata: new Dictionary<string, string>
            {
                [CredProxMetadata.ErrorNormalisation] = value,
            }),
            CancellationToken.None);

        Assert.Equal("vendor's own shape", await response.Content.ReadAsStringAsync());
        Assert.Equal("text/plain", response.Content.Headers.ContentType?.MediaType);
    }

    [Theory]
    [InlineData("false")] // the near-misses normalise anyway — the value is "off"
    [InlineData("enabled")]
    [InlineData("")]
    public async Task RouteOptOut_UnknownValue_StillNormalises(string value)
    {
        var response = VendorError(HttpStatusCode.BadRequest, Content("boom", "text/plain"));

        await Feature().ApplyAsync(
            Context(response, routeMetadata: new Dictionary<string, string>
            {
                [CredProxMetadata.ErrorNormalisation] = value,
            }),
            CancellationToken.None);

        Assert.Equal(
            "urn:credprox:errors:vendor",
            JsonDocument.Parse(await response.Content.ReadAsStringAsync())
                .RootElement.GetProperty("type").GetString());
    }

    [Fact]
    public async Task NoProxyPipelineFeature_StillNormalises()
    {
        // Outside the stub pipeline there is no route metadata to read; the default-on
        // posture must not depend on the YARP feature being present.
        var context = new DefaultHttpContext();
        context.Request.Method = "GET";
        var response = VendorError(HttpStatusCode.BadRequest, Content("boom", "text/plain"));
        context.Features.Set(
            new CredProxRequestState(context, new HttpRequestMessage(HttpMethod.Get, "http://upstream/api"))
            {
                ProxyResponse = response,
            });

        await Feature().ApplyAsync(context, CancellationToken.None);

        Assert.Equal(
            "urn:credprox:errors:vendor",
            JsonDocument.Parse(await response.Content.ReadAsStringAsync())
                .RootElement.GetProperty("type").GetString());
    }

    [Fact]
    public async Task ComposedAfterScrubber_CapOverflowKeepsEveryByte()
    {
        // The live pipeline's composition at unit speed: scrub (whose look-ahead window
        // splits reads) followed by normalise over the cap must still hand the caller
        // every byte of the body.
        var response = VendorError(
            HttpStatusCode.InternalServerError,
            Content(new string('x', 200), "text/html"));
        var context = Context(response);
        CredProxInjectedSecrets.GetOrCreate(context).Register("token-1");

        await new ResponseScrubFeature(
            new CredProxScrubbingOptions(), NullLogger<ResponseScrubFeature>.Instance)
            .ApplyAsync(context, CancellationToken.None);
        await Feature(cap: 64).ApplyAsync(context, CancellationToken.None);

        var bytes = await response.Content.ReadAsByteArrayAsync();
        Assert.Equal(200, bytes.Length);
        Assert.Equal(new string('x', 200), Encoding.UTF8.GetString(bytes));
    }

    [Fact]
    public async Task NoProxiedResponse_IsNoOp()
    {
        var context = Context(response: null);

        await Feature().ApplyAsync(context, CancellationToken.None);

        Assert.Equal(200, context.Response.StatusCode);
    }

    // ---- proxy-side documents carry the proxy URN ----

    [Fact]
    public async Task ProxyProblemResponses_CarryProxyErrorType()
    {
        var response = CredProxProblemResponses.CreateResponse(503, "credprox.circuit_open", "No.");

        using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("urn:credprox:errors:proxy", problem.RootElement.GetProperty("type").GetString());
        Assert.Equal(
            "credprox.circuit_open",
            problem.RootElement.GetProperty("extensions").GetProperty("code").GetString());
    }

    // ---- charset eligibility (F1, M24 review): the embed decodes to text, so only
    // absent / UTF-8 / US-ASCII charsets can be rewritten without corrupting the payload;
    // anything else forwards byte-identical rather than arriving maimed in vendor_detail ----

    [Theory]
    [InlineData("UTF-8")]
    [InlineData("utf8")]
    [InlineData("us-ascii")]
    [InlineData("US-ASCII")]
    [InlineData("ascii")]
    public async Task LosslesslyDecodableCharset_Normalises(string charset)
    {
        var response = VendorError(
            HttpStatusCode.BadRequest,
            Content("bad widget", $"text/plain; charset={charset}"));

        using var problem = await ApplyAndReadProblem(Feature(), response);

        var extensions = problem.RootElement.GetProperty("extensions");
        Assert.Equal("credprox.vendor_error", extensions.GetProperty("code").GetString());
        Assert.Equal("bad widget", extensions.GetProperty("vendor_detail").GetString());
    }

    [Theory]
    [InlineData("iso-8859-1")]
    [InlineData("ISO-8859-1")]
    [InlineData("ISO-8859-15")]
    [InlineData("windows-1252")]
    [InlineData("utf-16")]
    [InlineData("utf-16LE")]
    [InlineData("shift_jis")]
    public async Task NonLosslessCharset_ForwardsByteIdentical_WithWarning(string charset)
    {
        // 0xFC is the Latin-1 u-umlaut: exactly the byte a UTF-8 read would turn into U+FFFD.
        var body = new byte[] { (byte)'F', (byte)'e', 0xFC, (byte)'h', (byte)'l' };
        var raw = new ByteArrayContent(body);
        raw.Headers.ContentType = MediaTypeHeaderValue.Parse($"text/plain; charset={charset}");
        var response = VendorError(HttpStatusCode.BadRequest, raw);
        var logs = new List<string?>();

        await Feature(logs: logs).ApplyAsync(Context(response), CancellationToken.None);

        Assert.Equal(body, await response.Content.ReadAsByteArrayAsync());
        Assert.Equal(charset, response.Content.Headers.ContentType?.CharSet);
        Assert.Contains(
            logs,
            l => l is not null
                && l.Contains("charset", StringComparison.OrdinalIgnoreCase)
                && l.Contains(charset, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task NonLosslessCharset_Gzipped_ForwardsCompressedBytesUntouched()
    {
        using var compressed = new MemoryStream();
        using (var gz = new GZipStream(compressed, CompressionMode.Compress, leaveOpen: true))
        {
            gz.Write(Encoding.UTF8.GetBytes("bad widget"));
        }

        var raw = new ByteArrayContent(compressed.ToArray());
        raw.Headers.ContentType = MediaTypeHeaderValue.Parse("application/json; charset=iso-8859-1");
        raw.Headers.ContentEncoding.Add("gzip");
        var response = VendorError(HttpStatusCode.BadRequest, raw);

        await Feature().ApplyAsync(Context(response), CancellationToken.None);

        Assert.Equal(compressed.ToArray(), await response.Content.ReadAsByteArrayAsync());
        Assert.Equal("gzip", Assert.Single(response.Content.Headers.ContentEncoding));
    }

    [Fact]
    public async Task EmptyBodyWithNonLosslessCharset_StillNormalises()
    {
        // Nothing to corrupt: an empty body still takes the uniform document, just without
        // the vendor members — and without the charset warning.
        var response = VendorError(
            HttpStatusCode.BadRequest,
            Content(string.Empty, "text/plain; charset=iso-8859-1"));
        var logs = new List<string?>();

        using var problem = await ApplyAndReadProblem(Feature(logs: logs), response);

        Assert.Equal("urn:credprox:errors:vendor", problem.RootElement.GetProperty("type").GetString());
        Assert.False(problem.RootElement.GetProperty("extensions").TryGetProperty("vendor_detail", out _));
        Assert.DoesNotContain(logs, l => l is not null && l.Contains("charset", StringComparison.OrdinalIgnoreCase));
    }
}
