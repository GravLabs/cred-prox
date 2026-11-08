using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage of <see cref="ErrorNormalisationFeature"/>: the lenient-parse
/// settings behind the structured embed, the unknown-ContentLength sentinel, the
/// decompressed-form cap boundary, the too-large guidance text, the empty-body member
/// rule, the replacement content type, and the JSON-sniffing degrade paths.
/// </summary>
public sealed class ErrorNormalisationSurvivorTests
{
    private sealed class NonSeekableStream(Stream inner) : Stream
    {
        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Flush() => inner.Flush();

        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private static ErrorNormalisationFeature Feature(long cap = 8192, List<string?>? logs = null)
    {
        ILoggerFactory loggerFactory = logs is null
            ? Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance
            : new LoggerFactory([new CapturingLoggerProvider(logs)]);
        return new ErrorNormalisationFeature(
            new CredProxErrorsOptions { Enabled = true, MaxNormalisedBodyBytes = cap },
            loggerFactory.CreateLogger<ErrorNormalisationFeature>());
    }

    private static async Task<JsonDocument> ApplyAndReadProblem(
        ErrorNormalisationFeature feature,
        HttpResponseMessage response)
    {
        var context = M4Contexts.Create(out _);
        context.Features.Get<CredProxRequestState>()!.ProxyResponse = response;
        await feature.ApplyAsync(context, CancellationToken.None);
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync());
    }

    private static HttpResponseMessage VendorError(HttpStatusCode status, HttpContent content) =>
        new(status) { Content = content };

    private static StringContent Json(string body) =>
        new(body, Encoding.UTF8, "application/json");

    [Fact]
    public async Task LenientParsing_EmbedsTrailingCommaAndCommentJsonAsObjects()
    {
        var trailing = VendorError(HttpStatusCode.BadRequest, Json("""{"a":1,}"""));
        using (var problem = await ApplyAndReadProblem(Feature(), trailing))
        {
            Assert.Equal(
                JsonValueKind.Object,
                problem.RootElement.GetProperty("extensions").GetProperty("vendor_detail").ValueKind);
        }

        var commented = VendorError(HttpStatusCode.BadRequest, Json("""{"a":1 /*triage*/}"""));
        using var problem2 = await ApplyAndReadProblem(Feature(), commented);
        Assert.Equal(
            JsonValueKind.Object,
            problem2.RootElement.GetProperty("extensions").GetProperty("vendor_detail").ValueKind);
    }

    [Fact]
    public async Task UnknownContentLength_StillNormalises()
    {
        // The sentinel for "length unknown" must keep the body on the normalising path
        // (a raw ContentLength.Value would throw; a positive sentinel can short-circuit it).
        var content = new StreamContent(new NonSeekableStream(new MemoryStream("{\"a\":1}"u8.ToArray())))
        {
            Headers = { ContentType = MediaTypeHeaderValue.Parse("application/json") },
        };
        var response = VendorError(HttpStatusCode.BadRequest, content);

        using var problem = await ApplyAndReadProblem(Feature(), response);
        Assert.Equal(
            JsonValueKind.Object,
            problem.RootElement.GetProperty("extensions").GetProperty("vendor_detail").ValueKind);
    }

    [Fact]
    public async Task EmptyBodyWithUnknownLength_StillNormalisesAndCarriesNoVendorMembers()
    {
        // cap 0 plus an unknown declared length probes the sentinel directly: "unknown"
        // must never read as "larger than the cap".
        var content = new StreamContent(new NonSeekableStream(MemoryStream.Null))
        {
            Headers = { ContentType = MediaTypeHeaderValue.Parse("application/json") },
        };
        var response = VendorError(HttpStatusCode.BadRequest, content);

        using var problem = await ApplyAndReadProblem(Feature(cap: 0), response);
        var extensions = problem.RootElement.GetProperty("extensions");

        Assert.Equal("credprox.vendor_error", extensions.GetProperty("code").GetString());
        Assert.False(extensions.TryGetProperty("vendor_detail", out _)); // no text ⇒ no embed members
        Assert.False(extensions.TryGetProperty("vendor_content_type", out _));
    }

    [Fact]
    public async Task DecompressedFormExactlyAtTheCap_StillNormalises()
    {
        var decoded = new string('x', 8192); // exactly the cap
        using var compressed = new MemoryStream();
        using (var gzip = new GZipStream(compressed, CompressionMode.Compress, leaveOpen: true))
        {
            gzip.Write(Encoding.UTF8.GetBytes(decoded));
        }

        var content = new ByteArrayContent(compressed.ToArray())
        {
            Headers = { ContentType = MediaTypeHeaderValue.Parse("application/json") },
        };
        content.Headers.TryAddWithoutValidation("Content-Encoding", "gzip");
        var response = VendorError(HttpStatusCode.BadRequest, content);

        await Feature().ApplyAsync(ContextFor(response), CancellationToken.None);
        Assert.Equal(
            "application/problem+json",
            response.Content.Headers.ContentType!.MediaType);
    }

    private static Microsoft.AspNetCore.Http.HttpContext ContextFor(HttpResponseMessage response)
    {
        var context = M4Contexts.Create(out _);
        context.Features.Get<CredProxRequestState>()!.ProxyResponse = response;
        return context;
    }

    [Fact]
    public async Task BodyOverTheCap_LogsTheExactGuidanceMessage()
    {
        var logs = new List<string?>();
        var response = VendorError(
            HttpStatusCode.BadGateway,
            Json(new string('y', 100)));

        await Feature(cap: 8, logs: logs).ApplyAsync(ContextFor(response), CancellationToken.None);

        var message = Assert.Single(logs);
        Assert.Equal(
            "A vendor error body exceeded the 8-byte normalisation limit; the caller received "
            + "the vendor's own body untouched. Raise CredProx:Errors:MaxNormalisedBodyBytes to normalise larger bodies.",
            message);
    }

    [Fact]
    public async Task ReplacementContentType_IsProblemJsonWithUtf8Charset()
    {
        var response = VendorError(HttpStatusCode.BadRequest, Json("{}"));

        using (await ApplyAndReadProblem(Feature(), response))
        {
        }

        Assert.Equal(
            "application/problem+json; charset=utf-8",
            response.Content.Headers.ContentType!.ToString());
    }

    [Fact]
    public async Task JsonArrayBody_EmbedsStructured()
    {
        var response = VendorError(HttpStatusCode.BadRequest, Json("[1,2]"));

        using var problem = await ApplyAndReadProblem(Feature(), response);
        var detail = problem.RootElement.GetProperty("extensions").GetProperty("vendor_detail");
        Assert.Equal(JsonValueKind.Array, detail.ValueKind);
        Assert.Equal(2, detail.GetArrayLength());
    }

    [Theory]
    [InlineData(" ")] // whitespace only — an empty trimmed body is never parsed
    [InlineData("{oops")] // JSON-shaped but malformed — degrades to the raw text member
    [InlineData("5")] // a legal JSON SCALAR is not a JSON document shape: stays raw text (the shape guard is load-bearing)
    public async Task NonParsableBodies_DegradeToRawText(string body)
    {
        var response = VendorError(HttpStatusCode.BadRequest, Json(body));

        using var problem = await ApplyAndReadProblem(Feature(), response);
        var detail = problem.RootElement.GetProperty("extensions").GetProperty("vendor_detail");
        Assert.Equal(JsonValueKind.String, detail.ValueKind);
        Assert.Equal(body, detail.GetString());
    }

    [Fact]
    public void PrefixThenRest_CapabilityFlags_AndUnsupportedMembers()
    {
        // The replay stream is read-only: a host probing CanWrite must not be told it
        // may write into what is a request body being resent (M31 triage).
        using var stream = new PrefixThenRestStream("P"u8.ToArray(), new MemoryStream("R"u8.ToArray()));

        Assert.True(stream.CanRead);
        Assert.False(stream.CanSeek);
        Assert.False(stream.CanWrite);
        Assert.Throws<NotSupportedException>(() => _ = stream.Length);
        Assert.Throws<NotSupportedException>(() => _ = stream.Position);
        Assert.Throws<NotSupportedException>(() => stream.Position = 0);
        Assert.Throws<NotSupportedException>(() => stream.Seek(0, SeekOrigin.Begin));
        Assert.Throws<NotSupportedException>(() => stream.SetLength(1));
        Assert.Throws<NotSupportedException>(() => stream.Write(new byte[1], 0, 1));
        Assert.Throws<NotSupportedException>(() => stream.WriteByte(1));
    }

    [Fact]
    public async Task PrefixThenRest_ZeroLengthProbe_KeepsPrefixAndRest()
    {
        // The forwarder's copy loop opens with a zero-length probe: it must take 0 bytes
        // on BOTH paths without latching the prefix as drained — the whole body must
        // still follow byte-for-byte (M31 triage: the async probe path was unrun).
        using var stream = new PrefixThenRestStream(
            "PREFIX"u8.ToArray(),
            new MemoryStream("REST"u8.ToArray()));

        Assert.Equal(0, stream.Read(Span<byte>.Empty));
        Assert.Equal(0, await stream.ReadAsync(Memory<byte>.Empty));

        var buffer = new byte[32];
        var first = stream.Read(buffer, 0, buffer.Length);
        var rest = await stream.ReadAsync(buffer.AsMemory(first, buffer.Length - first));
        Assert.Equal("PREFIXREST", Encoding.UTF8.GetString(buffer, 0, first + rest));
    }

    [Fact]
    public void PrefixThenRest_Dispose_ReleasesBothHalves()
    {
        // The wrapper owns the inner body: disposing it must dispose the inner and the
        // buffered prefix, and make further reads refuse (M31 triage: the dispose wiring
        // had no witness).
        var rest = new MemoryStream("REST"u8.ToArray());
        var stream = new PrefixThenRestStream("PREFIX"u8.ToArray(), rest);

        stream.Dispose();

        Assert.Throws<ObjectDisposedException>(() => rest.Read(new byte[1], 0, 1));
        Assert.Throws<ObjectDisposedException>(() => stream.Read(new byte[8], 0, 8));
    }

    [Fact]
    public void PrefixThenRest_SyncRead_EmitsPrefixThenRest()
    {
        // The replay stream serves the buffered prefix first on the SYNC path too — a
        // caller (or a forwarder that fell back to sync reads) must see the byte-identical
        // body, prefix included. Only the async path had coverage (M31 triage).
        using var stream = new PrefixThenRestStream(
            "PREFIX"u8.ToArray(),
            new MemoryStream("REST"u8.ToArray()));

        var buffer = new byte[32];
        var all = new StringBuilder();
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            all.Append(Encoding.UTF8.GetString(buffer, 0, read));
        }

        Assert.Equal("PREFIXREST", all.ToString());
    }
}
