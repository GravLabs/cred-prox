using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CredProx;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// §5.2 "HMAC signing" row: three canonical-string layouts verified by an INDEPENDENT
/// reference verifier (implemented here straight from the documented layout, sharing no
/// code with <c>HmacSigner</c>); body hash correct for empty, small and max-size bodies;
/// body over the cap → 413 <c>credprox.body_too_large_to_sign</c>; signing runs after
/// header shaping (the signature covers the final header values); the timestamp comes
/// from <see cref="TimeProvider"/>.
/// </summary>
public sealed class HmacSignFeatureTests
{
    private const string KeyValue = "shared-key-value";
    private static readonly DateTimeOffset T0 = new(2026, 10, 15, 10, 0, 0, TimeSpan.Zero);

    private static (ServiceProvider Services, HmacSignFeature Feature) Build(
        params (string Key, string? Value)[] credProxEntries)
    {
        var configuration = TestConfig.Root(
            credProxEntries.Select(e => ("CredProx:" + e.Key, e.Value)).ToArray());

        var services = new ServiceCollection();
        services.AddCredProxTokenCache();
        services.AddCredProxConfigurationSecrets(configuration);
        services.AddCredProxBuiltInCredentials();
        services.AddCredProxHmac();
        services.AddCredProxCredentials(configuration);
        var provider = services.BuildServiceProvider();

        var feature = new HmacSignFeature(
            provider.GetRequiredService<CredentialRegistryProvider>(),
            new FakeTimeProvider(T0),
            NullLogger<HmacSignFeature>.Instance);
        return (provider, feature);
    }

    private static readonly Dictionary<string, string> SignRoute =
        new() { [CredProxMetadata.Credential] = "signer" };

    private static (string Key, string? Value)[] HmacConfig(params (string Key, string? Value)[] extra) =>
    [
        ("Credentials:signer:Type", "Hmac"),
        ("Credentials:signer:Secret", "secret:hmac-key"),
        ("Credentials:signer:SignatureHeader", "X-Signature"),
        ("Secrets:hmac-key", KeyValue),
        .. extra,
    ];

    // ---- independent reference verifiers (documented layouts, no product code) ----

    private static string ReferenceHmac(string canonical, string key) =>
        Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes(key), Encoding.UTF8.GetBytes(canonical)))
            .ToLowerInvariant();

    private static string ReferenceSha256Hex(byte[] body) =>
        Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant();

    [Fact]
    public async Task LayoutA_MethodPathTimestampBodyHash_VerifiesAgainstReference()
    {
        var (_, feature) = Build(HmacConfig(
            ("Credentials:signer:Components:0", "method"),
            ("Credentials:signer:Components:1", "path"),
            ("Credentials:signer:Components:2", "timestamp"),
            ("Credentials:signer:Components:3", "bodyHash"),
            ("Credentials:signer:BufferBody", "true")));

        var context = M4Contexts.Create(out var proxyRequest, SignRoute);
        proxyRequest.Method = HttpMethod.Post;
        proxyRequest.RequestUri = new Uri("https://vendor.example/api/widgets");
        proxyRequest.Content = new StringContent("payload-body");

        await feature.ApplyAsync(context, default);

        // Reference canonical string, written from the layout definition:
        // METHOD \n PATH \n UNIX-SECONDS \n sha256-hex(body)
        var canonical = string.Join('\n',
            "POST",
            "/api/widgets",
            T0.ToUnixTimeSeconds(),
            ReferenceSha256Hex(Encoding.UTF8.GetBytes("payload-body")));
        Assert.Equal(ReferenceHmac(canonical, KeyValue), GetHeader(proxyRequest, "X-Signature"));
        Assert.False(context.Features.Get<CredProxRequestState>()!.IsAborted);
    }

    [Fact]
    public async Task LayoutB_SelectedHeaders_VerifiesAgainstReference()
    {
        var (_, feature) = Build(HmacConfig(
            ("Credentials:signer:Components:0", "method"),
            ("Credentials:signer:Components:1", "path"),
            ("Credentials:signer:Components:2", "header:Content-Type"),
            ("Credentials:signer:Components:3", "header:X-Idempotency"),
            ("Credentials:signer:Components:4", "timestamp")));

        var context = M4Contexts.Create(out var proxyRequest, SignRoute);
        proxyRequest.Method = HttpMethod.Put;
        proxyRequest.RequestUri = new Uri("https://vendor.example/api/orders");
        proxyRequest.Content = new StringContent("{}", Encoding.UTF8, "application/json");
        proxyRequest.Headers.Add("X-Idempotency", "abc-123");

        await feature.ApplyAsync(context, default);

        var canonical = string.Join('\n',
            "PUT",
            "/api/orders",
            "application/json; charset=utf-8",
            "abc-123",
            T0.ToUnixTimeSeconds());
        Assert.Equal(ReferenceHmac(canonical, KeyValue), GetHeader(proxyRequest, "X-Signature"));
    }

    [Fact]
    public async Task LayoutC_QueryIncluded_VerifiesAgainstReference()
    {
        var (_, feature) = Build(HmacConfig(
            ("Credentials:signer:Components:0", "method"),
            ("Credentials:signer:Components:1", "path"),
            ("Credentials:signer:Components:2", "query"),
            ("Credentials:signer:Components:3", "timestamp"),
            ("Credentials:signer:TimestampFormat", "Iso8601Utc")));

        var context = M4Contexts.Create(out var proxyRequest, SignRoute);
        proxyRequest.RequestUri = new Uri("https://vendor.example/search?q=widget&page=2");

        await feature.ApplyAsync(context, default);

        var canonical = string.Join('\n',
            "GET",
            "/search",
            "q=widget&page=2",
            "2026-10-15T10:00:00Z");
        Assert.Equal(ReferenceHmac(canonical, KeyValue), GetHeader(proxyRequest, "X-Signature"));
    }

    [Fact]
    public async Task LivePipelineShape_NullRequestUri_SignsStatePathAndQuery()
    {
        // Regression (found by the E9 sample): on the live YARP pipeline RequestUri is
        // assembled only after every transform completes — it is null while features run —
        // and the final path/query ride on the state. Signing must use the state, not the
        // (still absent) RequestUri, or the path component signs empty.
        var (_, feature) = Build(HmacConfig(
            ("Credentials:signer:Components:0", "method"),
            ("Credentials:signer:Components:1", "path"),
            ("Credentials:signer:Components:2", "query"),
            ("Credentials:signer:Components:3", "timestamp")));

        var context = M4Contexts.Create(out var proxyRequest, SignRoute);
        proxyRequest.Method = HttpMethod.Post;
        proxyRequest.RequestUri = null;
        var state = context.Features.Get<CredProxRequestState>()!;
        state.OutboundPath = "/api/widgets";
        state.OutboundQuery = "?b=2&a=1";

        await feature.ApplyAsync(context, default);

        var canonical = string.Join('\n',
            "POST",
            "/api/widgets",
            "b=2&a=1",
            T0.ToUnixTimeSeconds());
        Assert.Equal(ReferenceHmac(canonical, KeyValue), GetHeader(proxyRequest, "X-Signature"));
        Assert.False(state.IsAborted);
    }

    [Theory]
    [InlineData("")]
    [InlineData("small body")]
    public async Task BodyHash_CorrectForEmptyAndSmallBodies(string body)
    {
        var (_, feature) = Build(HmacConfig(
            ("Credentials:signer:Components:0", "bodyHash"),
            ("Credentials:signer:BufferBody", "true")));

        var context = M4Contexts.Create(out var proxyRequest, SignRoute);
        proxyRequest.Content = new StringContent(body, Encoding.UTF8);

        await feature.ApplyAsync(context, default);

        Assert.Equal(
            ReferenceHmac(ReferenceSha256Hex(Encoding.UTF8.GetBytes(body)), KeyValue),
            GetHeader(proxyRequest, "X-Signature"));

        // The buffered body still flows to the upstream after hashing.
        Assert.Equal(body, await proxyRequest.Content!.ReadAsStringAsync());
    }

    [Fact]
    public async Task BodyHash_UnknownLengthBody_StillFlowsAfterHashing()
    {
        // Same upstream-forwarding guarantee as the known-length theory above, for the
        // branch where the size can only be learned by reading: whatever the signing
        // stage does to count the bytes, the body must remain fully readable after it.
        var body = "small body";
        var (_, feature) = Build(HmacConfig(
            ("Credentials:signer:Components:0", "bodyHash"),
            ("Credentials:signer:BufferBody", "true")));

        var context = M4Contexts.Create(out var proxyRequest, SignRoute);
        proxyRequest.Method = HttpMethod.Post;
        proxyRequest.RequestUri = new Uri("https://vendor.example/api/widgets");
        var content = new StreamContent(new MemoryStream(Encoding.UTF8.GetBytes(body)));
        content.Headers.ContentLength = null; // unknown length: the counted read is the only path
        proxyRequest.Content = content;

        await feature.ApplyAsync(context, default);

        Assert.Equal(
            ReferenceHmac(ReferenceSha256Hex(Encoding.UTF8.GetBytes(body)), KeyValue),
            GetHeader(proxyRequest, "X-Signature"));

        // The counted body still flows to the upstream after hashing.
        Assert.Equal(body, await proxyRequest.Content!.ReadAsStringAsync());
    }

    [Fact]
    public async Task BodyHash_CorrectForMaxSizeBody()
    {
        var body = new string('x', 64);
        var (_, feature) = Build(HmacConfig(
            ("Credentials:signer:Components:0", "bodyHash"),
            ("Credentials:signer:BufferBody", "true"),
            ("Credentials:signer:MaxBodyBytes", "64")));

        var context = M4Contexts.Create(out var proxyRequest, SignRoute);
        proxyRequest.Content = new StringContent(body, Encoding.UTF8);

        await feature.ApplyAsync(context, default);

        Assert.Equal(
            ReferenceHmac(ReferenceSha256Hex(Encoding.UTF8.GetBytes(body)), KeyValue),
            GetHeader(proxyRequest, "X-Signature"));
    }

    [Fact]
    public async Task BodyOverCap_Answers413WithCode()
    {
        var (_, feature) = Build(HmacConfig(
            ("Credentials:signer:Components:0", "bodyHash"),
            ("Credentials:signer:BufferBody", "true"),
            ("Credentials:signer:MaxBodyBytes", "8")));

        var context = M4Contexts.Create(out var proxyRequest, SignRoute);
        proxyRequest.Content = new StringContent(new string('x', 100), Encoding.UTF8);

        await feature.ApplyAsync(context, default);

        Assert.True(context.Features.Get<CredProxRequestState>()!.IsAborted);
        Assert.Equal(413, context.Response.StatusCode);
        using var document = JsonDocument.Parse(M4Contexts.ResponseBody(context));
        Assert.Equal(
            "credprox.body_too_large_to_sign",
            document.RootElement.GetProperty("extensions").GetProperty("code").GetString());
        Assert.False(proxyRequest.Headers.Contains("X-Signature"));
    }

    [Fact]
    public async Task Signing_CoversFinalHeaderValues_AfterShaping()
    {
        // The Sign stage runs after ShapeHeaders; a header set during shaping must be
        // covered by the signature exactly as the upstream will receive it.
        var (_, feature) = Build(HmacConfig(
            ("Credentials:signer:Components:0", "header:X-Tenant"),
            ("Credentials:signer:Components:1", "timestamp")));

        var context = M4Contexts.Create(out var proxyRequest, SignRoute);
        proxyRequest.Headers.Add("X-Tenant", "final-value"); // as left by header shaping

        await feature.ApplyAsync(context, default);

        var canonical = $"final-value\n{T0.ToUnixTimeSeconds()}";
        Assert.Equal(ReferenceHmac(canonical, KeyValue), GetHeader(proxyRequest, "X-Signature"));
    }

    [Fact]
    public async Task TimestampHeader_ComesFromTimeProvider()
    {
        var (_, feature) = Build(HmacConfig(
            ("Credentials:signer:Components:0", "timestamp"),
            ("Credentials:signer:TimestampHeader", "X-Timestamp")));

        var context = M4Contexts.Create(out var proxyRequest, SignRoute);

        await feature.ApplyAsync(context, default);

        Assert.Equal(T0.ToUnixTimeSeconds().ToString(), GetHeader(proxyRequest, "X-Timestamp"));
    }

    [Fact]
    public async Task SignatureHeader_IsReplacedNotMerged()
    {
        var (_, feature) = Build(HmacConfig(("Credentials:signer:Components:0", "method")));

        var context = M4Contexts.Create(out var proxyRequest, SignRoute);
        proxyRequest.Headers.Add("X-Signature", "caller-forged-signature");

        await feature.ApplyAsync(context, default);

        Assert.Equal(
            new[] { ReferenceHmac("GET", KeyValue) },
            proxyRequest.Headers.GetValues("X-Signature"));
    }

    [Fact]
    public async Task SchemePrefix_IsWrittenBeforeTheSignature()
    {
        var (_, feature) = Build(HmacConfig(
            ("Credentials:signer:Components:0", "method"),
            ("Credentials:signer:SchemePrefix", "HMAC-SHA256 ")));

        var context = M4Contexts.Create(out var proxyRequest, SignRoute);

        await feature.ApplyAsync(context, default);

        Assert.Equal("HMAC-SHA256 " + ReferenceHmac("GET", KeyValue), GetHeader(proxyRequest, "X-Signature"));
    }

    [Fact]
    public async Task NonHmacCredential_PassesThrough()
    {
        var (_, feature) = Build(
            ("Credentials:signer:Type", "StaticKey"),
            ("Credentials:signer:Secret", "secret:k"),
            ("Credentials:signer:Name", "X-Key"),
            ("Secrets:k", "v"));

        var context = M4Contexts.Create(out var proxyRequest, SignRoute);

        await feature.ApplyAsync(context, default);

        Assert.False(proxyRequest.Headers.Contains("X-Signature"));
        Assert.False(context.Features.Get<CredProxRequestState>()!.IsAborted);
    }

    [Fact]
    public async Task RouteWithoutCredential_PassesThrough()
    {
        var (_, feature) = Build(HmacConfig(("Credentials:signer:Components:0", "method")));

        var context = M4Contexts.Create(out var proxyRequest, routeMetadata: null);

        await feature.ApplyAsync(context, default);

        Assert.False(proxyRequest.Headers.Contains("X-Signature"));
    }

    [Fact]
    public async Task CredentialDoesNotResolve_Aborts502WithCodeTitleAndWarning()
    {
        // The Secret reference is configured but names nothing the source can answer:
        // the provider's obtain throws inside the feature's try, the catch answers the
        // uniform credential problem (code + caller-safe title) and warns with the
        // per-request reason. §5.2 "unobtainable credential" row, signing stage.
        var configuration = TestConfig.Root(HmacConfig(("Credentials:signer:Components:0", "method"))
            .Select(e => (Key: "CredProx:" + e.Key, Value: e.Value))
            .Where(e => e.Key != "CredProx:Secrets:hmac-key") // the reference names nothing
            .ToArray());
        var services = new ServiceCollection();
        services.AddCredProxTokenCache();
        services.AddCredProxConfigurationSecrets(configuration);
        services.AddCredProxBuiltInCredentials();
        services.AddCredProxHmac();
        services.AddCredProxCredentials(configuration);
        var logger = new CapturingLogger();
        var feature = new HmacSignFeature(
            services.BuildServiceProvider().GetRequiredService<CredentialRegistryProvider>(),
            new FakeTimeProvider(T0),
            logger);

        var context = M4Contexts.Create(out var proxyRequest, SignRoute);
        await feature.ApplyAsync(context, default);

        var state = context.Features.Get<CredProxRequestState>()!;
        Assert.True(state.IsAborted);
        Assert.Equal(502, context.Response.StatusCode);
        using var problem = JsonDocument.Parse(M4Contexts.ResponseBody(context));
        Assert.Equal(
            "credprox.credential_unavailable",
            problem.RootElement.GetProperty("extensions").GetProperty("code").GetString());
        Assert.Equal(
            "The outbound credential could not be obtained.",
            problem.RootElement.GetProperty("title").GetString());
        Assert.False(proxyRequest.Headers.Contains("X-Signature"));

        // The warning carries the credential name and the obtain failure for operators —
        // it is the only place the per-request reason surfaces (the body stays static).
        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("signer", entry.Message, StringComparison.Ordinal);
        Assert.Contains("could not be obtained", entry.Message, StringComparison.Ordinal);
    }

    // ---- defensive feature guards, unreachable through a validated config -------------
    //
    // The options validator rejects these combinations at startup, so the feature's own
    // fail-closed branches cannot be driven by configuration. The live registry of a
    // correctly built provider is swapped to the state each guard protects, and the
    // feature must refuse to sign rather than emit a signature no verifier can reproduce.

    private static CredentialRegistry HandRolledHmacRegistry(HmacOptions options) =>
        new(new Dictionary<string, CredentialBinding>(StringComparer.OrdinalIgnoreCase)
        {
            ["signer"] = new CredentialBinding
            {
                Name = "signer",
                TypeName = "Hmac",
                Options = options,
                GetCredential = static (_, _) => ValueTask.FromResult(KeyValue),
            },
        });

    private static void SwapInRegistry(ServiceProvider services, CredentialRegistry registry)
    {
        var provider = services.GetRequiredService<CredentialRegistryProvider>();
        typeof(CredentialRegistryProvider)
            .GetField("_current", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
            .SetValue(provider, registry);
    }

    private static HmacSignFeature BuildFeature(ServiceProvider services, CapturingLogger logger) =>
        new(
            services.GetRequiredService<CredentialRegistryProvider>(),
            new FakeTimeProvider(T0),
            logger);

    private static (int StatusCode, string Code, string Title) ProblemEnvelope(HttpContext context)
    {
        using var document = JsonDocument.Parse(M4Contexts.ResponseBody(context));
        return (
            document.RootElement.GetProperty("status").GetInt32(),
            document.RootElement.GetProperty("extensions").GetProperty("code").GetString()!,
            document.RootElement.GetProperty("title").GetString()!);
    }

    [Fact]
    public async Task UnparseableComponent_FailsClosedSigningRefused()
    {
        var (services, _) = Build(HmacConfig(("Credentials:signer:Components:0", "method")));
        var registry = HandRolledHmacRegistry(new HmacOptions
        {
            Secret = "secret:hmac-key",
            SignatureHeader = "X-Signature",
            Components = ["method", "components"], // the second token is no recipe the verifier could rebuild
        });
        SwapInRegistry(services, registry);
        var logger = new CapturingLogger();
        var feature = BuildFeature(services, logger);

        var context = M4Contexts.Create(out var proxyRequest, SignRoute);
        await feature.ApplyAsync(context, default);

        var state = context.Features.Get<CredProxRequestState>()!;
        Assert.True(state.IsAborted);
        Assert.Equal(502, context.Response.StatusCode);
        var (status, code, title) = ProblemEnvelope(context);
        Assert.Equal(502, status);
        Assert.Equal("credprox.credential_unavailable", code);
        Assert.Equal("The outbound credential could not be obtained.", title);
        Assert.False(proxyRequest.Headers.Contains("X-Signature"));

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("signer", entry.Message, StringComparison.Ordinal);
        Assert.Contains("components", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task BodyHashWithoutBufferBody_FailsClosedBeforeHashing()
    {
        var (services, _) = Build(HmacConfig(("Credentials:signer:Components:0", "method")));
        var registry = HandRolledHmacRegistry(new HmacOptions
        {
            Secret = "secret:hmac-key",
            SignatureHeader = "X-Signature",
            Components = ["bodyHash"],
            BufferBody = false, // the validator rejects this pair; the feature must also refuse
            MaxBodyBytes = 1024,
        });
        SwapInRegistry(services, registry);
        var logger = new CapturingLogger();
        var feature = BuildFeature(services, logger);

        var context = M4Contexts.Create(out var proxyRequest, SignRoute);
        proxyRequest.Method = HttpMethod.Post;
        proxyRequest.RequestUri = new Uri("https://vendor.example/api/widgets");
        proxyRequest.Content = new StringContent("payload-body");

        await feature.ApplyAsync(context, default);

        var state = context.Features.Get<CredProxRequestState>()!;
        Assert.True(state.IsAborted);
        Assert.Equal(502, context.Response.StatusCode);
        Assert.Equal("credprox.credential_unavailable", ProblemEnvelope(context).Code);
        Assert.False(proxyRequest.Headers.Contains("X-Signature"));

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("BufferBody", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UnknownLengthBodyOverCap_Answers413WithCode()
    {
        // No Content-Length: the size cap is caught mid-buffer by the signing stage
        // itself, not from the header — the request must be refused, not signed blind.
        var (_, feature) = Build(HmacConfig(
            ("Credentials:signer:Components:0", "bodyHash"),
            ("Credentials:signer:BufferBody", "true"),
            ("Credentials:signer:MaxBodyBytes", "8")));

        var context = M4Contexts.Create(out var proxyRequest, SignRoute);
        proxyRequest.Method = HttpMethod.Post;
        proxyRequest.RequestUri = new Uri("https://vendor.example/api/widgets");
        var content = new StreamContent(new MemoryStream(Encoding.UTF8.GetBytes(new string('x', 200))));
        content.Headers.ContentLength = null; // unknown length
        proxyRequest.Content = content;

        await feature.ApplyAsync(context, default);

        var state = context.Features.Get<CredProxRequestState>()!;
        Assert.True(state.IsAborted);
        Assert.Equal(413, context.Response.StatusCode);
        using var document = JsonDocument.Parse(M4Contexts.ResponseBody(context));
        Assert.Equal(
            "credprox.body_too_large_to_sign",
            document.RootElement.GetProperty("extensions").GetProperty("code").GetString());
        Assert.False(proxyRequest.Headers.Contains("X-Signature"));
    }

    [Fact]
    public async Task ForwarderShapeBody_SignsAndFlows_WhenContentRefusesStreamShortcut()
    {
        // The real forwarder hands this stage YARP's StreamCopyHttpContent, whose
        // CreateContentReadStreamAsync throws NotImplementedException — a read path that
        // takes that shortcut fails the whole request. The body must still be counted,
        // hashed and forwarded through a read path every HttpContent supports.
        var body = "forwarded-through-the-forwarder-body";
        var (_, feature) = Build(HmacConfig(
            ("Credentials:signer:Components:0", "bodyHash"),
            ("Credentials:signer:BufferBody", "true")));

        var context = M4Contexts.Create(out var proxyRequest, SignRoute);
        proxyRequest.Method = HttpMethod.Post;
        proxyRequest.RequestUri = new Uri("https://vendor.example/api/widgets");
        proxyRequest.Content = new ForwarderShapeContent(Encoding.UTF8.GetBytes(body));

        await feature.ApplyAsync(context, default);

        Assert.False(context.Features.Get<CredProxRequestState>()!.IsAborted);
        Assert.Equal(
            ReferenceHmac(ReferenceSha256Hex(Encoding.UTF8.GetBytes(body)), KeyValue),
            GetHeader(proxyRequest, "X-Signature"));

        // The counted body still flows to the upstream after hashing, with its measured length.
        Assert.Equal(body, await proxyRequest.Content!.ReadAsStringAsync());
        Assert.Equal(Encoding.UTF8.GetByteCount(body), proxyRequest.Content!.Headers.ContentLength);
    }

    [Fact]
    public async Task ForwarderShapeBodyOverCap_Answers413WithCode()
    {
        // The measured-overrun refusal must hold for the forwarder's content shape too:
        // the cap is counted byte-by-byte during the copy, not learned from a shortcut.
        var (_, feature) = Build(HmacConfig(
            ("Credentials:signer:Components:0", "bodyHash"),
            ("Credentials:signer:BufferBody", "true"),
            ("Credentials:signer:MaxBodyBytes", "8")));

        var context = M4Contexts.Create(out var proxyRequest, SignRoute);
        proxyRequest.Method = HttpMethod.Post;
        proxyRequest.RequestUri = new Uri("https://vendor.example/api/widgets");
        proxyRequest.Content = new ForwarderShapeContent(Encoding.UTF8.GetBytes(new string('x', 200)));

        await feature.ApplyAsync(context, default);

        var state = context.Features.Get<CredProxRequestState>()!;
        Assert.True(state.IsAborted);
        Assert.Equal(413, context.Response.StatusCode);
        using var document = JsonDocument.Parse(M4Contexts.ResponseBody(context));
        Assert.Equal(
            "credprox.body_too_large_to_sign",
            document.RootElement.GetProperty("extensions").GetProperty("code").GetString());
        Assert.False(proxyRequest.Headers.Contains("X-Signature"));
    }

    private sealed class ForwarderShapeContent(byte[] body) : HttpContent
    {
        protected override Task SerializeToStreamAsync(Stream stream, System.Net.TransportContext? context) =>
            new MemoryStream(body, writable: false).CopyToAsync(stream);

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false; // the forwarder's copy carries no length until it is read
        }

        protected override Task<Stream> CreateContentReadStreamAsync() =>
            throw new NotImplementedException(); // exactly what YARP's StreamCopyHttpContent does
    }

    [Fact]
    public async Task UnknownLengthBodyWithFailingContent_KeepsItsCause_AndIsNotRefusedAsTooLarge()
    {
        // A content that fails for a reason unrelated to size must not be answered as a
        // body-size refusal: the failure travels with its own cause so the host pipeline
        // can log and map it. The cap is a number this stage measures itself, never a
        // guess from an exception that merely happens to arrive during buffering.
        var (_, feature) = Build(HmacConfig(
            ("Credentials:signer:Components:0", "bodyHash"),
            ("Credentials:signer:BufferBody", "true"),
            ("Credentials:signer:MaxBodyBytes", "1048576")));

        var context = M4Contexts.Create(out var proxyRequest, SignRoute);
        proxyRequest.Method = HttpMethod.Post;
        proxyRequest.RequestUri = new Uri("https://vendor.example/api/widgets");
        proxyRequest.Content = new ThrowingContent(); // no Content-Length; serialization always fails

        var failure = await Assert.ThrowsAsync<HttpRequestException>(
            () => feature.ApplyAsync(context, default).AsTask());

        Assert.Contains("simulated content serialization failure", failure.Message, StringComparison.Ordinal);
        var state = context.Features.Get<CredProxRequestState>()!;
        Assert.False(state.IsAborted);
        Assert.Equal(200, context.Response.StatusCode);
        Assert.False(proxyRequest.Headers.Contains("X-Signature"));
    }

    private sealed class ThrowingContent : HttpContent
    {
        protected override Task SerializeToStreamAsync(Stream stream, System.Net.TransportContext? context) =>
            throw new HttpRequestException("simulated content serialization failure");

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false; // unknown length: nothing in the headers answers the size
        }
    }

    private sealed class CapturingLogger : ILogger<HmacSignFeature>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception)));
    }

    private static string GetHeader(HttpRequestMessage request, string name) =>
        Assert.Single(request.Headers.GetValues(name));
}
