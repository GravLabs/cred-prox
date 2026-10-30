using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.DependencyInjection;
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

    private static string GetHeader(HttpRequestMessage request, string name) =>
        Assert.Single(request.Headers.GetValues(name));
}
