using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// §5.2 "JWT assertion" row: RS256/ES256/PS256 signatures verify against the public key;
/// <c>iss</c>/<c>sub</c>/<c>aud</c>/<c>exp</c>/<c>iat</c>/<c>jti</c> set correctly; unique
/// <c>jti</c> per assertion; clock skew applied; the GitHub App (bearer) flow obtains an
/// installation token against a stub. Failure paths never leak key material or bodies.
/// </summary>
public sealed class JwtAssertionProviderTests : IDisposable
{
    private readonly RSA _rsa = RSA.Create(2048);
    private readonly ECDsa _ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public void Dispose()
    {
        _rsa.Dispose();
        _ecdsa.Dispose();
    }

    private const string RsaPemKey = "jwt-rsa-key";
    private const string EcPemKey = "jwt-ec-key";

    private static CredentialRequestContext Context(string? partition = "p1") =>
        new() { CredentialName = "test", Partition = partition };

    private string RsaPem() => _rsa.ExportPkcs8PrivateKeyPem();

    private string EcPem() => _ecdsa.ExportPkcs8PrivateKeyPem();

    private static ISecretAccessor Secrets(string rsaPem, string ecPem) => TestSecrets.AccessorFor(
        new() { ["SigningKey"] = $"secret:{RsaPemKey}" },
        new()
        {
            [RsaPemKey] = rsaPem,
            [EcPemKey] = ecPem,
        });

    private static (JwtAssertionProvider Provider, InMemoryTokenCache Cache, StubHttpHandler Handler) CreateProvider(
        StubHttpHandler handler,
        FakeTimeProvider? time = null)
    {
        time ??= new FakeTimeProvider();
        var cache = new InMemoryTokenCache(Options.Create(new TokenCacheOptions()), time);
        var provider = new JwtAssertionProvider(cache, new StubHttpClientFactory(handler), time);
        return (provider, cache, handler);
    }

    private static JwtAssertionOptions AssertionOptions(JwtAssertionExchange exchange = JwtAssertionExchange.ClientAssertion) => new()
    {
        Algorithm = JwtAssertionAlgorithm.RS256,
        SigningKey = $"secret:{RsaPemKey}",
        Issuer = "app-123",
        Subject = "installation-456",
        Audience = "https://github.com/login/oauth/access_token",
        TokenEndpoint = "https://vendor.example/token",
        Exchange = exchange,
    };

    private static (string Header, string Payload, byte[] Signature, byte[] SigningInput) ParseJwt(string jwt)
    {
        var parts = jwt.Split('.');
        Assert.Equal(3, parts.Length);
        return (
            Encoding.UTF8.GetString(Base64UrlDecode(parts[0])),
            Encoding.UTF8.GetString(Base64UrlDecode(parts[1])),
            Base64UrlDecode(parts[2]),
            Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]));
    }

    private static byte[] Base64UrlDecode(string value) =>
        Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4));

    private static Dictionary<string, string> ParseForm(string body) =>
        body.Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(pair => pair.Split('=', 2))
            .ToDictionary(parts => Uri.UnescapeDataString(parts[0]), parts => Uri.UnescapeDataString(parts[1]));

    [Theory]
    [InlineData(JwtAssertionAlgorithm.RS256)]
    [InlineData(JwtAssertionAlgorithm.PS256)]
    public async Task RsaAlgorithms_SignatureVerifiesAgainstPublicKey(JwtAssertionAlgorithm algorithm)
    {
        var (provider, _, handler) = CreateProvider(
            new StubHttpHandler(HttpStatusCode.OK, """{"access_token":"tok-1","expires_in":3600}"""));
        var options = AssertionOptions();
        options.Algorithm = algorithm;

        await provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default);

        var form = ParseForm(handler.Body(0)!);
        var (header, _, signature, signingInput) = ParseJwt(form["client_assertion"]);
        Assert.Contains($"\"alg\":\"{algorithm}\"", header);

        var padding = algorithm == JwtAssertionAlgorithm.PS256
            ? RSASignaturePadding.Pss
            : RSASignaturePadding.Pkcs1;
        Assert.True(_rsa.VerifyData(signingInput, signature, HashAlgorithmName.SHA256, padding));
    }

    [Fact]
    public async Task Es256_SignatureVerifiesAgainstPublicKey()
    {
        var (provider, _, handler) = CreateProvider(
            new StubHttpHandler(HttpStatusCode.OK, """{"access_token":"tok-1","expires_in":3600}"""));
        var options = AssertionOptions();
        options.Algorithm = JwtAssertionAlgorithm.ES256;
        options.SigningKey = $"secret:{EcPemKey}";

        // The scoped accessor admits only references declared in the credential's own
        // configuration — so the EC key needs its own declaration.
        var secrets = TestSecrets.AccessorFor(
            new() { ["SigningKey"] = $"secret:{EcPemKey}" },
            new() { [EcPemKey] = EcPem() });

        await provider.GetCredentialAsync(options, secrets, Context(), default);

        var form = ParseForm(handler.Body(0)!);
        var (_, _, signature, signingInput) = ParseJwt(form["client_assertion"]);
        Assert.True(_ecdsa.VerifyData(signingInput, signature, HashAlgorithmName.SHA256));
    }

    [Fact]
    public async Task Claims_AreSetCorrectly()
    {
        var time = new FakeTimeProvider(new DateTimeOffset(2026, 10, 15, 10, 0, 0, TimeSpan.Zero));
        var (provider, _, handler) = CreateProvider(
            new StubHttpHandler(HttpStatusCode.OK, """{"access_token":"tok-1","expires_in":3600}"""), time);
        var options = AssertionOptions();
        options.Lifetime = TimeSpan.FromMinutes(5);

        await provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default);

        var form = ParseForm(handler.Body(0)!);
        var (_, payloadJson, _, _) = ParseJwt(form["client_assertion"]);
        using var payload = JsonDocument.Parse(payloadJson);
        var root = payload.RootElement;

        Assert.Equal("app-123", root.GetProperty("iss").GetString());
        Assert.Equal("installation-456", root.GetProperty("sub").GetString());
        Assert.Equal("https://github.com/login/oauth/access_token", root.GetProperty("aud").GetString());
        Assert.Equal(
            new DateTimeOffset(2026, 10, 15, 10, 0, 0, TimeSpan.Zero).ToUnixTimeSeconds(),
            root.GetProperty("iat").GetInt64());
        Assert.Equal(
            new DateTimeOffset(2026, 10, 15, 10, 5, 0, TimeSpan.Zero).ToUnixTimeSeconds(),
            root.GetProperty("exp").GetInt64());
        Assert.False(string.IsNullOrEmpty(root.GetProperty("jti").GetString()));
    }

    [Fact]
    public async Task Subject_OmittedWhenNotConfigured()
    {
        var (provider, _, handler) = CreateProvider(
            new StubHttpHandler(HttpStatusCode.OK, """{"access_token":"tok-1"}"""));
        var options = AssertionOptions();
        options.Subject = null;

        await provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default);

        var form = ParseForm(handler.Body(0)!);
        var (_, payloadJson, _, _) = ParseJwt(form["client_assertion"]);
        using var payload = JsonDocument.Parse(payloadJson);
        Assert.False(payload.RootElement.TryGetProperty("sub", out _));
    }

    [Fact]
    public async Task Jti_IsUniquePerAssertion()
    {
        var time = new FakeTimeProvider();
        var (provider, cache, handler) = CreateProvider(
            new StubHttpHandler(HttpStatusCode.OK, """{"access_token":"tok-1","expires_in":3600}"""), time);
        var secrets = Secrets(RsaPem(), EcPem());

        await provider.GetCredentialAsync(AssertionOptions(), secrets, Context(), default);
        cache.Invalidate("test", "p1");
        time.Advance(TimeSpan.FromSeconds(1));
        await provider.GetCredentialAsync(AssertionOptions(), secrets, Context(), default);

        var first = ParseJwt(ParseForm(handler.Body(0)!)["client_assertion"]);
        var second = ParseJwt(ParseForm(handler.Body(1)!)["client_assertion"]);
        string Jti((string Header, string Payload, byte[] Signature, byte[] SigningInput) jwt) =>
            JsonDocument.Parse(jwt.Payload).RootElement.GetProperty("jti").GetString()!;

        Assert.NotEqual(Jti(first), Jti(second));
    }

    [Fact]
    public async Task ClockSkew_MovesIatBackAndExpForward()
    {
        var time = new FakeTimeProvider(new DateTimeOffset(2026, 10, 15, 10, 0, 0, TimeSpan.Zero));
        var (provider, _, handler) = CreateProvider(
            new StubHttpHandler(HttpStatusCode.OK, """{"access_token":"tok-1"}"""), time);
        var options = AssertionOptions();
        options.Lifetime = TimeSpan.FromMinutes(5);
        options.ClockSkew = TimeSpan.FromSeconds(30);

        await provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default);

        var form = ParseForm(handler.Body(0)!);
        var (_, payloadJson, _, _) = ParseJwt(form["client_assertion"]);
        using var payload = JsonDocument.Parse(payloadJson);
        var baseTime = new DateTimeOffset(2026, 10, 15, 10, 0, 0, TimeSpan.Zero).ToUnixTimeSeconds();

        Assert.Equal(baseTime - 30, payload.RootElement.GetProperty("iat").GetInt64());
        Assert.Equal(baseTime + 300 + 30, payload.RootElement.GetProperty("exp").GetInt64());
    }

    [Fact]
    public async Task ClientAssertion_SendsRfc7523FormFields()
    {
        var (provider, _, handler) = CreateProvider(
            new StubHttpHandler(HttpStatusCode.OK, """{"access_token":"tok-1"}"""));
        var options = AssertionOptions();
        options.ClientId = "client-abc";
        options.Scope = "repo";

        var token = await provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default);

        Assert.Equal("tok-1", token);
        var form = ParseForm(handler.Body(0)!);
        Assert.Equal("client_credentials", form["grant_type"]);
        Assert.Equal("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", form["client_assertion_type"]);
        Assert.Equal("client-abc", form["client_id"]);
        Assert.Equal("repo", form["scope"]);
    }

    [Fact]
    public async Task JwtBearerGrant_SendsAssertionGrantForm()
    {
        var (provider, _, handler) = CreateProvider(
            new StubHttpHandler(HttpStatusCode.OK, """{"access_token":"tok-1"}"""));

        await provider.GetCredentialAsync(
            AssertionOptions(JwtAssertionExchange.JwtBearerGrant), Secrets(RsaPem(), EcPem()), Context(), default);

        var form = ParseForm(handler.Body(0)!);
        Assert.Equal("urn:ietf:params:oauth:grant-type:jwt-bearer", form["grant_type"]);
        Assert.True(form.ContainsKey("assertion"));
        Assert.False(form.ContainsKey("client_assertion"));
    }

    [Fact]
    public async Task BearerExchange_GitHubAppFlow_ObtainsInstallationToken()
    {
        var time = new FakeTimeProvider(new DateTimeOffset(2026, 10, 15, 10, 0, 0, TimeSpan.Zero));
        var (provider, _, handler) = CreateProvider(
            new StubHttpHandler(
                HttpStatusCode.Created,
                """{"token":"ghs_installation","expires_at":"2026-10-15T11:00:00Z"}"""),
            time);
        var options = AssertionOptions(JwtAssertionExchange.BearerExchange);
        options.TokenEndpoint = "https://api.github.com/app/installations/456/access_tokens";
        options.TokenField = "token";
        options.ExpiresInField = null;
        options.ExpiresAtField = "expires_at";

        var token = await provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default);

        Assert.Equal("ghs_installation", token);
        var request = Assert.Single(handler.Requests);
        Assert.Equal("Bearer", request.Headers.Authorization!.Scheme);
        var (_, payloadJson, _, _) = ParseJwt(request.Headers.Authorization.Parameter!);
        using var payload = JsonDocument.Parse(payloadJson);
        Assert.Equal("app-123", payload.RootElement.GetProperty("iss").GetString());

        // Cached until the absolute expiry: still served 30 minutes later, refetched after.
        time.Advance(TimeSpan.FromMinutes(30));
        Assert.Equal("ghs_installation", await provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default));
        Assert.Single(handler.Requests);

        time.Advance(TimeSpan.FromMinutes(31));
        await provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default);
        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task Certificate_SignsAssertionWithItsPrivateKey()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=credprox-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        var pkcs12 = Convert.ToBase64String(cert.Export(X509ContentType.Pkcs12));

        var (provider, _, handler) = CreateProvider(
            new StubHttpHandler(HttpStatusCode.OK, """{"access_token":"tok-1"}"""));
        var options = AssertionOptions();
        options.SigningKey = null;
        options.SigningCertificate = "secret:cert";

        var secrets = TestSecrets.AccessorFor(
            new() { ["SigningCertificate"] = "secret:cert" },
            new() { ["cert"] = pkcs12 });

        await provider.GetCredentialAsync(options, secrets, Context(), default);

        var form = ParseForm(handler.Body(0)!);
        var (_, _, signature, signingInput) = ParseJwt(form["client_assertion"]);
        Assert.True(rsa.VerifyData(signingInput, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    [Fact]
    public async Task TokenIsCached_PerExchangeNotPerRequest()
    {
        var time = new FakeTimeProvider();
        var (provider, _, handler) = CreateProvider(
            new StubHttpHandler(HttpStatusCode.OK, """{"access_token":"tok-1","expires_in":3600}"""), time);
        var secrets = Secrets(RsaPem(), EcPem());
        var options = AssertionOptions();

        Assert.Equal("tok-1", await provider.GetCredentialAsync(options, secrets, Context(), default));
        time.Advance(TimeSpan.FromMinutes(10));
        Assert.Equal("tok-1", await provider.GetCredentialAsync(options, secrets, Context(), default));

        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task ExchangeFailure_FailsWithoutLeakingKeyMaterial()
    {
        var (provider, _, _) = CreateProvider(new StubHttpHandler(HttpStatusCode.Unauthorized, "bad client"));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => provider
            .GetCredentialAsync(AssertionOptions(), Secrets(RsaPem(), EcPem()), Context(), default).AsTask());

        Assert.Contains("HTTP 401", ex.Message);
        Assert.DoesNotContain(RsaPem(), ex.Message);
        Assert.DoesNotContain("bad client", ex.Message);
    }

    [Fact]
    public async Task MalformedResponse_FailsWithoutLeakingBody()
    {
        var (provider, _, _) = CreateProvider(
            new StubHttpHandler(HttpStatusCode.OK, """{"unexpected":"echoed secret: csec"}"""));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => provider
            .GetCredentialAsync(AssertionOptions(), Secrets(RsaPem(), EcPem()), Context(), default).AsTask());

        Assert.Contains("malformed", ex.Message);
        Assert.DoesNotContain("echoed", ex.Message);
    }
}
