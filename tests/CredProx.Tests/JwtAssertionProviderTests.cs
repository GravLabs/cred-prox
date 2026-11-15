using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Logging;
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
        // M38: the refetch (request 2, at +61 min) must carry a LIVE absolute expiry — the
        // old fixture replayed the fixed 11:00Z value, which by then is already past and
        // correctly rejects under this milestone. Request 1 keeps the pinned literal; the
        // cache assertions below are unchanged.
        var (provider, _, handler) = CreateProvider(
            new StubHttpHandler((_, i) => new HttpResponseMessage(HttpStatusCode.Created)
            {
                Content = new StringContent(i == 0
                    ? """{"token":"ghs_installation","expires_at":"2026-10-15T11:00:00Z"}"""
                    : $$$"""{"token":"ghs_installation","expires_at":"{{{time.GetUtcNow().UtcDateTime.AddHours(1):yyyy-MM-ddTHH:mm:ssZ}}}"}"""),
            }),
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

    // --- M31 mutation triage: the argument guards and Type identity had no test;
    // the assertion header and jti format survived string mutants; the expires_in
    // comparator survived sign mutants; and every certificate-diagnosis message
    // (wrong key type, unloadable material) was never asserted. ---

    [Fact]
    public void Type_IsJwtAssertion()
    {
        var (provider, _, _) = CreateProvider(new StubHttpHandler(HttpStatusCode.OK, "{}"));

        Assert.Equal("JwtAssertion", provider.Type);
    }

    [Fact]
    public async Task NullOptions_Throws_NamingOptions()
    {
        var (provider, _, _) = CreateProvider(new StubHttpHandler(HttpStatusCode.OK, "{}"));

        var ex = await Assert.ThrowsAsync<ArgumentNullException>(() =>
            provider.GetCredentialAsync(null!, Secrets(RsaPem(), EcPem()), Context(), default).AsTask());

        Assert.Equal("options", ex.ParamName);
    }

    [Fact]
    public async Task NullSecrets_Throws_NamingSecrets()
    {
        var (provider, _, _) = CreateProvider(new StubHttpHandler(HttpStatusCode.OK, "{}"));

        var ex = await Assert.ThrowsAsync<ArgumentNullException>(() =>
            provider.GetCredentialAsync(AssertionOptions(), null!, Context(), default).AsTask());

        Assert.Equal("secrets", ex.ParamName);
    }

    [Fact]
    public async Task NullContext_Throws_NamingContext()
    {
        var (provider, _, _) = CreateProvider(new StubHttpHandler(HttpStatusCode.OK, "{}"));

        var ex = await Assert.ThrowsAsync<ArgumentNullException>(() =>
            provider.GetCredentialAsync(AssertionOptions(), Secrets(RsaPem(), EcPem()), null!, default).AsTask());

        Assert.Equal("context", ex.ParamName);
    }

    [Fact]
    public async Task EmptySigningMaterial_FailsBeforeAnyRequest()
    {
        var (provider, _, handler) = CreateProvider(new StubHttpHandler(HttpStatusCode.OK, "{}"));

        var options = AssertionOptions();
        options.SigningKey = string.Empty;

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default).AsTask());

        Assert.Contains("signing key does not resolve", ex.Message, StringComparison.Ordinal);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task MintedAssertion_HeaderNamesAlgorithmAndType_JtiIsUndashedGuid()
    {
        var (provider, _, handler) = CreateProvider(
            new StubHttpHandler(HttpStatusCode.OK, """{"access_token":"tok"}"""));

        await provider.GetCredentialAsync(AssertionOptions(), Secrets(RsaPem(), EcPem()), Context(), default);

        var form = ParseForm(handler.Body(0)!);
        var (header, payload, _, _) = ParseJwt(form["client_assertion"]);
        using var headerJson = JsonDocument.Parse(header);
        Assert.Equal("RS256", headerJson.RootElement.GetProperty("alg").GetString());
        Assert.Equal("JWT", headerJson.RootElement.GetProperty("typ").GetString());
        using var payloadJson = JsonDocument.Parse(payload);
        Assert.Matches("^[0-9a-f]{32}$", payloadJson.RootElement.GetProperty("jti").GetString());
    }

    [Fact]
    public async Task EmptyIssuer_FailsNamingMissingRequiredValue()
    {
        var (provider, _, handler) = CreateProvider(new StubHttpHandler(HttpStatusCode.OK, "{}"));

        var options = AssertionOptions();
        options.Issuer = string.Empty;

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default).AsTask());

        Assert.Contains("missing a required value", ex.Message, StringComparison.Ordinal);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task UnsupportedAlgorithmValue_FailsNamingIt()
    {
        // Same undefined-enum-number shape as the validator's Mode guard (M27 review N1),
        // reachable when options are constructed in code.
        var (provider, _, _) = CreateProvider(new StubHttpHandler(HttpStatusCode.OK, "{}"));

        var options = AssertionOptions();
        options.Algorithm = (JwtAssertionAlgorithm)99;

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default).AsTask());

        Assert.Contains("Unsupported JWT assertion algorithm '99'", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ExpiresIn_Zero_IgnoresVendorValue_KeepsDefaultLifetime()
    {
        // expires_in 0 must fall back to DefaultLifetime (the > 0 bound in TryReadSeconds):
        // a token 'expiring' at mint would make every proxied call re-mint. A mutant
        // accepting 0 refetches immediately and shows two vendor calls.
        var (provider, _, handler) = CreateProvider(
            new StubHttpHandler(HttpStatusCode.OK, """{"access_token":"tok","expires_in":0}"""));

        await provider.GetCredentialAsync(AssertionOptions(), Secrets(RsaPem(), EcPem()), Context(), default);
        await provider.GetCredentialAsync(AssertionOptions(), Secrets(RsaPem(), EcPem()), Context(), default);

        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task ExpiresIn_BeyondDefaultLifetime_ExtendsTheCacheWindow()
    {
        // The sign mutant ('seconds < 0') discards the vendor's 7200 and stores the
        // 1 h default: its token hits the 80 % refresh point at 48 min. The real
        // token lasts 2 h (refresh at 96 min), so at 55 min exactly one fetch happened.
        var time = new FakeTimeProvider();
        var (provider, _, handler) = CreateProvider(
            new StubHttpHandler(HttpStatusCode.OK, """{"access_token":"tok","expires_in":7200}"""), time);

        await provider.GetCredentialAsync(AssertionOptions(), Secrets(RsaPem(), EcPem()), Context(), default);
        time.Advance(TimeSpan.FromMinutes(55));
        await provider.GetCredentialAsync(AssertionOptions(), Secrets(RsaPem(), EcPem()), Context(), default);

        Assert.Single(handler.Requests);
    }

    private static string PfxBase64For(RSA rsa) =>
        PfxBase64(new CertificateRequest(
            new X500DistinguishedName("CN=credprox-test"), rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));

    private static string PfxBase64For(ECDsa ecdsa) =>
        PfxBase64(new CertificateRequest(new X500DistinguishedName("CN=credprox-test"), ecdsa, HashAlgorithmName.SHA256));

    private static string PfxBase64(CertificateRequest request)
    {
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        return Convert.ToBase64String(cert.Export(X509ContentType.Pfx));
    }

    [Fact]
    public async Task RsaAlgorithmWithEcdsaCertificate_FailsNamingMissingRsaKey()
    {
        var (provider, _, _) = CreateProvider(new StubHttpHandler(HttpStatusCode.OK, "{}"));

        var options = AssertionOptions();
        options.SigningKey = null;
        options.SigningCertificate = PfxBase64For(_ecdsa);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default).AsTask());

        Assert.Contains("The signing certificate has no RSA private key", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task EcdsaAlgorithmWithRsaCertificate_FailsNamingMissingEcdsaKey()
    {
        // The :314 conditional mutant routes certificate material through the plain
        // PEM import instead: it cannot load a PKCS #12 blob and dies with a raw
        // cryptographic error instead of this diagnosis.
        var (provider, _, _) = CreateProvider(new StubHttpHandler(HttpStatusCode.OK, "{}"));

        var options = AssertionOptions();
        options.Algorithm = JwtAssertionAlgorithm.ES256;
        options.SigningKey = null;
        options.SigningCertificate = PfxBase64For(_rsa);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default).AsTask());

        Assert.Contains("The signing certificate has no ECDSA private key", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CertificateMaterial_ValidBase64ButGarbage_FailsAsCouldNotBeLoaded()
    {
        var (provider, _, _) = CreateProvider(new StubHttpHandler(HttpStatusCode.OK, "{}"));

        var options = AssertionOptions();
        options.SigningKey = null;
        options.SigningCertificate = Convert.ToBase64String([1, 2, 3, 4, 5, 6, 7, 8]);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default).AsTask());

        Assert.Contains("The signing certificate could not be loaded", ex.Message, StringComparison.Ordinal);
        Assert.IsAssignableFrom<CryptographicException>(ex.InnerException);
    }

    [Fact]
    public async Task CertificateMaterial_NotBase64AtAll_FailsAsCouldNotBeLoaded()
    {
        // M31 triage fix: the FormatException from the Base-64 decode is wrapped like
        // every other unloadable-material shape, never surfaced raw.
        var (provider, _, _) = CreateProvider(new StubHttpHandler(HttpStatusCode.OK, "{}"));

        var options = AssertionOptions();
        options.SigningKey = null;
        options.SigningCertificate = "not base64 at all!!";

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default).AsTask());

        Assert.Contains("The signing certificate could not be loaded", ex.Message, StringComparison.Ordinal);
        Assert.IsAssignableFrom<FormatException>(ex.InnerException);
    }

    // ---- M37 fold 2 (hardening review F1 + fold rulings): the
    // expires_in parse is culture-invariant, and a NEGATIVE value is unusable - expires_at
    // keeps precedence when valid, and only a negative with nothing usable left rejects
    // (M33 fault 7 mirrored from OAuth, nothing cached). ZERO keeps the fallback in every
    // case: valid expires_at first, else DefaultLifetime (ExpiresIn_Zero_... pins the
    // no-ExpiresAtField shape). M37 kept non-finite/grouped/non-numeric on the fallback;
    // M38 A moved non-finite and grouped to reject (defer-then-reject, precedence intact —
    // see the M38 section and the changed grouped pin), M38 B extends this to non-numeric.
    // Tests compile against f34b86e; the RED run is behaviour.

    [Fact]
    public async Task ExpiresIn_DecimalCommaCulture_ParsesDotAsDecimal()
    {
        using var _culture = new CultureOverride("de-DE");
        var time = new FakeTimeProvider();
        var (provider, _, handler) = CreateProvider(
            new StubHttpHandler(HttpStatusCode.OK, """{"access_token":"tok-1","expires_in":"3600.9"}"""), time);

        await provider.GetCredentialAsync(AssertionOptions(), Secrets(RsaPem(), EcPem()), Context(), default);
        time.Advance(TimeSpan.FromMinutes(50)); // past 80 % of 3600.9 s; a 1 h default would still be cached
        await provider.GetCredentialAsync(AssertionOptions(), Secrets(RsaPem(), EcPem()), Context(), default);

        // RED at f34b86e: de-DE reads "3600.9" as 36 009 s - still cached at 50 min.
        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task ExpiresIn_DecimalCommaCulture_GroupedValueRejects()
    {
        // M38 A CHANGED this pin (it asserted "grouped keeps DefaultLifetime"): the grouped value
        // is a protocol violation now (no ExpiresAtField configured, so nothing usable remains)
        // and rejects on every culture. The M37 fold-2 culture-invariance intent stands: the
        // cached lifetime never depends on the machine's culture.
        using var _culture = new CultureOverride("de-DE");
        var time = new FakeTimeProvider();
        var (provider, _, handler) = CreateProvider(
            new StubHttpHandler(HttpStatusCode.OK, """{"access_token":"tok-1","expires_in":"1,000"}"""), time);

        var ex = await Record.ExceptionAsync(() =>
            provider.GetCredentialAsync(AssertionOptions(), Secrets(RsaPem(), EcPem()), Context(), default).AsTask());
        Assert.NotNull(ex);
        Assert.IsAssignableFrom<InvalidOperationException>(ex);
        Assert.IsNotType<InvalidOperationException>(ex);
        Assert.Contains("expires_in", ex.Message);
        Assert.DoesNotContain("1,000", ex.Message);
        Assert.DoesNotContain("malformed", ex.Message);
        Assert.Single(handler.Requests);                    // rejected, nothing cached
    }

    [Fact]
    public async Task ExpiresIn_Negative_NoExpiresAt_RejectsResponse_CachesNothing()
    {
        var time = new FakeTimeProvider();
        var (provider, _, handler) = CreateProvider(
            new StubHttpHandler(HttpStatusCode.OK, """{"access_token":"tok-1","expires_in":-30}"""), time);

        var ex = await Record.ExceptionAsync(() =>
            provider.GetCredentialAsync(AssertionOptions(), Secrets(RsaPem(), EcPem()), Context(), default).AsTask());
        Assert.NotNull(ex);                                 // RED at f34b86e: cached for DefaultLifetime there
        Assert.IsAssignableFrom<InvalidOperationException>(ex); // the documented IdP-failure type
        Assert.IsNotType<InvalidOperationException>(ex);    // a specific rejection, not the re-wrap
        Assert.Contains("expires_in", ex.Message);          // names the field...
        Assert.Contains("test", ex.Message);                // ...and the credential id...
        Assert.DoesNotContain("tok-1", ex.Message);         // ...never the token or the value.
        Assert.DoesNotContain("-30", ex.Message);
        Assert.DoesNotContain("malformed", ex.Message);
        Assert.Single(handler.Requests);

        Assert.NotNull(await Record.ExceptionAsync(() =>
            provider.GetCredentialAsync(AssertionOptions(), Secrets(RsaPem(), EcPem()), Context(), default).AsTask()));
        Assert.Single(handler.Requests);                    // backoff re-throw: nothing was cached

        time.Advance(TimeSpan.FromSeconds(6));              // past NegativeCacheTtl
        Assert.NotNull(await Record.ExceptionAsync(() =>
            provider.GetCredentialAsync(AssertionOptions(), Secrets(RsaPem(), EcPem()), Context(), default).AsTask()));
        Assert.Equal(2, handler.Requests.Count);            // re-mints once the backoff lapses
    }

    [Fact]
    public async Task ExpiresIn_Negative_ValidExpiresAt_UsesAbsoluteExpiry()
    {
        // Ruling 02:19Z: a negative expires_in is UNUSABLE, not an instant throw - the
        // ExpiresAtField branch (JwtAssertionProvider.cs:156-169 chain) wins when configured
        // and valid; rejection fires only when no usable expires_at exists. This pins the
        // precedence (nothing pinned it at f34b86e; GREEN on both trees by design).
        var time = new FakeTimeProvider();
        var absolute = time.GetUtcNow().UtcDateTime.AddHours(2).ToString("O");
        var (provider, _, handler) = CreateProvider(new StubHttpHandler(
            HttpStatusCode.OK,
            $$"""{"access_token":"tok-1","expires_in":-1,"expires_at":"{{absolute}}"}"""), time);
        var options = AssertionOptions();
        options.ExpiresAtField = "expires_at";

        await provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default);
        time.Advance(TimeSpan.FromMinutes(55)); // 80 % of 2 h is 96 min; a 1 h DefaultLifetime would be refreshing
        await provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default);

        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task ExpiresIn_Zero_ValidExpiresAt_UsesAbsoluteExpiry()
    {
        // Ruling 02:20Z precision: ZERO is its own branch and unchanged in every case -
        // it falls through to a valid expires_at exactly as at f34b86e (GREEN both trees).
        var time = new FakeTimeProvider();
        var absolute = time.GetUtcNow().UtcDateTime.AddHours(2).ToString("O");
        var (provider, _, handler) = CreateProvider(new StubHttpHandler(
            HttpStatusCode.OK,
            $$"""{"access_token":"tok-1","expires_in":0,"expires_at":"{{absolute}}"}"""), time);
        var options = AssertionOptions();
        options.ExpiresAtField = "expires_at";

        await provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default);
        time.Advance(TimeSpan.FromMinutes(55));
        await provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default);

        Assert.Single(handler.Requests);
    }

    // ---- M38 (plan §8.6 policy row). A + B: non-finite, grouped and
    // non-numeric `expires_in` reject like OAuth when nothing usable remains, but the M37 precedence
    // stands: an unusable expires_in still gives way to a valid expires_at. C: the 24 h cap clamps
    // accepted lifetimes, including TimeSpan-overflow values (1e12/1e300) that today die in the
    // generic malformed re-wrap via the OverflowException catch-all at JwtAssertionProvider.cs:192.
    // D: `expires_at` parses InvariantCulture + AssumeUniversal (offset-less = UTC), accepts a JSON
    // number as epoch seconds, and an unparseable value falls back with a warning (the warning
    // assertion rides the GREEN logger seam; it cannot compile at 3b2d758 — noted per M37 fold 2).
    // Tests compile at 3b2d758 and assert base types / observable caching only. Host note for the
    // UTC pin: this machine is EST-0500 (date +%z -0500), so the local-vs-UTC difference is real.

    [Theory]
    [InlineData("1e400")]         // +∞ via JSON number (culture-independent, M37 matrix)
    [InlineData("\"Infinity\"")]
    [InlineData("\"1,000\"")]     // grouped: OAuth's M37 A1 rejection now applies here too
    [InlineData("\"abc\"")]       // B: non-numeric
    [InlineData("\"0x10\"")]
    [InlineData("\"١٢٣\"")]
    public async Task M38_UnusableExpiresIn_NoExpiryLeft_RejectsResponse_CachesNothing(string json)
    {
        // A/B with no ExpiresAtField configured: nothing usable remains, so the response rejects
        // on the IdP-failure path. RED at 3b2d758: every row fell through TryReadSeconds to a
        // silent DefaultLifetime (and never mentions "malformed" — the exclusion must hold).
        var time = new FakeTimeProvider();
        var (provider, _, handler) = CreateProvider(
            new StubHttpHandler(HttpStatusCode.OK, $$"""{"access_token":"tok-1","expires_in":{{json}}}"""), time);

        var ex = await Record.ExceptionAsync(() =>
            provider.GetCredentialAsync(AssertionOptions(), Secrets(RsaPem(), EcPem()), Context(), default).AsTask());
        Assert.NotNull(ex);                                 // RED at 3b2d758: silently cached DefaultLifetime
        Assert.IsAssignableFrom<InvalidOperationException>(ex); // the documented IdP-failure type
        Assert.IsNotType<InvalidOperationException>(ex);    // a specific rejection, not the re-wrap
        Assert.Contains("expires_in", ex.Message);          // names the field...
        Assert.Contains("test", ex.Message);                // ...and the credential id...
        Assert.DoesNotContain("tok-1", ex.Message);         // ...never the token or the value.
        Assert.DoesNotContain("Infinity", ex.Message);
        Assert.DoesNotContain("1e400", ex.Message);
        Assert.DoesNotContain("1,000", ex.Message);
        Assert.DoesNotContain("malformed", ex.Message);     // not swallowed by the malformed re-wrap
        Assert.Single(handler.Requests);

        Assert.NotNull(await Record.ExceptionAsync(() =>
            provider.GetCredentialAsync(AssertionOptions(), Secrets(RsaPem(), EcPem()), Context(), default).AsTask()));
        Assert.Single(handler.Requests);                    // backoff re-throw: nothing was cached

        time.Advance(TimeSpan.FromSeconds(6));              // past NegativeCacheTtl
        Assert.NotNull(await Record.ExceptionAsync(() =>
            provider.GetCredentialAsync(AssertionOptions(), Secrets(RsaPem(), EcPem()), Context(), default).AsTask()));
        Assert.Equal(2, handler.Requests.Count);            // re-mints once the backoff lapses
    }

    [Theory]
    [InlineData("1e400")]
    [InlineData("\"1,000\"")]
    [InlineData("\"abc\"")]
    public async Task M38_UnusableExpiresIn_ValidExpiresAt_KeepsPrecedence(string json)
    {
        // A's boundary (M37 precedence preserved): an unusable expires_in gives way to a valid
        // expires_at and must NOT reject. GREEN at 3b2d758 by design (the M37 fold-2 chain already
        // falls through) — this pins that the M38 rejection does not steal precedence from it.
        var time = new FakeTimeProvider();
        var absolute = time.GetUtcNow().UtcDateTime.AddHours(2).ToString("O");
        var (provider, _, handler) = CreateProvider(new StubHttpHandler(
            HttpStatusCode.OK,
            $$"""{"access_token":"tok-1","expires_in":{{json}},"expires_at":"{{absolute}}"}"""), time);
        var options = AssertionOptions();
        options.ExpiresAtField = "expires_at";

        await provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default);
        time.Advance(TimeSpan.FromMinutes(55));             // 80 % of 2 h is 96 min; the 1 h default would refresh
        await provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default);

        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task M38_LifetimeAboveOneDay_ClampedTo24h()
    {
        // C: 48 h clamps to 24 h — refresh lands at 80 % of 24 h (19.2 h).
        // RED at 3b2d758: 48 h caches uncapped and is still served at +20 h.
        var time = new FakeTimeProvider();
        var (provider, _, handler) = CreateProvider(
            new StubHttpHandler(HttpStatusCode.OK, """{"access_token":"tok-1","expires_in":172800}"""), time);

        await provider.GetCredentialAsync(AssertionOptions(), Secrets(RsaPem(), EcPem()), Context(), default);
        time.Advance(TimeSpan.FromHours(20));               // past 80 % of 24 h, below 80 % of 48 h
        await provider.GetCredentialAsync(AssertionOptions(), Secrets(RsaPem(), EcPem()), Context(), default);

        Assert.Equal(2, handler.Requests.Count);
    }

    [Theory]
    [InlineData("1e12")]   // 1e12 s = 1e19 ticks > TimeSpan.MaxTicks: OverflowException today
    [InlineData("1e300")]
    public async Task M38_TimeSpanOverflow_ClampedNotMalformed(string json)
    {
        // C: the JwtAssertionProvider.cs:171 FromSeconds(seconds) overflow must clamp, not die in
        // the :192 generic malformed re-wrap. RED at 3b2d758: the await throws that re-wrap.
        var time = new FakeTimeProvider();
        var (provider, _, handler) = CreateProvider(
            new StubHttpHandler(HttpStatusCode.OK, $$"""{"access_token":"tok-1","expires_in":{{json}}}"""), time);

        Assert.Equal("tok-1", await provider
            .GetCredentialAsync(AssertionOptions(), Secrets(RsaPem(), EcPem()), Context(), default));
        time.Advance(TimeSpan.FromHours(20));               // past the clamped 80 % point
        Assert.Equal("tok-1", await provider
            .GetCredentialAsync(AssertionOptions(), Secrets(RsaPem(), EcPem()), Context(), default));

        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task M38_ExpiresAt_HostCultureFormat_UnparseableFallsBackToDefault()
    {
        // D: expires_at parses with CultureInfo.InvariantCulture — the de-DE dotted date that the
        // base DateTimeOffset.TryParse(string) (current culture) accepts is UNPARSEABLE under the
        // new rule and must fall back to DefaultLifetime. RED at 3b2d758: de-DE parsed it (year
        // 2026 vs the fake clock's 2000 — a ~26-year cache) so the token is still cached at
        // +50 min. The once-per-credential warning (battery note: "asserted once the logger seam
        // exists") is asserted here now that outcome B added the seam.
        using var _culture = new CultureOverride("de-DE");
        var time = new FakeTimeProvider();
        var handler = new StubHttpHandler(
            HttpStatusCode.OK, """{"access_token":"tok-1","expires_at":"15.11.2026 22:00:00"}""");
        var logger = new CollectingLogger();
        var cache = new InMemoryTokenCache(Options.Create(new TokenCacheOptions()), time);
        var provider = new JwtAssertionProvider(cache, new StubHttpClientFactory(handler), time, logger);
        var options = AssertionOptions();
        options.ExpiresAtField = "expires_at";

        await provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default);
        time.Advance(TimeSpan.FromMinutes(50));             // past 80 % of the 1 h default
        await provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default);

        Assert.Equal(2, handler.Requests.Count);            // fallback clock, not the far-future parse
        Assert.Single(logger.Messages, static m => m.Contains("expires_at"));   // one notice, twice fell back
        Assert.DoesNotContain("15.11.2026", logger.Messages.Single(m => m.Contains("expires_at")));
    }

    [Fact]
    public async Task M38_ExpiresAt_EpochNumber_IsUsed()
    {
        // D: a JSON-number expires_at is epoch seconds and must be used. RED at 3b2d758: the
        // String-only branch skips it silently, so the 1 h default refreshes at 48 min (< +55).
        var time = new FakeTimeProvider();
        var epoch = time.GetUtcNow().ToUnixTimeSeconds() + 7200; // now + 2 h
        var (provider, _, handler) = CreateProvider(new StubHttpHandler(
            HttpStatusCode.OK,
            $$"""{"access_token":"tok-1","expires_at":{{epoch}}}"""), time);
        var options = AssertionOptions();
        options.ExpiresAtField = "expires_at";

        await provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default);
        time.Advance(TimeSpan.FromMinutes(55));             // past 80 % of 1 h, below 80 % of 2 h
        await provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default);

        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task M38_ExpiresAt_Offsetless_IsUtc()
    {
        // D: AssumeUniversal — an offset-less value is UTC, not host-local. RED at 3b2d758 on this
        // host (TZ EST-0500): the base reads 07:00 as 12:00 UTC → a 12 h lifetime, still cached at
        // +6 h. GREEN: 07:00 UTC → 7 h → refresh at 80 % = 5.6 h → re-mint. (On a UTC host base and
        // new agree; the rule is pinned, the host is not — M37 fold-2 precedent, noted.)
        var time = new FakeTimeProvider();                  // fake clock: 2000-01-01T00:00:00Z
        var (provider, _, handler) = CreateProvider(
            new StubHttpHandler(HttpStatusCode.OK, """{"access_token":"tok-1","expires_at":"2000-01-01T07:00:00"}"""), time);
        var options = AssertionOptions();
        options.ExpiresAtField = "expires_at";

        await provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default);
        time.Advance(TimeSpan.FromHours(6));                // past 80 % of 7 h (UTC), below 80 % of 12 h (local EST)
        await provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default);

        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task M38_EmptyStringExpiresIn_FallsBackWithOneWarning()
    {
        // B boundary: "" is present-but-empty = absent — the M37 chain falls through it (it
        // sets neither rejection flag) to DefaultLifetime WITH one warning per credential
        // (two mints here via the 80 % refresh, one notice total — the OAuth zero-lifetime
        // rule mirrored). Added WITH outcome B: the warning needs the additive 4-arg logger
        // ctor, so this pin cannot compile at 3b2d758 (M37 fold-2 precedent — base-
        // incompatible warning pins, noted on the row).
        var time = new FakeTimeProvider();
        var handler = new StubHttpHandler(
            HttpStatusCode.OK, """{"access_token":"tok-1","expires_in":""}""");
        var logger = new CollectingLogger();
        var cache = new InMemoryTokenCache(Options.Create(new TokenCacheOptions()), time);
        var provider = new JwtAssertionProvider(cache, new StubHttpClientFactory(handler), time, logger);
        var options = AssertionOptions();

        Assert.Equal("tok-1", await provider
            .GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default));
        time.Advance(TimeSpan.FromMinutes(50));             // past 80 % of the 1 h default -> second mint
        Assert.Equal("tok-1", await provider
            .GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default));
        Assert.Equal(2, handler.Requests.Count);            // the fallback clock, twice

        Assert.Single(logger.Messages, static m => m.Contains("expires_in")); // one notice across mints
        Assert.DoesNotContain("tok-1", logger.Messages.Single(m => m.Contains("expires_in")));
    }

    [Fact]
    public async Task M38_ValidExpiresAt_FarFuture_ClampedTo24h()
    {
        // C's other half (the cap rides after the precedence): a far-future
        // expires_at lifetime clamps to now + 24 h, so the refresh lands at 80 % of 24 h
        // (19.2 h), not 80 % of 30 days. RED at 3b2d758: the absolute expiry is cached as-is
        // and the token is still served at +20 h. Compiles at base; added with the C outcome
        // because C is what makes it green (same notice-on-the-row shape as the deferred pins).
        var time = new FakeTimeProvider();
        var absolute = time.GetUtcNow().UtcDateTime.AddDays(30).ToString("O");
        var (provider, _, handler) = CreateProvider(new StubHttpHandler(
            HttpStatusCode.OK,
            $$"""{"access_token":"tok-1","expires_at":"{{absolute}}"}"""), time);
        var options = AssertionOptions();
        options.ExpiresAtField = "expires_at";

        await provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default);
        time.Advance(TimeSpan.FromHours(20));               // past 80 % of the capped 24 h
        await provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default);

        Assert.Equal(2, handler.Requests.Count);
    }

    // ---- M38: an absolute expiry at or before now (ISO or epoch, epoch 0 and exactly-now
    // included) is UNUSABLE — the same class as a negative expires_in (M33 fault 7: never act
    // on a token whose stated expiry is already dead). When it is the only stated expiry left,
    // the response rejects through the protocol-violation path: nothing cached, the message
    // names the field and the credential id only. Precedence as shipped: a usable expires_in
    // wins. Before M38 the past value was cached as-is: Serve never returns it, so every later
    // call re-minted with zero log messages, and the epoch-lower-bound row instead threw
    // ArgumentOutOfRangeException from the cache's refresh arithmetic, outside the documented
    // 502 contract (pinned independently in InMemoryTokenCacheTests).

    [Theory]
    [InlineData("\"1999-06-01T00:00:00Z\"")]   // ISO, clearly past vs the 2000-01-01T00:00:00Z clock
    [InlineData("0")]                          // epoch 0 — the classic "present but never set" stub bug
    [InlineData("-62135596800")]               // epoch guard's lower bound (year 1) — the cache floor re-pins this in InMemoryTokenCacheTests
    [InlineData("-1")]                         // pre-epoch epoch seconds
    public async Task M38F1_PastExpiresAt_RejectsResponse_CachesNothing(string json)
    {
        var time = new FakeTimeProvider();
        var (provider, _, handler) = CreateProvider(
            new StubHttpHandler(HttpStatusCode.OK, $$"""{"access_token":"tok-1","expires_at":{{json}}}"""), time);
        var options = AssertionOptions();
        options.ExpiresAtField = "expires_at";

        var ex = await Record.ExceptionAsync(() =>
            provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default).AsTask());
        Assert.NotNull(ex);                                 // RED at 3dc04ae: cached (or crashed, year 1)
        Assert.IsAssignableFrom<InvalidOperationException>(ex); // the documented IdP-failure path
        Assert.IsNotType<InvalidOperationException>(ex);    // a specific rejection, not the re-wrap
        Assert.Contains("expires_at", ex.Message);          // names the field...
        Assert.Contains("test", ex.Message);                // ...and the credential id...
        Assert.DoesNotContain("tok-1", ex.Message);         // ...never the token or the value.
        Assert.DoesNotContain("1999", ex.Message);
        Assert.DoesNotContain("62135596800", ex.Message);
        Assert.DoesNotContain("malformed", ex.Message);     // not swallowed by the malformed re-wrap
        Assert.Single(handler.Requests);

        Assert.NotNull(await Record.ExceptionAsync(() =>
            provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default).AsTask()));
        Assert.Single(handler.Requests);                    // backoff re-throw: nothing was cached

        time.Advance(TimeSpan.FromSeconds(6));              // past NegativeCacheTtl
        Assert.NotNull(await Record.ExceptionAsync(() =>
            provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default).AsTask()));
        Assert.Equal(2, handler.Requests.Count);            // re-mints once the backoff lapses
    }

    [Fact]
    public async Task M38F1_ExpiresAtExactlyNow_RejectsResponse()
    {
        // "exactly now" is already dead: absolute <= now is unusable (architect ruling).
        var time = new FakeTimeProvider();                  // fake clock: 2000-01-01T00:00:00Z
        var (provider, _, handler) = CreateProvider(new StubHttpHandler(
            HttpStatusCode.OK, """{"access_token":"tok-1","expires_at":"2000-01-01T00:00:00Z"}"""), time);
        var options = AssertionOptions();
        options.ExpiresAtField = "expires_at";

        var ex = await Record.ExceptionAsync(() =>
            provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default).AsTask());
        Assert.NotNull(ex);                                 // RED at 3dc04ae: cached as-is
        Assert.IsAssignableFrom<InvalidOperationException>(ex);
        Assert.IsNotType<InvalidOperationException>(ex);
        Assert.Contains("expires_at", ex.Message);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task M38F1_ExpiresAtOneSecondBeforeNow_RejectsResponse()
    {
        var time = new FakeTimeProvider();
        var epoch = time.GetUtcNow().ToUnixTimeSeconds() - 1;
        var (provider, _, handler) = CreateProvider(new StubHttpHandler(
            HttpStatusCode.OK, $$"""{"access_token":"tok-1","expires_at":{{epoch}}}"""), time);
        var options = AssertionOptions();
        options.ExpiresAtField = "expires_at";

        var ex = await Record.ExceptionAsync(() =>
            provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default).AsTask());
        Assert.NotNull(ex);
        Assert.IsAssignableFrom<InvalidOperationException>(ex);
        Assert.IsNotType<InvalidOperationException>(ex);
        Assert.Contains("expires_at", ex.Message);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task M38F1_ValidExpiresIn_PastExpiresAt_KeepsPrecedence()
    {
        // GREEN at 3dc04ae by design — a pin that the new reject must NOT steal precedence from a
        // usable expires_in (same guard shape as M38_UnusableExpiresIn_ValidExpiresAt_KeepsPrecedence).
        var time = new FakeTimeProvider();
        var (provider, _, handler) = CreateProvider(new StubHttpHandler(
            HttpStatusCode.OK,
            """{"access_token":"tok-1","expires_in":7200,"expires_at":"1999-06-01T00:00:00Z"}"""), time);
        var options = AssertionOptions();
        options.ExpiresAtField = "expires_at";

        Assert.Equal("tok-1", await provider
            .GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default));
        time.Advance(TimeSpan.FromMinutes(55));             // 80 % of 2 h is 96 min; the 1 h default would refresh
        Assert.Equal("tok-1", await provider
            .GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default));

        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task M38F1_ZeroExpiresIn_PastExpiresAt_Rejects()
    {
        // The row's explicit case: zero expires_in is not a fault, but it leaves the past
        // expires_at as the only stated expiry — and that one is dead, so reject, not DefaultLifetime.
        var time = new FakeTimeProvider();
        var (provider, _, handler) = CreateProvider(new StubHttpHandler(
            HttpStatusCode.OK, """{"access_token":"tok-1","expires_in":0,"expires_at":"1999-06-01T00:00:00Z"}"""), time);
        var options = AssertionOptions();
        options.ExpiresAtField = "expires_at";

        var ex = await Record.ExceptionAsync(() =>
            provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default).AsTask());
        Assert.NotNull(ex);                                 // RED at 3dc04ae: silent DefaultLifetime
        Assert.IsAssignableFrom<InvalidOperationException>(ex);
        Assert.IsNotType<InvalidOperationException>(ex);
        Assert.Contains("expires_at", ex.Message);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task M38F1_PastExpiresAt_SingleFlight_ThenCleanRetryAfterNegativeCacheTtl()
    {
        // The rejection path keeps the cache contract: 4 concurrent waiters share ONE vendor
        // request and fault identically; the failure is negative-cached (no new request inside the
        // window); after the TTL a fixed vendor mints clean (nothing poisoned).
        var time = new FakeTimeProvider();
        var handler = new StubHttpHandler((_, i) => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(i == 0
                ? """{"access_token":"tok-1","expires_at":"1999-06-01T00:00:00Z"}"""
                : """{"access_token":"tok-2","expires_in":3600}"""),
        });
        var (provider, _, _) = CreateProvider(handler, time);
        var options = AssertionOptions();
        options.ExpiresAtField = "expires_at";

        var waiters = Enumerable.Range(0, 4).Select(_ =>
            provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default).AsTask()).ToArray();
        var faults = await Task.WhenAll(waiters.Select(async t => await Record.ExceptionAsync(() => t)));
        Assert.All(faults, Assert.NotNull);
        Assert.All(faults, static ex => Assert.Contains("expires_at", ex!.Message));
        Assert.Single(handler.Requests);                    // one shared fetch for four waiters

        Assert.NotNull(await Record.ExceptionAsync(() =>
            provider.GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default).AsTask()));
        Assert.Single(handler.Requests);                    // negative cache re-throw

        time.Advance(TimeSpan.FromSeconds(6));              // past NegativeCacheTtl
        Assert.Equal("tok-2", await provider
            .GetCredentialAsync(options, Secrets(RsaPem(), EcPem()), Context(), default));
        Assert.Equal(2, handler.Requests.Count);            // clean mint after the TTL
    }

    private sealed class CollectingLogger : ILogger<JwtAssertionProvider>
    {
        public List<string> Messages { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) => Messages.Add(formatter(state, exception));
    }
}
