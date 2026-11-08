using System.Net;
using System.Security.Cryptography;
using System.Text;
using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage for <see cref="TokenExchangeProvider"> (direct-JWKS mode): the
/// ctor guards, the rotation eviction rule (evict on key-not-found only — never on an
/// expired or forged token), rejection messages that name the credential, the exact
/// Basic-auth pair, and every <c>expires_in</c> shape against the default lifetime.
/// </summary>
public sealed class TokenExchangeProviderM31Tests
{
    private const string Issuer = "https://idp.example";
    private const string Audience = "credprox-api";
    private const string JwksUrl = "https://idp.example/jwks";
    private const string TokenUrl = "https://idp.example/token";

    private static readonly RSA IssuerRsa = RSA.Create(2048);
    private static readonly RSA OtherRsa = RSA.Create(2048);

    private static string JwksWith(params (string Kid, RSA Key)[] keys)
    {
        static string B64Url(byte[] bytes) =>
            Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var entries = keys.Select(k =>
        {
            var p = k.Key.ExportParameters(false);
            return new { kty = "RSA", use = "sig", alg = "RS256", kid = k.Kid, n = B64Url(p.Modulus!), e = B64Url(p.Exponent!) };
        }).ToArray();
        return System.Text.Json.JsonSerializer.Serialize(new { keys = entries });
    }

    private static string IssueToken(
        RSA signingKey,
        string? subject = "user-A",
        string audience = Audience,
        string issuer = Issuer,
        TimeSpan? lifetime = null,
        DateTimeOffset? now = null,
        bool sign = true)
    {
        var start = now ?? DateTimeOffset.UtcNow;
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            NotBefore = start.AddMinutes(-1).UtcDateTime,
            Expires = start.Add(lifetime ?? TimeSpan.FromMinutes(5)).UtcDateTime,
        };
        if (sign)
        {
            descriptor.SigningCredentials = new SigningCredentials(new RsaSecurityKey(signingKey), SecurityAlgorithms.RsaSha256);
        }

        if (subject is not null)
        {
            descriptor.Claims = new Dictionary<string, object> { ["sub"] = subject };
        }

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    private static TokenExchangeOptions Options_direct(TokenExchangeMode mode = TokenExchangeMode.Rfc8693) => new()
    {
        Mode = mode,
        Issuer = Issuer,
        JwksUri = JwksUrl,
        Audience = Audience,
        TokenEndpoint = TokenUrl,
        ClientId = "cid",
        ClientSecret = "csec",
    };

    private static CredentialRequestContext Ctx(string inbound) =>
        new() { CredentialName = "test", Partition = "p1", InboundToken = inbound };

    private static (TokenExchangeProvider Provider, StubHttpHandler Handler, FakeTimeProvider Time) Create(
        Func<HttpRequestMessage, int, HttpResponseMessage> responder)
    {
        var handler = new StubHttpHandler(responder);
        var time = new FakeTimeProvider();
        var cache = new InMemoryTokenCache(Options.Create(new TokenCacheOptions()), time);
        return (new TokenExchangeProvider(cache, new StubHttpClientFactory(handler), time), handler, time);
    }

    private static HttpResponseMessage Json(HttpStatusCode status, string body) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private static int JwksCalls(StubHttpHandler handler) =>
        handler.Requests.Count(r => r.RequestUri!.AbsolutePath.Contains("/jwks"));

    private static int TokenCalls(StubHttpHandler handler) =>
        handler.Requests.Count(r => r.RequestUri!.AbsolutePath.Contains("/token"));

    // ---- ctor guards and the type pin (:80-:82, :71) ----

    [Fact]
    public void Ctor_NullCache_Throws_NamingCache()
    {
        var ex = Assert.Throws<ArgumentNullException>(() =>
            new TokenExchangeProvider(null!, new StubHttpClientFactory(new StubHttpHandler(HttpStatusCode.OK, "{}")), new FakeTimeProvider()));

        Assert.Equal("cache", ex.ParamName);
    }

    [Fact]
    public void Ctor_NullHttpClientFactory_Throws_NamingFactory()
    {
        var ex = Assert.Throws<ArgumentNullException>(() =>
            new TokenExchangeProvider(
                new InMemoryTokenCache(Options.Create(new TokenCacheOptions()), new FakeTimeProvider()),
                null!,
                new FakeTimeProvider()));

        Assert.Equal("httpClientFactory", ex.ParamName);
    }

    [Fact]
    public void Ctor_NullTime_Throws_NamingTime()
    {
        var ex = Assert.Throws<ArgumentNullException>(() =>
            new TokenExchangeProvider(
                new InMemoryTokenCache(Options.Create(new TokenCacheOptions()), new FakeTimeProvider()),
                new StubHttpClientFactory(new StubHttpHandler(HttpStatusCode.OK, "{}")),
                null!));

        Assert.Equal("time", ex.ParamName);
    }

    [Fact]
    public void Type_IsTokenExchange() =>
        Assert.Equal("TokenExchange", Create((_, _) => Json(HttpStatusCode.OK, "{}")).Provider.Type);

    // ---- the rotation eviction rule (:161, :162) ----

    // No usable signing keys is the rotation signal mid-cutover (IdP answers with the
    // new set only moments later): evict so the next request refetches and succeeds.
    // Skipping the eviction pins the fleet to the dead set until the 15-minute interval.
    [Fact]
    public async Task Rotation_KeyNotFound_EvictsCachedJwks_NextRequestRefetchesAndSucceeds()
    {
        var jwksFetches = 0;
        var (provider, handler, _) = Create((req, _) =>
            req.RequestUri!.AbsolutePath.Contains("/jwks")
                ? Json(HttpStatusCode.OK, ++jwksFetches == 1
                    ? JwksWith() // cutover window: the old set is gone, the new one not yet cached
                    : JwksWith(("key-2", OtherRsa)))
                : Json(HttpStatusCode.OK, """{"access_token":"down-tok","expires_in":300}"""));
        var inbound = IssueToken(OtherRsa);

        var ex = await Assert.ThrowsAsync<InboundTokenRejectedException>(() => provider
            .GetCredentialAsync(Options_direct(), TestSecrets.AccessorFor([]), Ctx(inbound), default).AsTask());
        Assert.Equal("signature", ex.Reason);
        Assert.Equal(1, JwksCalls(handler));
        Assert.Equal(0, TokenCalls(handler));

        Assert.Equal("down-tok", await provider.GetCredentialAsync(
            Options_direct(), TestSecrets.AccessorFor([]), Ctx(inbound), default).AsTask());
        Assert.Equal(2, JwksCalls(handler));
        Assert.Equal(1, TokenCalls(handler));
    }

    // The other half of the rule: an expired token is NOT rotation. Evicting then would
    // turn every stale inbound into a JWKS refetch — a cheap IdP hammer from callers.
    [Fact]
    public async Task ExpiredToken_Rejects_WithoutEvictingJwks()
    {
        var (provider, handler, _) = Create((req, _) => req.RequestUri!.AbsolutePath.Contains("/jwks")
            ? Json(HttpStatusCode.OK, JwksWith(("key-1", IssuerRsa)))
            : Json(HttpStatusCode.OK, """{"access_token":"down-tok","expires_in":300}"""));
        var inbound = IssueToken(IssuerRsa, lifetime: TimeSpan.FromMinutes(-30));

        var ex = await Assert.ThrowsAsync<InboundTokenRejectedException>(() => provider
            .GetCredentialAsync(Options_direct(), TestSecrets.AccessorFor([]), Ctx(inbound), default).AsTask());
        Assert.Equal("expired", ex.Reason);

        await Assert.ThrowsAsync<InboundTokenRejectedException>(() => provider
            .GetCredentialAsync(Options_direct(), TestSecrets.AccessorFor([]), Ctx(inbound), default).AsTask());
        Assert.Equal(1, JwksCalls(handler)); // no refetch: the cached set was never touched
    }

    // ---- rejection messages name the credential (:170, :178) ----

    [Fact]
    public async Task ValidationFailure_MessageNamesCredential()
    {
        var (provider, _, _) = Create((_, _) => Json(HttpStatusCode.OK, JwksWith(("key-1", IssuerRsa))));
        var inbound = IssueToken(IssuerRsa, audience: "some-other-api");

        var ex = await Assert.ThrowsAsync<InboundTokenRejectedException>(() => provider
            .GetCredentialAsync(Options_direct(), TestSecrets.AccessorFor([]), Ctx(inbound), default).AsTask());

        Assert.Equal("audience", ex.Reason);
        Assert.Contains("credential 'test'", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MissingSubject_MessageNamesCredentialAndClaim()
    {
        var (provider, _, _) = Create((_, _) => Json(HttpStatusCode.OK, JwksWith(("key-1", IssuerRsa))));
        var inbound = IssueToken(IssuerRsa, subject: null!);

        var ex = await Assert.ThrowsAsync<InboundTokenRejectedException>(() => provider
            .GetCredentialAsync(Options_direct(), TestSecrets.AccessorFor([]), Ctx(inbound), default).AsTask());

        Assert.Equal("missing-subject", ex.Reason);
        Assert.Contains("credential 'test'", ex.Message, StringComparison.Ordinal);
        Assert.Contains("'sub' claim", ex.Message, StringComparison.Ordinal);
    }

    // ---- MapReason arms (:186, :187) ----

    [Fact]
    public async Task NotYetValidToken_ReasonIsNotYetValid()
    {
        var (provider, _, _) = Create((_, _) => Json(HttpStatusCode.OK, JwksWith(("key-1", IssuerRsa))));
        var inbound = IssueToken(IssuerRsa, now: DateTimeOffset.UtcNow + TimeSpan.FromDays(1));

        var ex = await Assert.ThrowsAsync<InboundTokenRejectedException>(() => provider
            .GetCredentialAsync(Options_direct(), TestSecrets.AccessorFor([]), Ctx(inbound), default).AsTask());

        Assert.Equal("not-yet-valid", ex.Reason);
    }

    // ---- Basic auth exactness (:393 Expand family) ----

    [Fact]
    public async Task BasicAuth_SendsExactExpandedPair()
    {
        var (provider, handler, _) = Create((req, _) => req.RequestUri!.AbsolutePath.Contains("/jwks")
            ? Json(HttpStatusCode.OK, JwksWith(("key-1", IssuerRsa)))
            : Json(HttpStatusCode.OK, """{"access_token":"down-tok","expires_in":300}"""));

        await provider.GetCredentialAsync(
            Options_direct(), TestSecrets.AccessorFor([]), Ctx(IssueToken(IssuerRsa)), default);

        var request = Assert.Single(handler.Requests, r => r.RequestUri!.AbsolutePath.Contains("/token"));
        Assert.Equal("Basic", request.Headers.Authorization!.Scheme);
        Assert.Equal(
            Convert.ToBase64String(Encoding.UTF8.GetBytes("cid:csec")),
            request.Headers.Authorization.Parameter);
    }

    // A null secret is legal (public-client style); the expander must not be reached
    // with it and the pair is still sent exactly.
    [Fact]
    public async Task BasicAuth_NullSecret_SendsPairWithEmptySecret()
    {
        var (provider, handler, _) = Create((req, _) => req.RequestUri!.AbsolutePath.Contains("/jwks")
            ? Json(HttpStatusCode.OK, JwksWith(("key-1", IssuerRsa)))
            : Json(HttpStatusCode.OK, """{"access_token":"down-tok","expires_in":300}"""));
        var options = Options_direct();
        options.ClientSecret = null;

        await provider.GetCredentialAsync(
            options, TestSecrets.AccessorFor([]), Ctx(IssueToken(IssuerRsa)), default);

        var request = Assert.Single(handler.Requests, r => r.RequestUri!.AbsolutePath.Contains("/token"));
        Assert.Equal(
            Convert.ToBase64String(Encoding.UTF8.GetBytes("cid:")),
            request.Headers.Authorization!.Parameter);
    }

    // ---- expires_in shapes vs DefaultLifetime (1 h default) (:427) ----

    [Theory]
    [InlineData("-5")]   // negative: nonsense, not a past expiry
    [InlineData("0")]    // zero: expires immediately, nonsense
    [InlineData("\"soon\"")] // unparsable string
    public async Task NonsenseExpiresIn_UsesDefaultLifetime_ServesFromCache(string expiresInJson)
    {
        var (provider, handler, _) = Create((req, _) => req.RequestUri!.AbsolutePath.Contains("/jwks")
            ? Json(HttpStatusCode.OK, JwksWith(("key-1", IssuerRsa)))
            : Json(HttpStatusCode.OK, $$"""{"access_token":"down-tok","expires_in":{{expiresInJson}}}"""));
        var inbound = IssueToken(IssuerRsa);

        Assert.Equal("down-tok", await provider.GetCredentialAsync(
            Options_direct(), TestSecrets.AccessorFor([]), Ctx(inbound), default).AsTask());

        // A second request at once: default lifetime means a cache hit. A past/zero
        // expiry (the surviving mutants) forces a second IdP call instead.
        Assert.Equal("down-tok", await provider.GetCredentialAsync(
            Options_direct(), TestSecrets.AccessorFor([]), Ctx(inbound), default).AsTask());
        Assert.Equal(1, TokenCalls(handler));
    }

    [Fact]
    public async Task ShorterExpiresIn_WinsOverDefaultLifetime_CachesOnlyThatLong()
    {
        var (provider, handler, time) = Create((req, _) => req.RequestUri!.AbsolutePath.Contains("/jwks")
            ? Json(HttpStatusCode.OK, JwksWith(("key-1", IssuerRsa)))
            : Json(HttpStatusCode.OK, """{"access_token":"down-tok","expires_in":600}"""));
        var inbound = IssueToken(IssuerRsa);

        await provider.GetCredentialAsync(Options_direct(), TestSecrets.AccessorFor([]), Ctx(inbound), default);
        time.Advance(TimeSpan.FromMinutes(30)); // well past the 10-minute expires_in, inside the 1 h default
        await provider.GetCredentialAsync(Options_direct(), TestSecrets.AccessorFor([]), Ctx(inbound), default);

        Assert.Equal(2, TokenCalls(handler)); // the short lifetime was honored, not the default
    }

    // ---- ValidateIssuerSigningKey pin (:150 equivalence witness) ----

    // With RequireSignedTokens=true and an explicit key set, unsigned tokens refuse and
    // signed ones validate against those keys — the behaviour the flag pair pins.
    [Fact]
    public async Task UnsignedToken_Rejected_EvenWithKeysConfigured()
    {
        var (provider, handler, _) = Create((_, _) => Json(HttpStatusCode.OK, JwksWith(("key-1", IssuerRsa))));
        var inbound = IssueToken(IssuerRsa, sign: false);

        var ex = await Assert.ThrowsAsync<InboundTokenRejectedException>(() => provider
            .GetCredentialAsync(Options_direct(), TestSecrets.AccessorFor([]), Ctx(inbound), default).AsTask());

        Assert.Equal("signature", ex.Reason);
        Assert.Equal(0, TokenCalls(handler)); // rejected before any exchange
    }
}
