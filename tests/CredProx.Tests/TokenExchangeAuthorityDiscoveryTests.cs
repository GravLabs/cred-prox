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
/// M31 mutation triage for <see cref="TokenExchangeProvider"> authority mode: the whole
/// discovery cluster (well-known path, issuer precedence, discovered token endpoint,
/// metadata failure wrapping, cancellation passthrough) had zero unit coverage. The
/// discovery and JWKS fetches ride the credential's per-connection egress client, so the
/// ordinary <see cref="StubHttpHandler"/> can serve the whole IdP.
/// </summary>
public sealed class TokenExchangeAuthorityDiscoveryTests
{
    private const string Issuer = "https://idp.example";
    private const string Audience = "credprox-api";
    private const string JwksUrl = "https://idp.example/jwks";
    private const string TokenUrl = "https://idp.example/token";
    private const string WellKnown = "/.well-known/openid-configuration";

    private static readonly RSA IssuerRsa = RSA.Create(2048);

    private static string JwksJson()
    {
        var p = IssuerRsa.ExportParameters(false);
        static string B64Url(byte[] bytes) =>
            Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return System.Text.Json.JsonSerializer.Serialize(new
        {
            keys = new[]
            {
                new { kty = "RSA", use = "sig", alg = "RS256", n = B64Url(p.Modulus!), e = B64Url(p.Exponent!) },
            },
        });
    }

    private static string IssueToken(string issuer = Issuer)
    {
        var start = DateTimeOffset.UtcNow;
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = Audience,
            NotBefore = start.AddMinutes(-1).UtcDateTime,
            Expires = start.AddMinutes(5).UtcDateTime,
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(IssuerRsa), SecurityAlgorithms.RsaSha256),
            Claims = new Dictionary<string, object> { ["sub"] = "user-A" },
        };
        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    // The discovery document Wilson's retriever parses; jwks_uri is fetched too.
    private const string DiscoveryDoc =
        """{"issuer":"https://idp.example","jwks_uri":"https://idp.example/jwks","token_endpoint":"https://idp.example/token"}""";

    private static HttpResponseMessage Json(HttpStatusCode status, string body) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private static (TokenExchangeProvider Provider, StubHttpHandler Handler) Create(
        Func<HttpRequestMessage, int, HttpResponseMessage> responder)
    {
        var handler = new StubHttpHandler(responder);
        var time = new FakeTimeProvider();
        var cache = new InMemoryTokenCache(Options.Create(new TokenCacheOptions()), time);
        return (new TokenExchangeProvider(cache, new StubHttpClientFactory(handler), time), handler);
    }

    private static TokenExchangeOptions AuthorityOptions(string? optionsIssuer = null) => new()
    {
        Authority = "https://idp.example/", // trailing slash: TrimEnd must land exactly once
        Issuer = optionsIssuer,
        Audience = Audience,
        ClientId = "cid",
        ClientSecret = "csec",
        // TokenEndpoint and JwksUri deliberately unset: discovery must supply them.
    };

    private static CredentialRequestContext Ctx(string inbound) =>
        new() { CredentialName = "test", Partition = "p1", InboundToken = inbound };

    private static int PathCalls(StubHttpHandler handler, string path) =>
        handler.Requests.Count(r => r.RequestUri!.AbsolutePath == path);

    private static Func<HttpRequestMessage, int, HttpResponseMessage> Idp(string discoveryDoc = DiscoveryDoc) =>
        (req, _) => req.RequestUri!.AbsolutePath switch
        {
            WellKnown => Json(HttpStatusCode.OK, discoveryDoc),
            "/jwks" => Json(HttpStatusCode.OK, JwksJson()),
            _ => Json(HttpStatusCode.OK, """{"access_token":"down-tok","expires_in":300}"""),
        };

    [Fact]
    public async Task AuthorityMode_ExchangesWithDiscoveredEndpoints()
    {
        var (provider, handler) = Create(Idp());

        Assert.Equal("down-tok", await provider.GetCredentialAsync(
            AuthorityOptions(), TestSecrets.AccessorFor([]), Ctx(IssueToken()), default).AsTask());

        Assert.Equal(1, PathCalls(handler, WellKnown));
        Assert.Equal(1, PathCalls(handler, "/jwks"));
        Assert.Equal(1, PathCalls(handler, "/token"));

        // Second request: cached downstream token and reused discovery config.
        Assert.Equal("down-tok", await provider.GetCredentialAsync(
            AuthorityOptions(), TestSecrets.AccessorFor([]), Ctx(IssueToken()), default).AsTask());
        Assert.Equal(1, PathCalls(handler, WellKnown));
        Assert.Equal(1, PathCalls(handler, "/token"));
    }

    // options.Issuer wins over the discovered issuer (issuer ??= oidc.Issuer).
    [Fact]
    public async Task AuthorityMode_OptionsIssuerWins_OverDiscoveredIssuer()
    {
        var (provider, _) = Create(Idp(
            """{"issuer":"https://discovered.example","jwks_uri":"https://idp.example/jwks","token_endpoint":"https://idp.example/token"}"""));

        Assert.Equal("down-tok", await provider.GetCredentialAsync(
            AuthorityOptions(optionsIssuer: Issuer), TestSecrets.AccessorFor([]), Ctx(IssueToken()), default).AsTask());
    }

    [Fact]
    public async Task AuthorityMode_MetadataUnreachable_WrapsAsCredentialFailure_NamingAuthority()
    {
        var (provider, _) = Create((req, _) => req.RequestUri!.AbsolutePath == WellKnown
            ? Json(HttpStatusCode.InternalServerError, "boom")
            : Idp()(req, 0));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => provider.GetCredentialAsync(
            AuthorityOptions(), TestSecrets.AccessorFor([]), Ctx(IssueToken()), default).AsTask());

        Assert.IsNotType<InboundTokenRejectedException>(ex); // a credential failure, not a caller rejection
        Assert.Contains("authority", ex.Message, StringComparison.Ordinal);
        Assert.Contains("could not be retrieved", ex.Message, StringComparison.Ordinal);
        Assert.NotNull(ex.InnerException); // wrapped, never rethrown raw (:380 filter)
    }

    [Fact]
    public async Task AuthorityMode_Cancelled_CancellationPropagatesUnwrapped()
    {
        var (provider, _) = Create(Idp());
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();

        // OperationCanceledException must pass the wrapping filter untouched.
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => provider.GetCredentialAsync(
            AuthorityOptions(), TestSecrets.AccessorFor([]), Ctx(IssueToken()), cancelled.Token).AsTask());
    }

    [Theory]
    [InlineData(false, null)]  // token_endpoint absent
    [InlineData(true, "\"\"")] // token_endpoint empty
    public async Task AuthorityMode_NoDiscoveredTokenEndpoint_Throws_NamingRemedy(bool present, string? endpointJson)
    {
        var doc = $$"""{"issuer":"https://idp.example","jwks_uri":"https://idp.example/jwks"{{(present ? ",\"token_endpoint\":" + endpointJson : "")}}}""";
        var (provider, handler) = Create(Idp(doc));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => provider.GetCredentialAsync(
            AuthorityOptions(), TestSecrets.AccessorFor([]), Ctx(IssueToken()), default).AsTask());

        Assert.IsNotType<InboundTokenRejectedException>(ex);
        Assert.Contains("no token_endpoint", ex.Message, StringComparison.Ordinal);
        Assert.Contains("set TokenEndpoint explicitly", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(handler.Requests, r => r.Method == HttpMethod.Post); // no exchange attempted
    }
}
