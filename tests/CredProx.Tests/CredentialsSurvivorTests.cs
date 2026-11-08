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
/// M31 mutation triage of the credential providers and placement types: the argument
/// guards of the four exchange providers (which no test called with nulls), the plain-http
/// allowance on authority metadata, the discovery-failure message source label, the
/// placement-name defaults behind the attachment interface, the single documented reject
/// type and diagnosis texts of the attacher, and the literal-brace path of the template
/// expander.
/// </summary>
public sealed class CredentialsSurvivorTests
{
    // ---- provider argument guards -----------------------------------------------------

    private static InMemoryTokenCache NewCache() =>
        new(Options.Create(new TokenCacheOptions()), new FakeTimeProvider());

    private static CredentialRequestContext Ctx(string? inbound = "inbound.tok") =>
        new() { CredentialName = "test", Partition = "p1", InboundToken = inbound };

    [Fact]
    public async Task TokenExchange_GuardsItsArguments_NamingEachParam()
    {
        var options = new TokenExchangeOptions { TokenEndpoint = "http://tok.example/oauth/token" };
        var provider = new TokenExchangeProvider(
            NewCache(), new StubHttpClientFactory(new StubHttpHandler(HttpStatusCode.OK, "{}")), new FakeTimeProvider());
        var secrets = TestSecrets.AccessorFor([]);

        var opt = await Assert.ThrowsAsync<ArgumentNullException>(() =>
            provider.GetCredentialAsync(null!, secrets, Ctx(), default).AsTask());
        Assert.Equal("options", opt.ParamName);

        var sec = await Assert.ThrowsAsync<ArgumentNullException>(() =>
            provider.GetCredentialAsync(options, null!, Ctx(), default).AsTask());
        Assert.Equal("secrets", sec.ParamName);

        var ctx = await Assert.ThrowsAsync<ArgumentNullException>(() =>
            provider.GetCredentialAsync(options, secrets, null!, default).AsTask());
        Assert.Equal("context", ctx.ParamName);
    }

    [Fact]
    public async Task LoginExchange_GuardsNullSecrets_NamingSecrets()
    {
        var options = new LoginExchangeOptions
        {
            LoginEndpoint = "https://acme.example/login",
            Basic = new LoginExchangeCredentials { User = "u", Password = "secret:p" },
        };
        var provider = new LoginExchangeProvider(
            NewCache(), new StubHttpClientFactory(new StubHttpHandler(HttpStatusCode.OK, "tok")), new FakeTimeProvider());

        var error = await Assert.ThrowsAsync<ArgumentNullException>(() =>
            provider.GetCredentialAsync(options, null!, Ctx(), default).AsTask());

        Assert.Equal("secrets", error.ParamName);
    }

    [Fact]
    public async Task JwtAssertion_GuardsNullSecrets_NamingSecrets()
    {
        var provider = new JwtAssertionProvider(
            NewCache(), new StubHttpClientFactory(new StubHttpHandler(HttpStatusCode.OK, "{}")), new FakeTimeProvider());

        var error = await Assert.ThrowsAsync<ArgumentNullException>(() =>
            provider.GetCredentialAsync(new JwtAssertionOptions(), null!, Ctx(), default).AsTask());

        Assert.Equal("secrets", error.ParamName);
    }

    [Fact]
    public async Task OAuthClientCredentials_GuardsNullSecrets_NamingSecrets()
    {
        var provider = new OAuthClientCredentialsProvider(
            NewCache(), new StubHttpClientFactory(new StubHttpHandler(HttpStatusCode.OK, "{}")), new FakeTimeProvider());

        var error = await Assert.ThrowsAsync<ArgumentNullException>(() =>
            provider.GetCredentialAsync(new OAuthClientCredentialsOptions(), null!, Ctx(), default).AsTask());

        Assert.Equal("secrets", error.ParamName);
    }

    // ---- authority discovery: http allowance + failure label ---------------------------

    private const string Audience = "credprox-api";
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

    private static string IssueHttpToken()
    {
        var start = DateTimeOffset.UtcNow;
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = "http://idp.example",
            Audience = Audience,
            NotBefore = start.AddMinutes(-1).UtcDateTime,
            Expires = start.AddMinutes(5).UtcDateTime,
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(IssuerRsa), SecurityAlgorithms.RsaSha256),
            Claims = new Dictionary<string, object> { ["sub"] = "user-A" },
        };
        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    private static HttpResponseMessage Json(string body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private const string HttpDiscoveryDoc =
        """{"issuer":"http://idp.example","jwks_uri":"http://idp.example/jwks","token_endpoint":"http://idp.example/token"}""";

    private static (TokenExchangeProvider Provider, StubHttpHandler Handler) CreateIdp(
        Func<HttpRequestMessage, int, HttpResponseMessage> responder)
    {
        var handler = new StubHttpHandler(responder);
        var time = new FakeTimeProvider();
        var cache = new InMemoryTokenCache(Options.Create(new TokenCacheOptions()), time);
        return (new TokenExchangeProvider(cache, new StubHttpClientFactory(handler), time), handler);
    }

    [Fact]
    public async Task AuthorityMode_PlainHttpMetadata_IsAccepted()
    {
        // The opt-out path (docs/adr/0003): a private-network http IdP is supported once
        // RequireHttpsMetadata is explicitly false, and the metadata still rides the
        // connection-scoped retriever (M31 triage first exposed both as unobserved).
        var (provider, _) = CreateIdp((req, _) => req.RequestUri!.AbsolutePath switch
        {
            WellKnown => Json(HttpDiscoveryDoc),
            "/jwks" => Json(JwksJson()),
            _ => Json("""{"access_token":"down-tok","expires_in":300}"""),
        });

        var token = await provider.GetCredentialAsync(
            new TokenExchangeOptions
            {
                Authority = "http://idp.example/",
                RequireHttpsMetadata = false,
                Audience = Audience,
                ClientId = "cid",
                ClientSecret = "csec",
            },
            TestSecrets.AccessorFor([]),
            Ctx(IssueHttpToken()),
            default);

        Assert.Equal("down-tok", token);
    }

    [Fact]
    public async Task AuthorityMode_PlainHttpMetadata_RefusedByDefault()
    {
        // Default posture (docs/adr/0003, the JwtBearer contract): http metadata carries
        // the keys that validate inbound tokens, so it fails closed even though the
        // endpoint itself is reachable — the fetch must not depend on the network path.
        var (provider, handler) = CreateIdp((req, _) => req.RequestUri!.AbsolutePath switch
        {
            WellKnown => Json(HttpDiscoveryDoc),
            "/jwks" => Json(JwksJson()),
            _ => Json("""{"access_token":"down-tok","expires_in":300}"""),
        });

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetCredentialAsync(
                new TokenExchangeOptions
                {
                    Authority = "http://idp.example/",
                    Audience = Audience,
                    ClientId = "cid",
                    ClientSecret = "csec",
                },
                TestSecrets.AccessorFor([]),
                Ctx(IssueHttpToken()),
                default).AsTask());

        Assert.Contains("authority could not be retrieved", error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(handler.Requests, r => r.RequestUri!.AbsolutePath == WellKnown);
    }

    [Fact]
    public async Task DirectJwks_PlainHttp_RefusedByDefault()
    {
        // Direct-JWKS mode has no Wilson retriever to carry RequireHttps; the provider's
        // own guard enforces the same rule and names the opt-out.
        var (provider, _) = CreateIdp((_, _) => Json("{}"));

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetCredentialAsync(
                new TokenExchangeOptions
                {
                    Issuer = "http://idp.example",
                    JwksUri = "http://idp.example/jwks",
                    TokenEndpoint = "https://idp.example/token",
                    Audience = Audience,
                    ClientId = "cid",
                    ClientSecret = "csec",
                },
                TestSecrets.AccessorFor([]),
                Ctx(IssueHttpToken()),
                default).AsTask());

        Assert.Contains("RequireHttpsMetadata", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DirectJwks_PlainHttp_AcceptedWhenOptedOut()
    {
        var (provider, _) = CreateIdp((req, _) => req.RequestUri!.AbsolutePath switch
        {
            "/jwks" => Json(JwksJson()),
            _ => Json("""{"access_token":"down-tok","expires_in":300}"""),
        });

        var token = await provider.GetCredentialAsync(
            new TokenExchangeOptions
            {
                Issuer = "http://idp.example",
                JwksUri = "http://idp.example/jwks",
                TokenEndpoint = "https://idp.example/token",
                RequireHttpsMetadata = false,
                Audience = Audience,
                ClientId = "cid",
                ClientSecret = "csec",
            },
            TestSecrets.AccessorFor([]),
            Ctx(IssueHttpToken()),
            default);

        Assert.Equal("down-tok", token);
    }

    [Fact]
    public async Task DirectJwks_CacheIsNeverAnHttpsBypassAcrossCredentials()
    {
        // F1 regression (P-7 ruling, same class the manager cache was keyed for): on one
        // singleton provider two credentials share the http JwksUri — one opted out, one
        // default. The default one fails closed in BOTH orders, including after the
        // opted-out one has populated the cache; http-obtained keys must never satisfy
        // the https posture by cache hit, and the strict calls touch no wire.
        var (provider, handler) = CreateIdp((req, _) => req.RequestUri!.AbsolutePath switch
        {
            "/jwks" => Json(JwksJson()),
            _ => Json("""{"access_token":"down-tok","expires_in":300}"""),
        });

        TokenExchangeOptions Strict() => new()
        {
            Issuer = "http://idp.example",
            JwksUri = "http://idp.example/jwks",
            TokenEndpoint = "https://idp.example/token",
            Audience = Audience,
            ClientId = "cid",
            ClientSecret = "csec",
        };
        var optedOut = new TokenExchangeOptions
        {
            Issuer = "http://idp.example",
            JwksUri = "http://idp.example/jwks",
            TokenEndpoint = "https://idp.example/token",
            RequireHttpsMetadata = false,
            Audience = Audience,
            ClientId = "cid",
            ClientSecret = "csec",
        };

        // Strict first: refused before any fetch.
        var first = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetCredentialAsync(Strict(), TestSecrets.AccessorFor([]), Ctx(IssueHttpToken()), default).AsTask());
        Assert.Contains("RequireHttpsMetadata", first.Message, StringComparison.Ordinal);

        // Opted-out next: works over http and populates the shared cache.
        Assert.Equal("down-tok", await provider.GetCredentialAsync(optedOut, TestSecrets.AccessorFor([]), Ctx(IssueHttpToken()), default));

        // Strict again against the WARM cache: still refused (pre-fix, this served keys).
        var again = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetCredentialAsync(Strict(), TestSecrets.AccessorFor([]), Ctx(IssueHttpToken()), default).AsTask());
        Assert.Contains("RequireHttpsMetadata", again.Message, StringComparison.Ordinal);

        // The strict calls produced no wire traffic: one JWKS fetch and one token call,
        // both from the opted-out credential.
        Assert.Equal(1, handler.Requests.Count(r => r.RequestUri!.AbsolutePath == "/jwks"));
    }

    [Fact]
    public async Task AuthorityMode_DiscoveryFailure_NamesTheAuthoritySource()
    {
        // The 502 diagnosis names WHICH source failed; a bare message would leave the
        // operator guessing between authority, JWKS and token endpoint.
        var (provider, _) = CreateIdp((req, _) =>
            req.RequestUri!.AbsolutePath == WellKnown
                ? new HttpResponseMessage(HttpStatusCode.InternalServerError) { Content = new StringContent("down") }
                : Json("{}"));

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetCredentialAsync(
                new TokenExchangeOptions { Authority = "https://idp.example/", Audience = Audience, ClientId = "cid", ClientSecret = "csec" },
                TestSecrets.AccessorFor([]),
                Ctx(IssueHttpToken()),
                default).AsTask());

        Assert.Contains("token-exchange authority", error.Message, StringComparison.Ordinal);
    }

    // ---- registration & options shapes -------------------------------------------------

    [Fact]
    public void CredentialTypeRegistration_EmptyTypeName_ThrowsArgumentNamingTypeName()
    {
        var error = Assert.Throws<ArgumentException>(() => new CredentialTypeRegistration(
            string.Empty,
            typeof(OAuthClientCredentialsOptions),
            typeof(OAuthClientCredentialsProvider)));

        Assert.Equal("typeName", error.ParamName);
    }

    [Fact]
    public void OAuthClientCredentialsOptions_Prefix_DefaultsToBearer_AndEmptyMeansRaw()
    {
        Assert.Equal("Bearer ", new OAuthClientCredentialsOptions().Prefix);
        // "Set empty to attach the raw token" — empty must fold to NO prefix, not " ".
        Assert.Null(new OAuthClientCredentialsOptions { TokenTypeName = string.Empty }.Prefix);
    }

    [Fact]
    public void LoginExchangeOptions_CookiePlacement_NamesCookieFromNameOrResponseField()
    {
        var attachment = (IHasAttachment)new LoginExchangeOptions
        {
            Location = CredentialLocation.Cookie,
            ResponseField = "session",
        };
        // Cookie mode defaults the cookie name to the login's own response field.
        Assert.Equal("session", attachment.Name);

        Assert.Equal("explicit", ((IHasAttachment)new LoginExchangeOptions
        {
            Location = CredentialLocation.Cookie,
            Name = "explicit",
            ResponseField = "session",
        }).Name);

        var error = Assert.Throws<InvalidOperationException>(() =>
            ((IHasAttachment)new LoginExchangeOptions { Location = CredentialLocation.Cookie }).Name);
        Assert.Contains("Cookie placement needs Name or ResponseField", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void StaticKeyOptions_AttachmentName_RequiresAName()
    {
        Assert.Equal("api-key", ((IHasAttachment)new StaticKeyOptions { Name = "api-key" }).Name);

        var error = Assert.Throws<InvalidOperationException>(
            () => ((IHasAttachment)new StaticKeyOptions()).Name);
        Assert.Contains("StaticKey requires a Name.", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task StaticKey_UnresolvableSecret_StatesTheCredentialName()
    {
        var value = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new StaticKeyProvider().GetCredentialAsync(
                new StaticKeyOptions { Secret = "secret:blank" },
                TestSecrets.AccessorFor(
                    new() { ["Secret"] = "secret:blank" },
                    new() { ["blank"] = string.Empty }),
                Ctx(),
                default).AsTask());

        Assert.Contains("static-key credential 'test' does not resolve.", value.Message, StringComparison.Ordinal);
    }

    // ---- attacher reject contract -------------------------------------------------------

    [Fact]
    public void Attacher_HeaderValueOutsideGrammar_TranslatesToArgumentException()
    {
        // One documented reject type for every placement refusal, never a raw BCL
        // FormatException from the header store (M31 fuzz triage).
        var error = Assert.Throws<ArgumentException>(
            () => CredentialAttacher.Apply(
                new HttpRequestMessage(), CredentialLocation.Header, "te", "a b"));

        Assert.Equal("name", error.ParamName);
        Assert.Contains("'te' cannot be used as a credential header name", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Attacher_ParsedKnownHeader_RefusesValueThatWouldNotRoundTrip()
    {
        // 'Date' is BCL-parsed: the obsolete spelling is re-serialized to RFC 1123 on the
        // wire. A credential must reach the vendor byte-identical, so placement refuses
        // with the documented reject type (M31 fuzz P-5).
        var error = Assert.Throws<ArgumentException>(
            () => CredentialAttacher.Apply(
                new HttpRequestMessage(), CredentialLocation.Header, "Date", "Sunday, 06-Nov-94 08:49:37 GMT"));

        Assert.Equal("name", error.ParamName);
        Assert.Contains("is parsed by the HTTP header store", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Attacher_QueryPlacement_RebuildsPassThroughQueryWithEscaping()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "http://vendor.example/p?x=1 2");

        CredentialAttacher.Apply(request, CredentialLocation.Query, "token", "a b");

        var query = request.RequestUri!.Query;
        Assert.Contains("token=a%20b", query, StringComparison.Ordinal);
        Assert.Contains("x=1%202", query, StringComparison.Ordinal);
    }

    // ---- template expander brace path ---------------------------------------------------

    [Fact]
    public async Task TemplateExpander_LiteralBraceBeforeReference_ResolvesOnlyTheReference()
    {
        // A '{' that does not begin '{secret:' is literal text; only the real reference
        // resolves. (The literal-brace guard had no test that distinguished it from
        // treating every '{' as a reference start — M31 triage.)
        var expanded = await TemplateExpander.ExpandAsync(
            "{a{secret:k}b}",
            null,
            TestSecrets.AccessorFor(new() { ["Secret"] = "secret:k" }, new() { ["k"] = "S" }),
            default);

        Assert.Equal("{aSb}", expanded);
    }
}
