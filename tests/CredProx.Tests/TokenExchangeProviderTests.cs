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
/// §3.6 / §5.2 "Token exchange" rows: the exact wire fields per mode, inbound validation
/// that rejects before any IdP call, per-user cache isolation (user A's token is never
/// served to user B, a forged subject cannot poison another user's key), single-flight per
/// user, exchange failures as 502-shaped <see cref="InvalidOperationException"/>, and the
/// rule that no message ever carries a token value.
/// </summary>
public sealed class TokenExchangeProviderTests
{
    private const string Issuer = "https://idp.example";
    private const string Audience = "credprox-api";
    private const string JwksUrl = "https://idp.example/jwks";
    private const string TokenUrl = "https://idp.example/token";

    private static readonly RSA IssuerRsa = RSA.Create(2048);
    private static readonly RSA AttackerRsa = RSA.Create(2048);

    private static RsaSecurityKey PublicIssuerKey() =>
        new(IssuerRsa.ExportParameters(false));

    private static string JwksJson()
    {
        // Plain RFC 7517 JWKS built from the public key — the exact shape a real IdP serves.
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

    private static string IssueToken(
        RSA signingKey,
        string? subject = "user-A",
        string audience = Audience,
        string issuer = Issuer,
        TimeSpan? lifetime = null,
        DateTimeOffset? now = null)
    {
        var start = now ?? DateTimeOffset.UtcNow;
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            NotBefore = start.AddMinutes(-1).UtcDateTime,
            Expires = start.Add(lifetime ?? TimeSpan.FromMinutes(5)).UtcDateTime,
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(signingKey), SecurityAlgorithms.RsaSha256),
        };
        if (subject is not null)
        {
            descriptor.Claims = new Dictionary<string, object> { ["sub"] = subject };
        }

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    private static TokenExchangeOptions ExchangeOptions(TokenExchangeMode mode = TokenExchangeMode.Rfc8693) => new()
    {
        Mode = mode,
        Issuer = Issuer,
        JwksUri = JwksUrl,
        Audience = Audience,
        TokenEndpoint = TokenUrl,
        ClientId = "cid",
        ClientSecret = "csec",
    };

    private static CredentialRequestContext Context(string inbound, string? partition = "p1") =>
        new() { CredentialName = "test", Partition = partition, InboundToken = inbound };

    private static (TokenExchangeProvider Provider, StubHttpHandler Handler) CreateProvider(
        Func<HttpRequestMessage, int, HttpResponseMessage>? responder = null)
    {
        var handler = new StubHttpHandler(responder ?? Route(jwks: JwksJson()));
        var time = new FakeTimeProvider();
        var cache = new InMemoryTokenCache(Options.Create(new TokenCacheOptions()), time);
        return (new TokenExchangeProvider(cache, new StubHttpClientFactory(handler), time), handler);
    }

    private static Func<HttpRequestMessage, int, HttpResponseMessage> Route(
        string jwks,
        string tokenBody = """{"access_token":"down-tok","expires_in":300}""",
        HttpStatusCode tokenStatus = HttpStatusCode.OK)
        => (req, _) => req.RequestUri!.AbsolutePath.Contains("/jwks")
            ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(jwks) }
            : new HttpResponseMessage(tokenStatus) { Content = new StringContent(tokenBody) };

    private static Dictionary<string, string> ParseForm(string body) =>
        body.Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(pair => pair.Split('=', 2))
            .ToDictionary(parts => Uri.UnescapeDataString(parts[0]), parts => Uri.UnescapeDataString(parts[1]));

    private static int ExchangeCalls(StubHttpHandler handler) =>
        handler.Requests.Count(r => r.RequestUri!.AbsolutePath.Contains("/token"));

    // The exchange request body (request 0 is the JWKS GET, which has no body).
    private static Dictionary<string, string> ExchangeBody(StubHttpHandler handler)
    {
        var index = handler.Requests.FindIndex(r => r.RequestUri!.AbsolutePath.Contains("/token"));
        return ParseForm(handler.Bodies[index]!);
    }

    // ---- wire shape (§5.2: exact form fields per mode) ----

    [Fact]
    public async Task Rfc8693_SendsSubjectTokenAndGrantUrn()
    {
        var (provider, handler) = CreateProvider();
        var inbound = IssueToken(IssuerRsa);

        var token = await provider.GetCredentialAsync(
            ExchangeOptions(), TestSecrets.AccessorFor([]), Context(inbound), default);

        Assert.Equal("down-tok", token);
        var form = ExchangeBody(handler);
        Assert.Equal("urn:ietf:params:oauth:grant-type:token-exchange", form["grant_type"]);
        Assert.Equal(inbound, form["subject_token"]);
        Assert.Equal("urn:ietf:params:oauth:token-type:access_token", form["subject_token_type"]);
        Assert.False(form.ContainsKey("assertion"));
        Assert.False(form.ContainsKey("requested_token_use"));

        var request = handler.Requests.Single(r => r.RequestUri!.AbsolutePath.Contains("/token"));
        Assert.Equal("Basic", request.Headers.Authorization!.Scheme);
    }

    [Fact]
    public async Task Rfc8693_OptionalFields_AreSentWhenConfigured()
    {
        var (provider, handler) = CreateProvider();
        var options = ExchangeOptions();
        options.SubjectTokenType = "urn:ietf:params:oauth:token-type:jwt";
        options.RequestedTokenType = "urn:ietf:params:oauth:token-type:access_token";
        options.IssuedTokenType = "urn:ietf:params:oauth:token-type:access_token";
        options.RequestedAudience = "downstream-api";
        options.Act = """{"sub":"orchestrator"}""";
        options.Scope = "api.read";

        await provider.GetCredentialAsync(
            options, TestSecrets.AccessorFor([]), Context(IssueToken(IssuerRsa)), default);

        var form = ExchangeBody(handler);
        Assert.Equal("urn:ietf:params:oauth:token-type:jwt", form["subject_token_type"]);
        Assert.Equal("urn:ietf:params:oauth:token-type:access_token", form["requested_token_type"]);
        Assert.Equal("urn:ietf:params:oauth:token-type:access_token", form["issued_token_type"]);
        Assert.Equal("downstream-api", form["audience"]);
        Assert.Equal("""{"sub":"orchestrator"}""", form["act"]);
        Assert.Equal("api.read", form["scope"]);
    }

    [Fact]
    public async Task EntraObo_SendsAssertionJwtBearerUrnAndOnBehalfOf()
    {
        var (provider, handler) = CreateProvider();
        var inbound = IssueToken(IssuerRsa);

        await provider.GetCredentialAsync(
            ExchangeOptions(TokenExchangeMode.EntraObo), TestSecrets.AccessorFor([]), Context(inbound), default);

        var form = ExchangeBody(handler);
        Assert.Equal("urn:ietf:params:oauth:grant-type:jwt-bearer", form["grant_type"]);
        Assert.Equal(inbound, form["assertion"]);
        Assert.Equal("on_behalf_of", form["requested_token_use"]);
        Assert.False(form.ContainsKey("subject_token"));
        Assert.False(form.ContainsKey("subject_token_type"));
    }

    // ---- inbound validation: rejected before any IdP call ----

    private static async Task AssertRejected(string inbound, string expectedReason)
    {
        var (provider, handler) = CreateProvider();

        var ex = await Assert.ThrowsAsync<InboundTokenRejectedException>(() => provider
            .GetCredentialAsync(ExchangeOptions(), TestSecrets.AccessorFor([]), Context(inbound), default)
            .AsTask());

        Assert.Equal(expectedReason, ex.Reason);
        // The token value never reaches the message (§5.2 no-leak).
        Assert.DoesNotContain(inbound, ex.Message, StringComparison.Ordinal);
        // Nothing reached the exchange endpoint.
        Assert.Equal(0, ExchangeCalls(handler));
    }

    [Fact]
    public Task BadSignature_Rejected() =>
        AssertRejected(IssueToken(AttackerRsa), "signature");

    [Fact]
    public Task Expired_Rejected() =>
        AssertRejected(IssueToken(IssuerRsa, lifetime: TimeSpan.FromMinutes(-2)), "expired");

    [Fact]
    public Task WrongAudience_Rejected() =>
        AssertRejected(IssueToken(IssuerRsa, audience: "some-other-api"), "audience");

    [Fact]
    public Task WrongIssuer_Rejected() =>
        AssertRejected(IssueToken(IssuerRsa, issuer: "https://evil.example"), "issuer");

    [Fact]
    public Task GarbageToken_Rejected() =>
        AssertRejected("not-a-jwt", "malformed");

    [Fact]
    public Task MissingSubjectClaim_Rejected() =>
        AssertRejected(IssueToken(IssuerRsa, subject: null), "missing-subject");

    [Fact]
    public async Task AlgNone_Rejected()
    {
        // Unsigned token: RequireSignedTokens must reject it before any exchange.
        static string B64Url(string json) =>
            Convert.ToBase64String(Encoding.UTF8.GetBytes(json)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var none = B64Url("""{"alg":"none","typ":"JWT"}""")
            + "."
            + B64Url($$"""{"sub":"user-A","aud":"{{Audience}}","iss":"{{Issuer}}","exp":9999999999}""")
            + ".";

        var (provider, handler) = CreateProvider();
        var ex = await Assert.ThrowsAsync<InboundTokenRejectedException>(() => provider
            .GetCredentialAsync(ExchangeOptions(), TestSecrets.AccessorFor([]), Context(none), default)
            .AsTask());

        Assert.Equal("signature", ex.Reason);
        Assert.Equal(0, ExchangeCalls(handler));
    }

    [Fact]
    public async Task SubjectCarryingCacheKeyDelimiter_CannotCollideWithAnotherUser()
    {
        // The combined key is "p:<partition>|u:<subject>"; a subject containing the
        // delimiter must not let one user land on another user's entry.
        var responses = 0;
        var (provider, handler) = CreateProvider((req, _) => req.RequestUri!.AbsolutePath.Contains("/jwks")
            ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(JwksJson()) }
            : new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent($$"""{"access_token":"down-tok-{{Interlocked.Increment(ref responses) - 1}}","expires_in":300}"""),
            });

        var attacker = Context(IssueToken(IssuerRsa, subject: "x|u:victim"));
        var victim = Context(IssueToken(IssuerRsa, subject: "victim"));

        Assert.Equal("down-tok-0", await provider.GetCredentialAsync(ExchangeOptions(), TestSecrets.AccessorFor([]), attacker, default));
        Assert.Equal("down-tok-1", await provider.GetCredentialAsync(ExchangeOptions(), TestSecrets.AccessorFor([]), victim, default));
        Assert.Equal("down-tok-0", await provider.GetCredentialAsync(ExchangeOptions(), TestSecrets.AccessorFor([]), attacker, default));

        Assert.Equal("p:p1|u:x|u:victim", attacker.CachePartition);
        Assert.Equal("p:p1|u:victim", victim.CachePartition);
        Assert.Equal(2, ExchangeCalls(handler));
    }

    [Fact]
    public async Task ForgedSubject_CannotPoisonVictimCacheKey()
    {
        // A token signed by the wrong key but claiming the victim's sub must fail
        // validation BEFORE keying the cache — the victim's later valid request still works.
        var (provider, _) = CreateProvider();
        var forged = IssueToken(AttackerRsa, subject: "victim");

        await AssertRejectedWith(provider, forged);

        var valid = IssueToken(IssuerRsa, subject: "victim");
        var token = await provider.GetCredentialAsync(
            ExchangeOptions(), TestSecrets.AccessorFor([]), Context(valid), default);
        Assert.Equal("down-tok", token);
    }

    private static async Task AssertRejectedWith(TokenExchangeProvider provider, string inbound)
    {
        await Assert.ThrowsAsync<InboundTokenRejectedException>(() => provider
            .GetCredentialAsync(ExchangeOptions(), TestSecrets.AccessorFor([]), Context(inbound), default)
            .AsTask());
    }

    // ---- per-user cache ----

    [Fact]
    public async Task SameUser_ServedFromCache_OneExchangeCall()
    {
        var (provider, handler) = CreateProvider();
        var inbound = IssueToken(IssuerRsa, subject: "user-A");
        var context = Context(inbound);

        Assert.Equal("down-tok", await provider.GetCredentialAsync(ExchangeOptions(), TestSecrets.AccessorFor([]), context, default));
        Assert.Equal("down-tok", await provider.GetCredentialAsync(ExchangeOptions(), TestSecrets.AccessorFor([]), context, default));

        Assert.Equal(1, ExchangeCalls(handler));
        Assert.Equal("p:p1|u:user-A", context.CachePartition);
    }

    [Fact]
    public async Task DifferentUsers_SeparateEntries_NeverCrossServed()
    {
        var responses = 0;
        var (provider, handler) = CreateProvider((req, _) => req.RequestUri!.AbsolutePath.Contains("/jwks")
            ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(JwksJson()) }
            : new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent($$"""{"access_token":"down-tok-{{Interlocked.Increment(ref responses) - 1}}","expires_in":300}"""),
            });

        var contextA = Context(IssueToken(IssuerRsa, subject: "user-A"));
        var contextB = Context(IssueToken(IssuerRsa, subject: "user-B"));

        // Interleave: A, B, A, B — each user must only ever get its own token.
        Assert.Equal("down-tok-0", await provider.GetCredentialAsync(ExchangeOptions(), TestSecrets.AccessorFor([]), contextA, default));
        Assert.Equal("down-tok-1", await provider.GetCredentialAsync(ExchangeOptions(), TestSecrets.AccessorFor([]), contextB, default));
        Assert.Equal("down-tok-0", await provider.GetCredentialAsync(ExchangeOptions(), TestSecrets.AccessorFor([]), contextA, default));
        Assert.Equal("down-tok-1", await provider.GetCredentialAsync(ExchangeOptions(), TestSecrets.AccessorFor([]), contextB, default));

        Assert.Equal(2, ExchangeCalls(handler));
        Assert.Equal("p:p1|u:user-A", contextA.CachePartition);
        Assert.Equal("p:p1|u:user-B", contextB.CachePartition);
    }

    [Fact]
    public async Task UnpartitionedCredential_CacheKeyIsSubjectOnly()
    {
        var (provider, _) = CreateProvider();
        var context = Context(IssueToken(IssuerRsa, subject: "user-A"), partition: null);

        await provider.GetCredentialAsync(ExchangeOptions(), TestSecrets.AccessorFor([]), context, default);

        Assert.Equal("u:user-A", context.CachePartition);
    }

    [Fact]
    public async Task SingleFlight_SameUser_ConcurrentRequestsOneExchange()
    {
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var exchanges = 0;
        var (provider, handler) = CreateProvider((req, _) =>
        {
            if (req.RequestUri!.AbsolutePath.Contains("/jwks"))
            {
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(JwksJson()) };
            }

            Interlocked.Increment(ref exchanges);
            gate.Task.GetAwaiter().GetResult();
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"access_token":"down-tok","expires_in":300}"""),
            };
        });

        var inbound = IssueToken(IssuerRsa, subject: "user-A");
        var tasks = Enumerable.Range(0, 50)
            .Select(_ => provider
                .GetCredentialAsync(ExchangeOptions(), TestSecrets.AccessorFor([]), Context(inbound), default)
                .AsTask())
            .ToArray();

        gate.SetResult();
        var results = await Task.WhenAll(tasks);

        Assert.All(results, r => Assert.Equal("down-tok", r));
        Assert.Equal(1, Volatile.Read(ref exchanges));
    }

    // ---- exchange failures ----

    [Fact]
    public async Task ExchangeEndpointFailure_ThrowsInvalidOperation_NamingStatusNotBody()
    {
        var (provider, _) = CreateProvider(Route(
            JwksJson(),
            """{"error":"invalid_grant","error_description":"bad assertion with secret-echo"}""",
            HttpStatusCode.BadRequest));

        var inbound = IssueToken(IssuerRsa);
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => provider
            .GetCredentialAsync(ExchangeOptions(), TestSecrets.AccessorFor([]), Context(inbound), default)
            .AsTask());

        Assert.IsNotType<InboundTokenRejectedException>(ex);
        Assert.Contains("400", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-echo", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(inbound, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MalformedTokenResponse_FailsWithoutBody()
    {
        var (provider, _) = CreateProvider(Route(JwksJson(), """{"nope":true}"""));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => provider
            .GetCredentialAsync(ExchangeOptions(), TestSecrets.AccessorFor([]), Context(IssueToken(IssuerRsa)), default)
            .AsTask());

        Assert.Contains("malformed", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MissingInboundToken_DefensiveFailure_NamingCredential()
    {
        var (provider, handler) = CreateProvider();
        var context = new CredentialRequestContext { CredentialName = "test", Partition = null };

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => provider
            .GetCredentialAsync(ExchangeOptions(), TestSecrets.AccessorFor([]), context, default)
            .AsTask());

        Assert.Contains("test", ex.Message, StringComparison.Ordinal);
        Assert.Equal(0, ExchangeCalls(handler));
    }

}
