using System.Net;
using System.Security.Cryptography;
using System.Text;
using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Logging;
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
        Func<HttpRequestMessage, int, HttpResponseMessage>? responder = null,
        FakeTimeProvider? time = null)
    {
        var handler = new StubHttpHandler(responder ?? Route(jwks: JwksJson()));
        time ??= new FakeTimeProvider();
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

    // Entra OBO (Mode=EntraObo wire shape) removed in M27 - docs/adr/0002.
    // CredentialRegistryProviderTests.RemovedEntraOboMode_FailsStartupBinding pins the
    // replacement behavior: naming the removed mode fails loudly at binding.

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

    // ---- M37 fold 2 (hardening review F1 + fold ruling): expires_in parsing is
    // culture-invariant, and a NEGATIVE value rejects like OAuth (M33 fault 7 mirrored).
    // The old double.TryParse(string, out _) overload was CurrentCulture + AllowThousands:
    // on a de-DE host "3600.9" cached ~10 h (36 009 s) and "1,000" cached 1 s, and a
    // negative silently took DefaultLifetime. M37 kept non-finite/grouped/non-numeric on the
    // fallback; M38 A moved non-finite and grouped to rejection (see the M38 section below and
    // the changed grouped pin), with non-numeric to follow under M38 B. Tests compile against
    // f34b86e and assert the base exception type only, so the RED run is the bug's own
    // behaviour, not a compile.

    [Fact]
    public async Task DecimalCommaCulture_ParsesDotAsDecimal()
    {
        using var _culture = new CultureOverride("de-DE");
        var time = new FakeTimeProvider();
        var (provider, handler) = CreateProvider(
            Route(jwks: JwksJson(), tokenBody: """{"access_token":"down-tok","expires_in":"3600.9"}"""), time);
        var inbound = IssueToken(IssuerRsa, lifetime: TimeSpan.FromHours(3));

        Assert.Equal("down-tok", await provider.GetCredentialAsync(
            ExchangeOptions(), TestSecrets.AccessorFor([]), Context(inbound), default));
        time.Advance(TimeSpan.FromMinutes(50)); // past 80 % of 3600.9 s; a 1 h default would still be cached
        await provider.GetCredentialAsync(
            ExchangeOptions(), TestSecrets.AccessorFor([]), Context(inbound), default);

        // RED at f34b86e: de-DE reads "3600.9" as 36 009 s, so the token is still cached at 50 min.
        Assert.Equal(2, ExchangeCalls(handler));
    }

    [Fact]
    public async Task DecimalCommaCulture_GroupedValueRejects()
    {
        // M38 A CHANGED this pin (it asserted "grouped keeps DefaultLifetime"): under the OAuth
        // rule the grouped value is a protocol violation now, rejecting through the
        // protocol-violation path on EVERY culture. The culture-invariance intent of the M37
        // fold-2 pin stands - what it cached never depends on the machine's culture; the answer
        // to an unparseable-without-grouping value is now uniformly "reject".
        using var _culture = new CultureOverride("de-DE");
        var time = new FakeTimeProvider();
        var (provider, handler) = CreateProvider(
            Route(jwks: JwksJson(), tokenBody: """{"access_token":"down-tok","expires_in":"1,000"}"""), time);
        var inbound = IssueToken(IssuerRsa, lifetime: TimeSpan.FromHours(3));

        var ex = await Record.ExceptionAsync(() => provider
            .GetCredentialAsync(ExchangeOptions(), TestSecrets.AccessorFor([]), Context(inbound), default)
            .AsTask());
        Assert.NotNull(ex);
        Assert.IsAssignableFrom<InvalidOperationException>(ex);
        Assert.IsNotType<InvalidOperationException>(ex);
        Assert.Contains("expires_in", ex.Message);
        Assert.DoesNotContain("1,000", ex.Message);
        Assert.DoesNotContain("malformed", ex.Message);
        Assert.Equal(1, ExchangeCalls(handler));            // rejected, nothing cached
    }

    [Fact]
    public async Task NegativeExpiresIn_RejectsResponse_CachesNothing()
    {
        var time = new FakeTimeProvider();
        var (provider, handler) = CreateProvider(
            Route(jwks: JwksJson(), tokenBody: """{"access_token":"down-tok","expires_in":-30}"""), time);
        var inbound = IssueToken(IssuerRsa, lifetime: TimeSpan.FromHours(3));

        var ex = await Record.ExceptionAsync(() => provider
            .GetCredentialAsync(ExchangeOptions(), TestSecrets.AccessorFor([]), Context(inbound), default)
            .AsTask());
        Assert.NotNull(ex);                                 // RED at f34b86e: cached for DefaultLifetime there
        Assert.IsAssignableFrom<InvalidOperationException>(ex); // the documented IdP-failure type
        Assert.IsNotType<InvalidOperationException>(ex);    // a specific rejection, not the re-wrap
        Assert.Contains("expires_in", ex.Message);          // names the field...
        Assert.Contains("test", ex.Message);                // ...and the credential id...
        Assert.DoesNotContain("down-tok", ex.Message);      // ...never the token or the value.
        Assert.DoesNotContain("-30", ex.Message);
        Assert.DoesNotContain("malformed", ex.Message);
        Assert.Equal(1, ExchangeCalls(handler));

        ex = await Record.ExceptionAsync(() => provider
            .GetCredentialAsync(ExchangeOptions(), TestSecrets.AccessorFor([]), Context(inbound), default)
            .AsTask());
        Assert.NotNull(ex);
        Assert.Equal(1, ExchangeCalls(handler));            // backoff re-throw: nothing was cached

        time.Advance(TimeSpan.FromSeconds(6));              // past NegativeCacheTtl
        Assert.NotNull(await Record.ExceptionAsync(() => provider
            .GetCredentialAsync(ExchangeOptions(), TestSecrets.AccessorFor([]), Context(inbound), default)
            .AsTask()));
        Assert.Equal(2, ExchangeCalls(handler));            // re-mints once the backoff lapses
    }

    [Fact]
    public async Task ZeroExpiresIn_KeepsDefaultLifetime()
    {
        // M33 ruling pinned for this provider (JwtAssertionProviderTests.cs:466 pins the
        // sibling): 0 means "no stated expiry" for some IdPs - DefaultLifetime, not a reject.
        var time = new FakeTimeProvider();
        var (provider, handler) = CreateProvider(
            Route(jwks: JwksJson(), tokenBody: """{"access_token":"down-tok","expires_in":"0"}"""), time);
        var inbound = IssueToken(IssuerRsa, lifetime: TimeSpan.FromHours(3));

        await provider.GetCredentialAsync(
            ExchangeOptions(), TestSecrets.AccessorFor([]), Context(inbound), default);
        time.Advance(TimeSpan.FromMinutes(30));             // inside the 1 h default, past any 0 s cache
        await provider.GetCredentialAsync(
            ExchangeOptions(), TestSecrets.AccessorFor([]), Context(inbound), default);

        Assert.Equal(1, ExchangeCalls(handler));
    }

    // ---- M38 (plan §8.6 policy row): this provider adopts OAuth's
    // rejection rule (A + B): non-finite, thousands-grouped and non-numeric `expires_in` values are
    // protocol violations on the IdP-failure path - at 3b2d758 every one of them was a NaN that
    // silently cached DefaultLifetime. C: an accepted lifetime above 24 h clamps to 24 h, and values
    // that overflow TimeSpan (1e12, 1e300 — 1e12 s = 1e19 ticks > TimeSpan.MaxTicks) clamp instead of
    // dying in the generic malformed-response re-wrap. The empty-string warning and the once-per-
    // credential clamp warnings ride the logger seam (additive 4-arg ctor) added in GREEN — they
    // cannot compile at 3b2d758, the M37 fold-2 precedent for a noted base-incompatible pin. The
    // tests below compile at 3b2d758 and assert only base types and observable caching: the RED run
    // is the bug's own behaviour, not a compile failure.

    [Theory]
    [InlineData("1e400")]         // JSON number +∞: the culture-independent non-finite route (M37 matrix)
    [InlineData("\"Infinity\"")]  // string arm, invariant parse: +∞ (TE already parses invariant)
    [InlineData("\"1e400\"")]
    public async Task M38_NonFiniteExpiresIn_RejectsResponse_CachesNothing(string json)
    {
        var time = new FakeTimeProvider();
        var (provider, handler) = CreateProvider(
            Route(jwks: JwksJson(), tokenBody: $$"""{"access_token":"down-tok","expires_in":{{json}}}"""), time);
        var inbound = IssueToken(IssuerRsa, lifetime: TimeSpan.FromHours(3));

        var ex = await Record.ExceptionAsync(() => provider
            .GetCredentialAsync(ExchangeOptions(), TestSecrets.AccessorFor([]), Context(inbound), default)
            .AsTask());
        Assert.NotNull(ex);                                 // RED at 3b2d758: NaN silently cached DefaultLifetime
        Assert.IsAssignableFrom<InvalidOperationException>(ex); // the documented IdP-failure type
        Assert.IsNotType<InvalidOperationException>(ex);    // a specific rejection, not the re-wrap
        Assert.Contains("expires_in", ex.Message);          // names the field...
        Assert.Contains("test", ex.Message);                // ...and the credential id...
        Assert.DoesNotContain("down-tok", ex.Message);      // ...never the token or the value.
        Assert.DoesNotContain("Infinity", ex.Message);
        Assert.DoesNotContain("1e400", ex.Message);
        Assert.DoesNotContain("malformed", ex.Message);     // the documented rejection, not the re-wrap
        Assert.Equal(1, ExchangeCalls(handler));

        ex = await Record.ExceptionAsync(() => provider
            .GetCredentialAsync(ExchangeOptions(), TestSecrets.AccessorFor([]), Context(inbound), default)
            .AsTask());
        Assert.NotNull(ex);
        Assert.Equal(1, ExchangeCalls(handler));            // backoff re-throw: nothing was cached

        time.Advance(TimeSpan.FromSeconds(6));              // past NegativeCacheTtl
        Assert.NotNull(await Record.ExceptionAsync(() => provider
            .GetCredentialAsync(ExchangeOptions(), TestSecrets.AccessorFor([]), Context(inbound), default)
            .AsTask()));
        Assert.Equal(2, ExchangeCalls(handler));            // re-mints once the backoff lapses
    }

    [Fact]
    public async Task M38_GroupedExpiresIn_RejectsResponse_CachesNothing()
    {
        // A: "1,000" is only parseable via thousands grouping (invariant Float already rejects it);
        // accepting it would make the cached lifetime culture-dependent — OAuth's M37 A1 ruling now
        // applies here too. RED at 3b2d758: the unparseable value silently cached DefaultLifetime.
        var time = new FakeTimeProvider();
        var (provider, handler) = CreateProvider(
            Route(jwks: JwksJson(), tokenBody: """{"access_token":"down-tok","expires_in":"1,000"}"""), time);
        var inbound = IssueToken(IssuerRsa, lifetime: TimeSpan.FromHours(3));

        var ex = await Record.ExceptionAsync(() => provider
            .GetCredentialAsync(ExchangeOptions(), TestSecrets.AccessorFor([]), Context(inbound), default)
            .AsTask());
        Assert.NotNull(ex);
        Assert.IsAssignableFrom<InvalidOperationException>(ex);
        Assert.IsNotType<InvalidOperationException>(ex);
        Assert.Contains("expires_in", ex.Message);
        Assert.Contains("test", ex.Message);
        Assert.DoesNotContain("down-tok", ex.Message);
        Assert.DoesNotContain("1,000", ex.Message);
        Assert.DoesNotContain("malformed", ex.Message);
        Assert.Equal(1, ExchangeCalls(handler));
    }

    [Theory]
    [InlineData("\"abc\"")]
    [InlineData("\"0x10\"")]
    [InlineData("\"١٢٣\"")]      // non-ASCII digits: not the JSON number grammar
    public async Task M38_NonNumericStringExpiresIn_RejectsResponse_CachesNothing(string json)
    {
        // B: a value unmistakably not in the JSON number grammar rejects (M38 ruling) instead of
        // the 3b2d758 silent DefaultLifetime. The empty string is NOT here — it is absent-with-
        // warning (its once-per-credential warning test rides the GREEN logger seam).
        var time = new FakeTimeProvider();
        var (provider, handler) = CreateProvider(
            Route(jwks: JwksJson(), tokenBody: $$"""{"access_token":"down-tok","expires_in":{{json}}}"""), time);
        var inbound = IssueToken(IssuerRsa, lifetime: TimeSpan.FromHours(3));

        var ex = await Record.ExceptionAsync(() => provider
            .GetCredentialAsync(ExchangeOptions(), TestSecrets.AccessorFor([]), Context(inbound), default)
            .AsTask());
        Assert.NotNull(ex);                                 // RED at 3b2d758: silent DefaultLifetime
        Assert.IsAssignableFrom<InvalidOperationException>(ex);
        Assert.IsNotType<InvalidOperationException>(ex);
        Assert.Contains("expires_in", ex.Message);
        Assert.Contains("test", ex.Message);
        Assert.DoesNotContain("down-tok", ex.Message);
        Assert.DoesNotContain(json.Trim('"'), ex.Message);  // never the value
        Assert.DoesNotContain("malformed", ex.Message);
        Assert.Equal(1, ExchangeCalls(handler));
    }

    [Fact]
    public async Task M38_LifetimeAboveOneDay_ClampedTo24h()
    {
        // C: 48 h is a valid finite lifetime; the cap clamps it to 24 h, so the cache refreshes on
        // the 24 h clock (80 % is 19.2 h). RED at 3b2d758: 48 h caches and stays served at +20 h.
        var time = new FakeTimeProvider();
        var (provider, handler) = CreateProvider(
            Route(jwks: JwksJson(), tokenBody: """{"access_token":"down-tok","expires_in":172800}"""), time);
        var inbound = IssueToken(IssuerRsa, lifetime: TimeSpan.FromHours(30));

        Assert.Equal("down-tok", await provider
            .GetCredentialAsync(ExchangeOptions(), TestSecrets.AccessorFor([]), Context(inbound), default));
        time.Advance(TimeSpan.FromHours(20));               // past 80 % of 24 h, below 80 % of 48 h
        Assert.Equal("down-tok", await provider
            .GetCredentialAsync(ExchangeOptions(), TestSecrets.AccessorFor([]), Context(inbound), default));

        Assert.Equal(2, ExchangeCalls(handler));
    }

    [Theory]
    [InlineData("1e12")]   // 1e12 s = 1e19 ticks > TimeSpan.MaxTicks: OverflowException today
    [InlineData("1e300")]
    public async Task M38_TimeSpanOverflow_ClampedNotMalformed(string json)
    {
        // C: TimeSpan-overflowing lifetimes clamp to 24 h with a warning — RED at 3b2d758: they die
        // in the generic "malformed token response" re-wrap (the inconsistency plan §8.6 names).
        var time = new FakeTimeProvider();
        var (provider, handler) = CreateProvider(
            Route(jwks: JwksJson(), tokenBody: $$"""{"access_token":"down-tok","expires_in":{{json}}}"""), time);
        var inbound = IssueToken(IssuerRsa, lifetime: TimeSpan.FromHours(30));

        // GREEN: the token is served and cached on the clamped 24 h clock, no error at all.
        Assert.Equal("down-tok", await provider
            .GetCredentialAsync(ExchangeOptions(), TestSecrets.AccessorFor([]), Context(inbound), default));
        time.Advance(TimeSpan.FromHours(20));               // past the clamped refresh point
        Assert.Equal("down-tok", await provider
            .GetCredentialAsync(ExchangeOptions(), TestSecrets.AccessorFor([]), Context(inbound), default));

        Assert.Equal(2, ExchangeCalls(handler));
    }

    [Fact]
    public async Task M38_EmptyStringExpiresIn_FallsBackWithOneWarning()
    {
        // B boundary: "" is present-but-empty = absent -> DefaultLifetime WITH one warning per
        // credential (two mints here via the 80 % refresh, one notice total — the OAuth
        // zero-lifetime rule mirrored). Added WITH outcome B: the warning needs the additive
        // 4-arg logger ctor, so this pin cannot compile at 3b2d758 (M37 fold-2 precedent —
        // base-incompatible warning pins, noted on the row).
        var time = new FakeTimeProvider();
        var handler = new StubHttpHandler(Route(jwks: JwksJson(),
            tokenBody: """{"access_token":"down-tok","expires_in":""}"""));
        var logger = new CollectingLogger();
        var cache = new InMemoryTokenCache(Options.Create(new TokenCacheOptions()), time);
        var provider = new TokenExchangeProvider(cache, new StubHttpClientFactory(handler), time, logger);
        var inbound = IssueToken(IssuerRsa, lifetime: TimeSpan.FromHours(3));

        Assert.Equal("down-tok", await provider
            .GetCredentialAsync(ExchangeOptions(), TestSecrets.AccessorFor([]), Context(inbound), default));
        time.Advance(TimeSpan.FromMinutes(50));             // past 80 % of the 1 h default -> second mint
        Assert.Equal("down-tok", await provider
            .GetCredentialAsync(ExchangeOptions(), TestSecrets.AccessorFor([]), Context(inbound), default));
        Assert.Equal(2, ExchangeCalls(handler));            // the fallback clock, twice

        Assert.Single(logger.Messages, static m => m.Contains("expires_in")); // one notice across mints
        Assert.DoesNotContain("down-tok", logger.Messages.Single(m => m.Contains("expires_in")));
    }

    private sealed class CollectingLogger : ILogger<TokenExchangeProvider>
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
