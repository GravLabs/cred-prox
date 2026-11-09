using System.Net;
using System.Text;
using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// §5.2 "OAuth client credentials" row: Basic-header vs form-body client authentication,
/// scope and audience on the form, <c>expires_in</c> honored with a default fallback,
/// per-credential caching, and failures that never leak secrets or bodies.
/// </summary>
public sealed class OAuthClientCredentialsProviderTests
{
    private const string ClientIdValue = "client-id-value";
    private const string ClientSecretValue = "client-secret-value";

    private static CredentialRequestContext Context(string? partition = "p1") =>
        new() { CredentialName = "test", Partition = partition };

    private static (OAuthClientCredentialsProvider Provider, StubHttpHandler Handler) CreateProvider(
        StubHttpHandler handler,
        FakeTimeProvider? time = null)
    {
        time ??= new FakeTimeProvider();
        var cache = new InMemoryTokenCache(Options.Create(new TokenCacheOptions()), time);
        var provider = new OAuthClientCredentialsProvider(cache, new StubHttpClientFactory(handler), time);
        return (provider, handler);
    }

    private static ISecretAccessor Secrets() => TestSecrets.AccessorFor(
        new()
        {
            ["ClientId"] = "secret:cid",
            ["ClientSecret"] = "secret:csec",
        },
        new()
        {
            ["cid"] = ClientIdValue,
            ["csec"] = ClientSecretValue,
        });

    private static OAuthClientCredentialsOptions OAuthOptions(OAuthClientAuthentication auth) => new()
    {
        TokenEndpoint = "https://vendor.example/token",
        ClientAuthentication = auth,
        ClientId = "secret:cid",
        ClientSecret = "secret:csec",
    };

    [Fact]
    public async Task BasicHeader_SendsBasicAuthAndClientCredentialsForm()
    {
        var (provider, handler) = CreateProvider(
            new StubHttpHandler(HttpStatusCode.OK, """{"access_token":"tok-1","expires_in":3600}"""));

        var token = await provider.GetCredentialAsync(
            OAuthOptions(OAuthClientAuthentication.BasicHeader), Secrets(), Context(), default);

        Assert.Equal("tok-1", token);
        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal("https://vendor.example/token", request.RequestUri!.ToString());

        var expected = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{ClientIdValue}:{ClientSecretValue}"));
        Assert.Equal("Basic", request.Headers.Authorization!.Scheme);
        Assert.Equal(expected, request.Headers.Authorization.Parameter);

        var form = ParseForm(handler.Body(0)!);
        Assert.Equal("client_credentials", form["grant_type"]);
        Assert.False(form.ContainsKey("client_id"));
    }

    [Fact]
    public async Task FormPost_SendsCredentialsInTheForm()
    {
        var (provider, handler) = CreateProvider(
            new StubHttpHandler(HttpStatusCode.OK, """{"access_token":"tok-1"}"""));

        await provider.GetCredentialAsync(
            OAuthOptions(OAuthClientAuthentication.FormPost), Secrets(), Context(), default);

        var request = Assert.Single(handler.Requests);
        Assert.Null(request.Headers.Authorization);
        var form = ParseForm(handler.Body(0)!);
        Assert.Equal(ClientIdValue, form["client_id"]);
        Assert.Equal(ClientSecretValue, form["client_secret"]);
    }

    [Fact]
    public async Task ScopeAndAudience_AreSentOnTheForm()
    {
        var (provider, handler) = CreateProvider(
            new StubHttpHandler(HttpStatusCode.OK, """{"access_token":"tok-1"}"""));

        var options = OAuthOptions(OAuthClientAuthentication.BasicHeader);
        options.Scope = "api offline";
        options.Audience = "https://api.example";

        await provider.GetCredentialAsync(options, Secrets(), Context(), default);

        var form = ParseForm(handler.Body(0)!);
        Assert.Equal("api offline", form["scope"]);
        Assert.Equal("https://api.example", form["audience"]);
    }

    [Fact]
    public async Task ExpiresIn_IsHonoredAsStringAndNumber()
    {
        var time = new FakeTimeProvider();
        var (provider, handler) = CreateProvider(
            new StubHttpHandler(HttpStatusCode.OK, """{"access_token":"tok-1","expires_in":"120"}"""), time);

        Assert.Equal("tok-1", await provider.GetCredentialAsync(OAuthOptions(OAuthClientAuthentication.BasicHeader), Secrets(), Context(), default));

        // Served while now < min(started + 0.8×120s, started + 120s − 30s skew) = started + 90s.
        time.Advance(TimeSpan.FromSeconds(60));
        Assert.Equal("tok-1", await provider.GetCredentialAsync(OAuthOptions(OAuthClientAuthentication.BasicHeader), Secrets(), Context(), default));
        Assert.Single(handler.Requests); // still cached

        time.Advance(TimeSpan.FromSeconds(31));
        Assert.Equal("tok-1", await provider.GetCredentialAsync(OAuthOptions(OAuthClientAuthentication.BasicHeader), Secrets(), Context(), default));
        Assert.Equal(2, handler.Requests.Count); // expired, refetched
    }

    [Fact]
    public async Task MissingExpiresIn_UsesDefaultLifetime()
    {
        var time = new FakeTimeProvider();
        var (provider, handler) = CreateProvider(
            new StubHttpHandler(HttpStatusCode.OK, """{"access_token":"tok-1"}"""), time);

        var options = OAuthOptions(OAuthClientAuthentication.BasicHeader);
        options.DefaultLifetime = TimeSpan.FromMinutes(10);

        Assert.Equal("tok-1", await provider.GetCredentialAsync(options, Secrets(), Context(), default));

        // Served while now < min(started + 0.8×10min, started + 10min − 30s skew) = started + 8min.
        time.Advance(TimeSpan.FromMinutes(7));
        await provider.GetCredentialAsync(options, Secrets(), Context(), default);
        Assert.Single(handler.Requests);

        time.Advance(TimeSpan.FromMinutes(2));
        await provider.GetCredentialAsync(options, Secrets(), Context(), default);
        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task ConcurrentCalls_ShareOneFetch()
    {
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var (provider, handler) = CreateProvider(new StubHttpHandler((_, _) =>
        {
            gate.Task.GetAwaiter().GetResult();
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("""{"access_token":"tok-1"}""") };
        }));

        var first = provider.GetCredentialAsync(OAuthOptions(OAuthClientAuthentication.BasicHeader), Secrets(), Context(), default).AsTask();
        var second = provider.GetCredentialAsync(OAuthOptions(OAuthClientAuthentication.BasicHeader), Secrets(), Context(), default).AsTask();
        gate.SetResult();

        Assert.Equal("tok-1", await first);
        Assert.Equal("tok-1", await second);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task DifferentPartitions_GetSeparateCacheEntries()
    {
        var (provider, handler) = CreateProvider(new StubHttpHandler((_, index) =>
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent($$"""{"access_token":"tok-{{index}}"}""") }));

        var options = OAuthOptions(OAuthClientAuthentication.BasicHeader);
        Assert.Equal("tok-0", await provider.GetCredentialAsync(options, Secrets(), Context("p1"), default));
        Assert.Equal("tok-1", await provider.GetCredentialAsync(options, Secrets(), Context("p2"), default));
        Assert.Equal("tok-0", await provider.GetCredentialAsync(options, Secrets(), Context("p1"), default));
        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task NonSuccessStatus_FailsWithoutLeakingSecrets()
    {
        var (provider, _) = CreateProvider(new StubHttpHandler(HttpStatusCode.Unauthorized, "invalid_client"));

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetCredentialAsync(OAuthOptions(OAuthClientAuthentication.BasicHeader), Secrets(), Context(), default).AsTask());

        Assert.Contains("test", error.Message);
        Assert.Contains("401", error.Message);
        Assert.DoesNotContain(ClientSecretValue, error.Message);
        Assert.DoesNotContain("invalid_client", error.Message);
    }

    [Fact]
    public async Task MalformedTokenBody_FailsWithoutLeakingTheBody()
    {
        var (provider, _) = CreateProvider(new StubHttpHandler(HttpStatusCode.OK, """{"note":"no token here, secret echo: leaky"}"""));

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetCredentialAsync(OAuthOptions(OAuthClientAuthentication.BasicHeader), Secrets(), Context(), default).AsTask());

        Assert.Contains("malformed", error.Message);
        Assert.DoesNotContain("leaky", error.Message);
    }

    [Fact]
    public async Task LiteralClientCredentials_AreUsedAsIs()
    {
        var (provider, handler) = CreateProvider(
            new StubHttpHandler(HttpStatusCode.OK, """{"access_token":"tok-1"}"""));

        var options = OAuthOptions(OAuthClientAuthentication.BasicHeader);
        options.ClientId = "plain-id";
        options.ClientSecret = "plain-secret";

        await provider.GetCredentialAsync(options, TestSecrets.AccessorFor(new()), Context(), default);

        var expected = Convert.ToBase64String(Encoding.UTF8.GetBytes("plain-id:plain-secret"));
        Assert.Equal(expected, handler.Requests[0].Headers.Authorization!.Parameter);
    }

    // ---- {partition} templates (M7, E7 prerequisite) -----------------------------------

    private static OAuthClientCredentialsOptions TemplatedOptions() => new()
    {
        TokenEndpoint = "https://vendor.example/{partition}/token",
        ClientAuthentication = OAuthClientAuthentication.FormPost,
        ClientId = "credprox-{partition}",
        ClientSecret = "secret:{partition}-csec",
    };

    private static ISecretAccessor TemplatedSecrets() => TestSecrets.AccessorFor(
        new()
        {
            ["TokenEndpoint"] = "https://vendor.example/{partition}/token",
            ["ClientId"] = "credprox-{partition}",
            ["ClientSecret"] = "secret:{partition}-csec",
        },
        new()
        {
            ["app-a-csec"] = "secret-app-a",
            ["app-b-csec"] = "secret-app-b",
        });

    [Fact]
    public async Task PartitionTemplates_ExpandInEndpointClientIdAndSecret()
    {
        var (provider, handler) = CreateProvider(
            new StubHttpHandler(HttpStatusCode.OK, """{"access_token":"tok-1"}"""));

        await provider.GetCredentialAsync(TemplatedOptions(), TemplatedSecrets(), Context("app-a"), default);

        var request = Assert.Single(handler.Requests);
        Assert.Equal("https://vendor.example/app-a/token", request.RequestUri!.ToString());
        var form = ParseForm(handler.Body(0)!);
        Assert.Equal("credprox-app-a", form["client_id"]);
        Assert.Equal("secret-app-a", form["client_secret"]);
    }

    [Fact]
    public async Task PartitionTemplates_PerPartitionCacheEntries()
    {
        var (provider, handler) = CreateProvider(
            new StubHttpHandler(HttpStatusCode.OK, """{"access_token":"tok-1"}"""));
        var options = TemplatedOptions();
        var secrets = TemplatedSecrets();

        await provider.GetCredentialAsync(options, secrets, Context("app-a"), default);
        await provider.GetCredentialAsync(options, secrets, Context("app-a"), default); // served from cache
        await provider.GetCredentialAsync(options, secrets, Context("app-b"), default);

        Assert.Equal(2, handler.Requests.Count);
        Assert.Contains("/app-a/token", handler.Requests[0].RequestUri!.ToString(), StringComparison.Ordinal);
        Assert.Contains("/app-b/token", handler.Requests[1].RequestUri!.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task PartitionTemplate_WithoutPartitionValue_FailsBeforeAnyRequest()
    {
        var (provider, handler) = CreateProvider(
            new StubHttpHandler(HttpStatusCode.OK, """{"access_token":"tok-1"}"""));

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetCredentialAsync(TemplatedOptions(), TemplatedSecrets(), Context(null), default).AsTask());

        Assert.Contains("{partition}", error.Message, StringComparison.Ordinal);
        Assert.Empty(handler.Requests);
    }

    // --- M31 mutation triage: Type identity and the null-argument guards had no
    // assertion, and the expires_in comparator mutants (accept 0, accept unparseable)
    // survived because no test pinned what an unusable expires_in must do: fall back
    // to the default lifetime — never a zero-lived or crashing cache entry. ---

    [Fact]
    public void Type_IsOAuthClientCredentials()
    {
        var (provider, _) = CreateProvider(new StubHttpHandler(HttpStatusCode.OK, "{}"));

        Assert.Equal("OAuthClientCredentials", provider.Type);
    }

    [Fact]
    public async Task NullOptions_Throws_NamingOptions()
    {
        var (provider, _) = CreateProvider(new StubHttpHandler(HttpStatusCode.OK, "{}"));

        var ex = await Assert.ThrowsAsync<ArgumentNullException>(() =>
            provider.GetCredentialAsync(null!, Secrets(), Context(), default).AsTask());

        Assert.Equal("options", ex.ParamName);
    }

    [Fact]
    public async Task NullSecrets_Throws_NamingSecrets()
    {
        var (provider, _) = CreateProvider(new StubHttpHandler(HttpStatusCode.OK, "{}"));

        var ex = await Assert.ThrowsAsync<ArgumentNullException>(() =>
            provider.GetCredentialAsync(OAuthOptions(OAuthClientAuthentication.BasicHeader), null!, Context(), default).AsTask());

        Assert.Equal("secrets", ex.ParamName);
    }

    [Fact]
    public async Task NullContext_Throws_NamingContext()
    {
        var (provider, _) = CreateProvider(new StubHttpHandler(HttpStatusCode.OK, "{}"));

        var ex = await Assert.ThrowsAsync<ArgumentNullException>(() =>
            provider.GetCredentialAsync(OAuthOptions(OAuthClientAuthentication.BasicHeader), Secrets(), null!, default).AsTask());

        Assert.Equal("context", ex.ParamName);
    }

    [Theory]
    [InlineData("0")]        // number zero: "no stated expiry" -> default lifetime (M33 design decision keeps this)
    [InlineData("\"0\"")]    // string zero, same rule through the string arm
    [InlineData("\"soon\"")] // unparseable
    [InlineData("null")]     // JSON null reaches neither arm
    public async Task UnusableExpiresIn_FallsBackToDefaultLifetime_AndIsCached(string json)
    {
        // The boundary mutants (seconds >= 0, IsFinite || seconds > 0, always-true) all
        // store a zero/throwing lifetime here: the second call would re-fetch (or the first
        // would crash) instead of hitting the cache. Negative expires_in is NOT in this row
        // since 0.9.x: a negative lifetime is a protocol violation and REJECTS the response
        // (M33 fault 7) - pinned by NegativeExpiresIn_RejectsResponse_CachesNothing below.
        var (provider, handler) = CreateProvider(new StubHttpHandler(
            HttpStatusCode.OK, $$"""{"access_token":"tok-1","expires_in":{{json}}}"""));

        var options = OAuthOptions(OAuthClientAuthentication.BasicHeader);
        var token = await provider.GetCredentialAsync(options, Secrets(), Context(), default);
        var again = await provider.GetCredentialAsync(options, Secrets(), Context(), default);

        Assert.Equal("tok-1", token);
        Assert.Equal("tok-1", again);
        Assert.Single(handler.Requests);
    }

    // --- M33 fault 7 (design decision 2026-11-09): negative expires_in must REJECT, never cache ---

    [Theory]
    [InlineData("-5")]      // negative number
    [InlineData("\"-30\"")] // negative numeric string goes through the string arm
    public async Task NegativeExpiresIn_RejectsResponse_CachesNothing(string json)
    {
        // 0.9.0 mapped ANY non-positive expires_in to DefaultLifetime (1 h): the past-expiry
        // token was cached and served for an hour against a real vendor. Negative is now a
        // protocol violation: the mint fails through the documented IdP-failure path and no
        // TOKEN is cached - the rejected body is never re-served. The shared backoff
        // (NegativeCacheTtl, 5 s default) then re-throws without a vendor hit inside the
        // window (the "no new mint-storm class" property from fault 1b) and mints fresh
        // once it lapses.
        var time = new FakeTimeProvider();
        var (provider, handler) = CreateProvider(new StubHttpHandler(
            HttpStatusCode.OK, $$"""{"access_token":"tok-1","expires_in":{{json}}}"""), time);

        var options = OAuthOptions(OAuthClientAuthentication.BasicHeader);

        var ex = await Assert.ThrowsAsync<OAuthClientCredentialsProvider.NegativeExpiresInRejectedException>(() =>
            provider.GetCredentialAsync(options, Secrets(), Context(), default).AsTask());
        Assert.IsAssignableFrom<InvalidOperationException>(ex); // the documented IdP-failure type
        Assert.Contains("expires_in", ex.Message);
        Assert.Contains("test", ex.Message);          // names the credential id...
        Assert.DoesNotContain("tok-1", ex.Message);   // ...never the token or the value.
        Assert.DoesNotContain("-5", ex.Message);
        Assert.DoesNotContain("-30", ex.Message);
        Assert.Single(handler.Requests);

        await Assert.ThrowsAsync<OAuthClientCredentialsProvider.NegativeExpiresInRejectedException>(() =>
            provider.GetCredentialAsync(options, Secrets(), Context(), default).AsTask());
        Assert.Single(handler.Requests);              // backoff re-throw: no vendor hammering

        time.SetUtcNow(time.GetUtcNow() + TimeSpan.FromSeconds(6)); // past NegativeCacheTtl
        await Assert.ThrowsAsync<OAuthClientCredentialsProvider.NegativeExpiresInRejectedException>(() =>
            provider.GetCredentialAsync(options, Secrets(), Context(), default).AsTask());
        Assert.Equal(2, handler.Requests.Count);      // re-mints once the backoff lapses
    }

    [Theory]
    [InlineData("0")]
    [InlineData("\"0\"")]
    public async Task ZeroExpiresIn_FallsBack_LogsOncePerCredential(string json)
    {
        // Zero keeps the 1 h fallback (some IdPs mean "no stated expiry"), but earns one
        // warning per credential - three mints of the same credential log exactly once.
        var time = new FakeTimeProvider();
        var handler = new StubHttpHandler(
            HttpStatusCode.OK, $$"""{"access_token":"tok-1","expires_in":{{json}}}""");
        var logger = new CollectingLogger();
        var cache = new InMemoryTokenCache(Options.Create(new TokenCacheOptions()), time);
        var provider = new OAuthClientCredentialsProvider(
            cache, new StubHttpClientFactory(handler), time, logger);

        var options = OAuthOptions(OAuthClientAuthentication.BasicHeader);
        for (var i = 0; i < 3; i++)
        {
            Assert.Equal("tok-1", await provider.GetCredentialAsync(options, Secrets(), Context(), default));
        }

        Assert.Single(handler.Requests); // cached on the default lifetime
        var warning = Assert.Single(logger.Messages);
        Assert.Contains("expires_in", warning);
        Assert.Contains("test", warning);
        Assert.DoesNotContain("tok-1", warning);
    }

    [Fact]
    public async Task OneSecondExpiresIn_RefreshesOnSchedule()
    {
        // Small positives must NOT be swallowed into the 1 h fallback: expiry is honoured
        // (fault 7's mint-collapse witness is the inverse of this).
        var time = new FakeTimeProvider();
        var (provider, handler) = CreateProvider(new StubHttpHandler(
            HttpStatusCode.OK, """{"access_token":"tok-1","expires_in":1}"""), time);

        // (The cache's expiry-skew is far larger than 1 s, so a hit inside the window is
        // already a refresh-attempt path; what MUST hold is that the 1 s token is not
        // stretched: past expiry the very next call re-mints.)
        var options = OAuthOptions(OAuthClientAuthentication.BasicHeader);
        Assert.Equal("tok-1", await provider.GetCredentialAsync(options, Secrets(), Context(), default));
        Assert.Single(handler.Requests);

        time.SetUtcNow(time.GetUtcNow() + TimeSpan.FromSeconds(2));
        Assert.Equal("tok-1", await provider.GetCredentialAsync(options, Secrets(), Context(), default));
        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task AbsentAndGarbageExpiresIn_KeepDefaultLifetimeFallback()
    {
        // Explicitly pinned beside the negative rows: only NEGATIVE changes behaviour.
        foreach (var body in new[]
        {
            """{"access_token":"tok-1"}""",
            """{"access_token":"tok-1","expires_in":"garbage"}""",
        })
        {
            var (provider, handler) = CreateProvider(new StubHttpHandler(HttpStatusCode.OK, body));
            var options = OAuthOptions(OAuthClientAuthentication.BasicHeader);

            Assert.Equal("tok-1", await provider.GetCredentialAsync(options, Secrets(), Context(), default));
            Assert.Equal("tok-1", await provider.GetCredentialAsync(options, Secrets(), Context(), default));
            Assert.Single(handler.Requests); // cached for DefaultLifetime, not re-minted
        }
    }

    private sealed class CollectingLogger : ILogger<OAuthClientCredentialsProvider>
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

    private static Dictionary<string, string> ParseForm(string body) =>
        body.Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(pair => pair.Split('=', 2))
            .ToDictionary(
                parts => System.Web.HttpUtility.UrlDecode(parts[0]),
                parts => System.Web.HttpUtility.UrlDecode(parts.Length > 1 ? parts[1] : string.Empty));
}
