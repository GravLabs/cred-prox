using System.Net;
using System.Text;
using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// §5.2 "Login exchange" row: GET/POST, Basic/Form credentials, token read from raw body,
/// JSON path, header or cookie; endpoint and credentials are templates expanded per request,
/// so per-partition secrets resolve correctly and cache entries stay separate.
/// </summary>
public sealed class LoginExchangeProviderTests
{
    private static CredentialRequestContext Context(string? partition = "uat") =>
        new() { CredentialName = "acme", Partition = partition };

    private static (LoginExchangeProvider Provider, StubHttpHandler Handler) Create(
        StubHttpHandler handler)
    {
        var cache = new InMemoryTokenCache(Options.Create(new TokenCacheOptions()), new FakeTimeProvider());
        return (new LoginExchangeProvider(cache, new StubHttpClientFactory(handler), new FakeTimeProvider()), handler);
    }

    private static ISecretAccessor AcmeSecrets() => TestSecrets.AccessorFor(
        new()
        {
            ["LoginEndpoint"] = "https://acme.example/{partition}/login",
            ["Basic:User"] = "secret:acme-{partition}-user",
            ["Basic:Password"] = "secret:acme-{partition}-pass",
        },
        new()
        {
            ["acme-uat-user"] = "uat-user",
            ["acme-uat-pass"] = "uat-pass",
            ["acme-prod-user"] = "prod-user",
            ["acme-prod-pass"] = "prod-pass",
        });

    private static LoginExchangeOptions AcmeOptions() => new()
    {
        LoginEndpoint = "https://acme.example/{partition}/login",
        Basic = new LoginExchangeCredentials
        {
            User = "secret:acme-{partition}-user",
            Password = "secret:acme-{partition}-pass",
        },
    };

    [Fact]
    public async Task Get_BasicAuth_ExpandsPartitionAndReadsRawBody()
    {
        var (provider, handler) = Create(new StubHttpHandler(HttpStatusCode.OK, "  token-abc  "));

        var token = await provider.GetCredentialAsync(AcmeOptions(), AcmeSecrets(), Context(), default);

        Assert.Equal("token-abc", token);
        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal("https://acme.example/uat/login", request.RequestUri!.ToString());
        var expected = Convert.ToBase64String(Encoding.UTF8.GetBytes("uat-user:uat-pass"));
        Assert.Equal(expected, request.Headers.Authorization!.Parameter);
        Assert.Null(handler.Body(0));
    }

    [Fact]
    public async Task Post_Form_SendsExpandedCredentialsAsFields()
    {
        var (provider, handler) = Create(new StubHttpHandler(HttpStatusCode.OK, "token-abc"));

        var options = AcmeOptions();
        options.Basic = null;
        options.Method = "POST";
        options.Form = new LoginExchangeCredentials
        {
            User = "secret:acme-{partition}-user",
            Password = "secret:acme-{partition}-pass",
        };

        await provider.GetCredentialAsync(options, AcmeSecrets(), Context(), default);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Null(request.Headers.Authorization);
        Assert.Contains("user=uat-user", handler.Body(0));
        Assert.Contains("password=uat-pass", handler.Body(0));
    }

    [Fact]
    public async Task JsonPath_ReadsNestedString()
    {
        var (provider, _) = Create(new StubHttpHandler(
            HttpStatusCode.OK, """{"token":{"value":"json-token"},"expires":123}"""));

        var options = new LoginExchangeOptions
        {
            LoginEndpoint = "https://vendor.example/login",
            Response = LoginExchangeResponse.JsonPath,
            ResponseField = "token.value",
        };

        Assert.Equal("json-token", await provider.GetCredentialAsync(
            options, TestSecrets.AccessorFor(new()), Context(), default));
    }

    [Fact]
    public async Task JsonPath_MissingPath_Fails()
    {
        var (provider, _) = Create(new StubHttpHandler(HttpStatusCode.OK, """{"other":"x"}"""));

        var options = new LoginExchangeOptions
        {
            LoginEndpoint = "https://vendor.example/login",
            Response = LoginExchangeResponse.JsonPath,
            ResponseField = "token.value",
        };

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetCredentialAsync(options, TestSecrets.AccessorFor(new()), Context(), default).AsTask());
        Assert.Contains("token.value", error.Message);
    }

    [Fact]
    public async Task Header_ReadsResponseHeader()
    {
        var (provider, _) = Create(new StubHttpHandler((_, _) =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK);
            response.Headers.TryAddWithoutValidation("X-Auth-Token", "header-token");
            return response;
        }));

        var options = new LoginExchangeOptions
        {
            LoginEndpoint = "https://vendor.example/login",
            Response = LoginExchangeResponse.Header,
            ResponseField = "X-Auth-Token",
        };

        Assert.Equal("header-token", await provider.GetCredentialAsync(
            options, TestSecrets.AccessorFor(new()), Context(), default));
    }

    [Fact]
    public async Task Cookie_ReadsNamedCookieFromSetCookie()
    {
        var (provider, _) = Create(new StubHttpHandler((_, _) =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("ignored") };
            response.Headers.TryAddWithoutValidation("Set-Cookie", "other=nope; Path=/");
            response.Headers.TryAddWithoutValidation("Set-Cookie", "session=cookie-token; Path=/; HttpOnly");
            return response;
        }));

        var options = new LoginExchangeOptions
        {
            LoginEndpoint = "https://vendor.example/login",
            Response = LoginExchangeResponse.Cookie,
            ResponseField = "session",
        };

        Assert.Equal("cookie-token", await provider.GetCredentialAsync(
            options, TestSecrets.AccessorFor(new()), Context(), default));
    }

    [Fact]
    public async Task PerPartitionSecrets_UseSeparateCacheEntriesAndSecrets()
    {
        var (provider, handler) = Create(new StubHttpHandler((_, index) =>
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent($"token-{index}") }));

        var options = AcmeOptions();
        Assert.Equal("token-0", await provider.GetCredentialAsync(options, AcmeSecrets(), Context("uat"), default));
        Assert.Equal("token-1", await provider.GetCredentialAsync(options, AcmeSecrets(), Context("prod"), default));
        Assert.Equal("token-0", await provider.GetCredentialAsync(options, AcmeSecrets(), Context("uat"), default));
        Assert.Equal(2, handler.Requests.Count);

        Assert.Equal("https://acme.example/uat/login", handler.Requests[0].RequestUri!.ToString());
        Assert.Equal("https://acme.example/prod/login", handler.Requests[1].RequestUri!.ToString());
        var uatPair = Encoding.UTF8.GetString(Convert.FromBase64String(handler.Requests[0].Headers.Authorization!.Parameter!));
        var prodPair = Encoding.UTF8.GetString(Convert.FromBase64String(handler.Requests[1].Headers.Authorization!.Parameter!));
        Assert.Equal("uat-user:uat-pass", uatPair);
        Assert.Equal("prod-user:prod-pass", prodPair);
    }

    [Fact]
    public async Task PartitionTemplate_WithoutPartitionValue_Fails()
    {
        var (provider, _) = Create(new StubHttpHandler(HttpStatusCode.OK, "token"));

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetCredentialAsync(AcmeOptions(), AcmeSecrets(), Context(null), default).AsTask());

        Assert.Contains("{partition}", error.Message);
    }

    [Fact]
    public async Task NonSuccessStatus_FailsWithoutLeakingSecrets()
    {
        var (provider, _) = Create(new StubHttpHandler(HttpStatusCode.Forbidden, "login denied"));

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetCredentialAsync(AcmeOptions(), AcmeSecrets(), Context(), default).AsTask());

        Assert.Contains("acme", error.Message);
        Assert.Contains("403", error.Message);
        Assert.DoesNotContain("uat-pass", error.Message);
        Assert.DoesNotContain("login denied", error.Message);
    }

    [Fact]
    public async Task EmptyRawBody_Fails()
    {
        var (provider, _) = Create(new StubHttpHandler(HttpStatusCode.OK, "   "));

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetCredentialAsync(AcmeOptions(), AcmeSecrets(), Context(), default).AsTask());

        Assert.Contains("empty", error.Message);
    }

    [Fact]
    public async Task UnsupportedMethod_Fails()
    {
        var (provider, _) = Create(new StubHttpHandler(HttpStatusCode.OK, "token"));

        var options = AcmeOptions();
        options.Method = "PUT";

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetCredentialAsync(options, AcmeSecrets(), Context(), default).AsTask());

        Assert.Contains("PUT", error.Message);
    }

    // --- M31 mutation triage: every failure message here is the operator's diagnosis
    // of a live vendor response shape; none was asserted, and the runtime guards
    // (null args, missing endpoint, empty templates) had no test at all. ---

    [Fact]
    public void Type_IsLoginExchange()
    {
        var (provider, _) = Create(new StubHttpHandler(HttpStatusCode.OK, "t"));

        Assert.Equal("LoginExchange", provider.Type);
    }

    [Fact]
    public async Task NullOptions_Throws_NamingOptions()
    {
        var (provider, _) = Create(new StubHttpHandler(HttpStatusCode.OK, "t"));

        var ex = await Assert.ThrowsAsync<ArgumentNullException>(() =>
            provider.GetCredentialAsync(null!, AcmeSecrets(), Context(), default).AsTask());

        Assert.Equal("options", ex.ParamName);
    }

    [Fact]
    public async Task NullSecrets_Throws_NamingSecrets()
    {
        var (provider, _) = Create(new StubHttpHandler(HttpStatusCode.OK, "t"));

        var ex = await Assert.ThrowsAsync<ArgumentNullException>(() =>
            provider.GetCredentialAsync(AcmeOptions(), null!, Context(), default).AsTask());

        Assert.Equal("secrets", ex.ParamName);
    }

    [Fact]
    public async Task NullContext_Throws_NamingContext()
    {
        var (provider, _) = Create(new StubHttpHandler(HttpStatusCode.OK, "t"));

        var ex = await Assert.ThrowsAsync<ArgumentNullException>(() =>
            provider.GetCredentialAsync(AcmeOptions(), AcmeSecrets(), null!, default).AsTask());

        Assert.Equal("context", ex.ParamName);
    }

    [Fact]
    public async Task MissingLoginEndpoint_FailsNamingTheCredential_AndNoRequestIsSent()
    {
        var (provider, handler) = Create(new StubHttpHandler(HttpStatusCode.OK, "t"));

        var options = AcmeOptions();
        options.LoginEndpoint = null;

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetCredentialAsync(options, AcmeSecrets(), Context(), default).AsTask());

        Assert.Contains("credential 'acme' has no LoginEndpoint configured", error.Message, StringComparison.Ordinal);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Basic_NullUser_ExpandsToEmpty_AndPairIsColonLed()
    {
        // ExpandAsync(null) -> "": a null template must produce the empty half of the
        // pair, never the literal template text or a crash.
        var (provider, handler) = Create(new StubHttpHandler(HttpStatusCode.OK, "t"));

        var options = AcmeOptions();
        options.Basic = new LoginExchangeCredentials { User = null, Password = "p4ss" };

        await provider.GetCredentialAsync(options, AcmeSecrets(), Context(), default);

        var expected = Convert.ToBase64String(Encoding.UTF8.GetBytes(":p4ss"));
        Assert.Equal(expected, Assert.Single(handler.Requests).Headers.Authorization!.Parameter);
    }

    [Fact]
    public async Task RawBody_OnlyWhitespace_FailsNamingWhatWasEmpty()
    {
        var (provider, _) = Create(new StubHttpHandler(HttpStatusCode.OK, "   \n "));

        var options = AcmeOptions();
        options.Response = LoginExchangeResponse.RawBody;

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetCredentialAsync(options, AcmeSecrets(), Context(), default).AsTask());

        Assert.Contains("credential 'acme' has an empty response body", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task JsonPath_ValueIsNotAString_FailsNamingThePath()
    {
        var (provider, _) = Create(new StubHttpHandler(HttpStatusCode.OK, """{"data":{"token":5}}"""));

        var options = AcmeOptions();
        options.Response = LoginExchangeResponse.JsonPath;
        options.ResponseField = "data.token";

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetCredentialAsync(options, AcmeSecrets(), Context(), default).AsTask());

        Assert.Contains("JSON path 'data.token'", error.Message, StringComparison.Ordinal);
        Assert.Contains("is not a token string", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task JsonPath_MalformedJson_FailsWithJsonExceptionInside()
    {
        var (provider, _) = Create(new StubHttpHandler(HttpStatusCode.OK, "{not json"));

        var options = AcmeOptions();
        options.Response = LoginExchangeResponse.JsonPath;
        options.ResponseField = "token";

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetCredentialAsync(options, AcmeSecrets(), Context(), default).AsTask());

        Assert.Contains("returned malformed JSON", error.Message, StringComparison.Ordinal);
        Assert.IsAssignableFrom<System.Text.Json.JsonException>(error.InnerException);
    }

    [Fact]
    public async Task HeaderMode_HeaderAbsent_FailsNamingTheHeader()
    {
        var (provider, _) = Create(new StubHttpHandler(HttpStatusCode.OK, "ignored"));

        var options = AcmeOptions();
        options.Response = LoginExchangeResponse.Header;
        options.ResponseField = "X-Auth-Token";

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetCredentialAsync(options, AcmeSecrets(), Context(), default).AsTask());

        Assert.Contains("has no header 'X-Auth-Token'", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AValuelessHeader_IsNotTreatedAsPresent_EquivalenceBasisForFirstVsFirstOrDefault()
    {
        // :184 FirstOrDefault -> First survived as an EQUIVALENCE mutant, and this is
        // the evidence: the BCL never reports a zero-value header as present, so the
        // value list at :184 is non-empty whenever FirstOrDefault is reached and First
        // can never see an empty sequence. If a future runtime changes this contract,
        // this test goes red and the equivalence row in the M31 report is re-opened.
        var response = new HttpResponseMessage(HttpStatusCode.OK);
        response.Headers.Add("X-Auth-Token", Array.Empty<string>());

        Assert.False(response.Headers.TryGetValues("X-Auth-Token", out _));
    }

    [Fact]
    public async Task CookieMode_CookieAbsent_FailsNamingTheCookie()
    {
        var (provider, _) = Create(new StubHttpHandler(HttpStatusCode.OK, "ignored"));

        var options = AcmeOptions();
        options.Response = LoginExchangeResponse.Cookie;
        options.ResponseField = "SESSION";

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetCredentialAsync(options, AcmeSecrets(), Context(), default).AsTask());

        Assert.Contains("has no cookie 'SESSION'", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CookieMode_MalformedPairsBeforeTarget_SkippedAndTargetFound()
    {
        // The '=' separator scan must skip pairs with no separator or an empty name,
        // then keep scanning — first-match, not first-attempt.
        var handler = new StubHttpHandler((_, _) =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("ignored") };
            response.Headers.TryAddWithoutValidation("Set-Cookie", "=novalue; Path=/");
            response.Headers.TryAddWithoutValidation("Set-Cookie", "junk-pair-no-equals");
            response.Headers.TryAddWithoutValidation("Set-Cookie", "SESSION=ok; Path=/; HttpOnly");
            return response;
        });
        var (provider, _) = Create(handler);

        var options = AcmeOptions();
        options.Response = LoginExchangeResponse.Cookie;
        options.ResponseField = "SESSION";

        var token = await provider.GetCredentialAsync(options, AcmeSecrets(), Context(), default);

        Assert.Equal("ok", token);
    }

    [Fact]
    public async Task ResponseFieldRequired_Missing_FailsNamingMode()
    {
        // Runtime reachability: the validator refuses this combo at startup, but a
        // provider called directly must still diagnose it, never NullReference.
        var (provider, _) = Create(new StubHttpHandler(HttpStatusCode.OK, """{"token":"t"}"""));

        var options = AcmeOptions();
        options.Response = LoginExchangeResponse.JsonPath;
        options.ResponseField = null;

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetCredentialAsync(options, AcmeSecrets(), Context(), default).AsTask());

        Assert.Contains("needs ResponseField for Response mode 'JsonPath'", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UndefinedResponseMode_FailsNamingTheValue()
    {
        // Same binder quirk as TokenExchangeMode (M27 review N1): an undefined enum
        // NUMBER reaches the provider; the default arm's message is the diagnosis.
        var (provider, _) = Create(new StubHttpHandler(HttpStatusCode.OK, "t"));

        var options = AcmeOptions();
        options.Response = (LoginExchangeResponse)99;

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetCredentialAsync(options, AcmeSecrets(), Context(), default).AsTask());

        Assert.Contains("Response mode '99' is not supported", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void GetCredentialAsync_NullSecrets_ThrowsSynchronouslyNamingSecrets()
    {
        // The guard fires at call time — a null accessor must not reach the cache and
        // surface later (or wrapped) from the exchange factory.
        var (provider, _) = Create(new StubHttpHandler(HttpStatusCode.OK, "unused"));

        var error = Assert.Throws<ArgumentNullException>(
            () => provider.GetCredentialAsync(AcmeOptions(), null!, Context(), default));

        Assert.Equal("secrets", error.ParamName);
    }
}
