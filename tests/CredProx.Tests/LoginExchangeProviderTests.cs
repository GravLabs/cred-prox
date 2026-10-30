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
}
