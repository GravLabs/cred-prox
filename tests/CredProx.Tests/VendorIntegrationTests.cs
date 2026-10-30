using System.Net;
using System.Net.Http;
using System.Text;
using CredProx;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The providers against a real HTTP stack: an in-process ASP.NET Core stub vendor behind a
/// real <see cref="HttpClient"/> — request serialization, form encoding and response reading
/// all run for real, no hand-rolled handler in between.
/// </summary>
public sealed class VendorIntegrationTests : IDisposable
{
    private readonly IHost _host;
    private readonly StubHttpClientFactory _httpClientFactory;
    private int _vendorCalls;

    public VendorIntegrationTests()
    {
        _host = new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.Configure(app => app.Run(HandleAsync));
            })
            .Start();
        _httpClientFactory = new StubHttpClientFactory(_host.GetTestServer().CreateHandler());
    }

    public void Dispose() => _host.Dispose();

    private async Task HandleAsync(HttpContext context)
    {
        _vendorCalls++;
        var request = context.Request;

        if (request.Path == "/token")
        {
            var form = await request.ReadFormAsync();
            if (form["grant_type"] != "client_credentials" ||
                form["client_id"] != "cid" ||
                form["client_secret"] != "csec")
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsync("bad request");
                return;
            }

            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("""{"access_token":"vendor-token","expires_in":3600}""");
            return;
        }

        if (request.Path.StartsWithSegments("/login"))
        {
            var auth = request.Headers.Authorization.ToString();
            var expected = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("user:pass"));
            if (auth != expected)
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsync("denied");
                return;
            }

            // The acme-style login returns the raw token in the body.
            await context.Response.WriteAsync("session-token-" + (request.Query["partition"]));
            return;
        }

        if (request.Path.StartsWithSegments("/cookielogin"))
        {
            var form = await request.ReadFormAsync();
            if (form["user"] != "user" || form["password"] != "pass")
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsync("denied");
                return;
            }

            // A session-cookie vendor: the credential is the Set-Cookie value, not the body.
            context.Response.Cookies.Append("CRMSESSION", "session-" + request.Query["partition"],
                new CookieOptions { Path = "/" });
            await context.Response.WriteAsync("ok");
            return;
        }

        context.Response.StatusCode = StatusCodes.Status404NotFound;
    }

    private ITokenCache NewCache() =>
        new InMemoryTokenCache(Options.Create(new TokenCacheOptions()), new FakeTimeProvider());

    [Fact]
    public async Task OAuthClientCredentials_EndToEnd()
    {
        var provider = new OAuthClientCredentialsProvider(NewCache(), _httpClientFactory, new FakeTimeProvider());
        var secrets = TestSecrets.AccessorFor(
            new() { ["ClientId"] = "secret:cid", ["ClientSecret"] = "secret:csec" },
            new() { ["cid"] = "cid", ["csec"] = "csec" });
        var options = new OAuthClientCredentialsOptions
        {
            TokenEndpoint = "http://localhost/token",
            ClientAuthentication = OAuthClientAuthentication.FormPost,
            ClientId = "secret:cid",
            ClientSecret = "secret:csec",
        };
        var context = new CredentialRequestContext { CredentialName = "vendor", Partition = null };

        Assert.Equal("vendor-token", await provider.GetCredentialAsync(options, secrets, context, default));
        Assert.Equal("vendor-token", await provider.GetCredentialAsync(options, secrets, context, default));
        Assert.Equal(1, _vendorCalls); // second call served from cache
    }

    [Fact]
    public async Task LoginExchange_EndToEnd_PerPartition()
    {
        var provider = new LoginExchangeProvider(NewCache(), _httpClientFactory, new FakeTimeProvider());
        var secrets = TestSecrets.AccessorFor(
            new()
            {
                ["LoginEndpoint"] = "http://localhost/login?partition={partition}",
                ["Basic:User"] = "secret:login-user",
                ["Basic:Password"] = "secret:login-pass",
            },
            new() { ["login-user"] = "user", ["login-pass"] = "pass" });
        var options = new LoginExchangeOptions
        {
            LoginEndpoint = "http://localhost/login?partition={partition}",
            Basic = new LoginExchangeCredentials { User = "secret:login-user", Password = "secret:login-pass" },
        };

        Assert.Equal(
            "session-token-uat",
            await provider.GetCredentialAsync(options, secrets, new CredentialRequestContext { CredentialName = "acme", Partition = "uat" }, default));
        Assert.Equal(
            "session-token-prod",
            await provider.GetCredentialAsync(options, secrets, new CredentialRequestContext { CredentialName = "acme", Partition = "prod" }, default));
        Assert.Equal(2, _vendorCalls);
    }

    [Fact]
    public async Task LoginExchange_WrongCredentials_FailsWithHttpStatus()
    {
        var provider = new LoginExchangeProvider(NewCache(), _httpClientFactory, new FakeTimeProvider());
        var secrets = TestSecrets.AccessorFor(
            new() { ["Basic:User"] = "secret:login-user", ["Basic:Password"] = "secret:login-pass" },
            new() { ["login-user"] = "wrong", ["login-pass"] = "wrong" });
        var options = new LoginExchangeOptions
        {
            LoginEndpoint = "http://localhost/login",
            Basic = new LoginExchangeCredentials { User = "secret:login-user", Password = "secret:login-pass" },
        };

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetCredentialAsync(options, secrets, new CredentialRequestContext { CredentialName = "acme" }, default).AsTask());

        Assert.Contains("401", error.Message);
        Assert.DoesNotContain("wrong", error.Message);
    }

    [Fact]
    public async Task LoginExchange_CookieMode_EndToEnd_ExtractsAndPlacesCookie()
    {
        var provider = new LoginExchangeProvider(NewCache(), _httpClientFactory, new FakeTimeProvider());
        var secrets = TestSecrets.AccessorFor(
            new() { ["Form:User"] = "secret:login-user", ["Form:Password"] = "secret:login-pass" },
            new() { ["login-user"] = "user", ["login-pass"] = "pass" });
        var options = new LoginExchangeOptions
        {
            LoginEndpoint = "http://localhost/cookielogin?partition={partition}",
            Method = "POST",
            Form = new LoginExchangeCredentials { User = "secret:login-user", Password = "secret:login-pass" },
            Response = LoginExchangeResponse.Cookie,
            ResponseField = "CRMSESSION",
            Location = CredentialLocation.Cookie,
        };

        var token = await provider.GetCredentialAsync(
            options, secrets, new CredentialRequestContext { CredentialName = "crm", Partition = "uat" }, default);
        Assert.Equal("session-uat", token);

        // Cookie placement (§8.1): one pair replacing the caller's whole Cookie header.
        var attachment = (IHasAttachment)options;
        var request = new HttpRequestMessage(HttpMethod.Get, "https://crm.example/api/contacts");
        request.Headers.Add("Cookie", "theme=dark; CRMSESSION=caller-forged");
        CredentialAttacher.Apply(request, attachment.Location, attachment.Name, token, attachment.Prefix);

        Assert.Equal("CRMSESSION=session-uat", Assert.Single(request.Headers.GetValues("Cookie")));
    }
}
