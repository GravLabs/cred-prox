using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;

namespace CredProx.Tests;

/// <summary>
/// M39 outcome D (verdict F2): <c>CredProx:CallerToken:MaxTokenAge</c> was an armed,
/// documented knob that nothing read — a token issued 2 h ago inside its own expiry passed
/// with <c>MaxTokenAge=00:15:00</c>. Enforcement is CredProx-side (the architect's F2 ruling,
/// moved to the authentication stage in fold 2 so a host-registered mapper cannot drop it):
/// the caller-authentication stage rejects a token whose raw <c>iat</c> is older than
/// <c>MaxTokenAge + 5 min</c> — the clock skew the JWT bearer handler itself permits by
/// default, in both directions — or newer than the skew, and a token with no parsable
/// <c>iat</c> when a limit is configured (fail closed: freshness the caller cannot establish
/// is not freshness). Rejection happens before any mapper runs and answers with the existing
/// <c>401 credprox.caller_unauthenticated</c>.
/// These facts run through the real JWT bearer scheme on the real request path (offline keys),
/// because only that path delivers the claims the stage and mapper actually see.
/// </summary>
public sealed class CallerTokenMaxTokenAgeTests : IAsyncLifetime
{
    private const string Issuer = "https://idp.example";
    private const string Audience = "credprox-api";

    private static readonly RSA IssuerRsa = RSA.Create(2048);

    private readonly IHost _upstream;

    public CallerTokenMaxTokenAgeTests()
    {
        _upstream = new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.Configure(app => app.Run(context => context.Response.WriteAsync("upstream-ok")));
            })
            .Start();
    }

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        await _upstream.StopAsync();
        _upstream.Dispose();
    }

    /// <summary>One token-only caller, agent-4, with a single named rule <c>plain-read</c>
    /// on /plain/*; the <c>MaxTokenAge</c> line is what these facts vary.</summary>
    private static Dictionary<string, string?> Entries(string? maxTokenAge)
    {
        var entries = new Dictionary<string, string?>
        {
            ["CredProx:Callers:agent-4:TokenClientIds:0"] = "client-sec-d",
            ["CredProx:Callers:agent-4:Operations:0:Route"] = "plain",
            ["CredProx:Callers:agent-4:Operations:0:Methods:0"] = "GET",
            ["CredProx:Callers:agent-4:Operations:0:Paths:0"] = "/plain/*",
            ["CredProx:Callers:agent-4:Operations:0:Name"] = "plain-read",

            ["CredProx:CallerToken:Authority"] = Issuer,
            ["CredProx:CallerToken:Audience"] = Audience,

            ["CredProx:Destinations:acme:Template"] = "http://upstream.example/",
        };
        if (maxTokenAge is not null)
        {
            entries["CredProx:CallerToken:MaxTokenAge"] = maxTokenAge;
        }

        return entries;
    }

    private static readonly RouteConfig PlainRoute = new()
    {
        RouteId = "plain",
        ClusterId = "acme",
        Match = new RouteMatch { Path = "/plain/{**catch-all}" },
        Metadata = new Dictionary<string, string>
        {
            [CredProxMetadata.Destination] = "acme",
        },
    };

    private static readonly ClusterConfig AcmeCluster = new()
    {
        ClusterId = "acme",
        Destinations = new Dictionary<string, DestinationConfig>
        {
            ["static"] = new() { Address = "http://static.example/" },
        },
    };

    private IHost StartHost(string? maxTokenAge, bool customMapper = false)
    {
        var transport = _upstream.GetTestServer().CreateHandler();

        return new HostBuilder()
            .ConfigureAppConfiguration(build => build.AddInMemoryCollection(Entries(maxTokenAge)))
            .ConfigureServices((context, services) =>
            {
                services.AddCredProxTokenCache();
                services.AddCredProxConfigurationSecrets(context.Configuration);
                services.AddCredProxBuiltInCredentials();
                services.AddCredProxCredentials(context.Configuration);
                services.AddCredProxCallerAuthentication(context.Configuration);
                // The product registers its default mapper with TryAddSingleton, so a
                // host-registered mapper wins — the exact ADR-0004 swap the D-F1 cells run.
                if (customMapper)
                {
                    services.AddSingleton<ICallerTokenMapper, AlwaysMapsMapper>();
                }
                services.AddCredProxCallerTokenAuthentication(context.Configuration);

                // Offline validation only: null the Authority, hand over the RSA key. The
                // production claim-shape settings (MapInboundClaims, RoleClaimType) stay as
                // the product set them — the mapper must see exactly what production sees.
                services.Configure<JwtBearerOptions>(CallerTokenOptions.Scheme, o =>
                {
                    o.Authority = null;
                    o.RequireHttpsMetadata = false;
                    var t = o.TokenValidationParameters;
                    t.ValidIssuer = Issuer;
                    t.ValidAudience = Audience;
                    t.IssuerSigningKey = new RsaSecurityKey(IssuerRsa.ExportParameters(false));
                    t.ClockSkew = TimeSpan.FromSeconds(30);
                });

                services.AddRouting();
                services.AddReverseProxy().LoadFromMemory([PlainRoute], [AcmeCluster]).AddCredProx(context.Configuration);

                services.AddSingleton<IForwarderHttpClientFactory>(new StubTransportFactory(transport));
            })
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints => endpoints.MapReverseProxy());
                });
            })
            .Start();
    }

    // A token the ISSUER still validates: nbf/exp are fresh; only iat is pushed into the
    // past. Raw claim names and JSON numbers — the shape MapInboundClaims=false delivers.
    private static string IssueToken(TimeSpan issuedAgo, bool includeIat = true, string uti = "tok-age")
    {
        var now = DateTimeOffset.UtcNow;
        var payload = new Dictionary<string, object>
        {
            ["iss"] = Issuer,
            ["aud"] = Audience,
            ["azp"] = "client-sec-d",
            ["uti"] = uti,
            ["roles"] = "plain-read",
            ["nbf"] = now.AddMinutes(-1).ToUnixTimeSeconds(),
            ["exp"] = now.AddMinutes(5).ToUnixTimeSeconds(),
        };
        if (includeIat)
        {
            payload["iat"] = (now - issuedAgo).ToUnixTimeSeconds();
        }

        var claimsJson = JsonSerializer.Serialize(payload);
        return new JsonWebTokenHandler().CreateToken(
            claimsJson,
            new SigningCredentials(new RsaSecurityKey(IssuerRsa), SecurityAlgorithms.RsaSha256));
    }

    private static HttpRequestMessage PlainRequest(string token)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy/plain/doc");
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + token);
        return request;
    }

    [Fact]
    public async Task StaleIat_MaxTokenAgeConfigured_401CallerUnauthenticated()
    {
        // Verdict F2's exact probe: issued 2 h ago, still inside its own expiry, limit 15 min.
        var host = StartHost("00:15:00");
        var response = await host.GetTestClient().SendAsync(PlainRequest(IssueToken(TimeSpan.FromHours(2))));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("credprox.caller_unauthenticated", await response.Content.ReadAsStringAsync());
        await host.StopAsync();
    }

    [Fact]
    public async Task FreshIat_MaxTokenAgeConfigured_200()
    {
        var host = StartHost("00:15:00");
        var response = await host.GetTestClient().SendAsync(PlainRequest(IssueToken(TimeSpan.FromMinutes(1))));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        await host.StopAsync();
    }

    [Fact]
    public async Task IatJustInsideAgePlusSkew_200()
    {
        // 15 min limit + the 5 min clock skew JwtBearer permits by default: 19m30s is inside.
        var host = StartHost("00:15:00");
        var response = await host.GetTestClient()
            .SendAsync(PlainRequest(IssueToken(TimeSpan.FromMinutes(19) + TimeSpan.FromSeconds(30))));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        await host.StopAsync();
    }

    [Fact]
    public async Task IatJustOutsideAgePlusSkew_401()
    {
        var host = StartHost("00:15:00");
        var response = await host.GetTestClient()
            .SendAsync(PlainRequest(IssueToken(TimeSpan.FromMinutes(20) + TimeSpan.FromSeconds(30))));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        await host.StopAsync();
    }

    [Fact]
    public async Task MissingIat_MaxTokenAgeConfigured_401_FailClosed()
    {
        // With a configured limit, freshness must be provable: a token with no iat gets nothing
        // to age against, so the stage refuses it before the mapper runs (fail closed).
        var host = StartHost("00:15:00");
        var response = await host.GetTestClient().SendAsync(PlainRequest(IssueToken(TimeSpan.Zero, includeIat: false)));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        await host.StopAsync();
    }

    [Fact]
    public async Task MaxTokenAgeUnset_IssuerLifetimeIsTheBound()
    {
        // Unset means the issuer's own lifetime policy is the bound — a 2 h old token the
        // issuer still validates stays admitted (no silent default).
        var host = StartHost(maxTokenAge: null);
        var response = await host.GetTestClient().SendAsync(PlainRequest(IssueToken(TimeSpan.FromHours(2))));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        await host.StopAsync();
    }

    // A deliberately naive host mapper (D-F1): every principal maps to agent-4 with
    // the role it carries and NO age check anywhere. The pin's point is that CredProx
    // enforces MaxTokenAge before any mapper runs, so replacing the mapper cannot
    // drop the bound.
    private sealed class AlwaysMapsMapper : ICallerTokenMapper
    {
        public CallerTokenMapping? MapToken(ClaimsPrincipal principal)
        {
            var scopes = principal.FindAll("roles").Select(c => c.Value).ToHashSet(StringComparer.Ordinal);
            return new CallerTokenMapping(
                new CallerIdentity("agent-4", "token:custom", "client-sec-d"),
                scopes);
        }
    }

    private sealed class StubTransportFactory(HttpMessageHandler transport) : IForwarderHttpClientFactory
    {
        public HttpMessageInvoker CreateClient(ForwarderHttpClientContext context) =>
            new(transport);
    }

    [Fact]
    public async Task CustomMapper_StaleIat_MaxTokenAge_StillRejected_401()
    {
        // D-F1 (verdict D, ruling 00:45Z): the bound belongs to CredProx's
        // authentication stage, not to the replaceable default mapper. A host mapper
        // that never looks at iat must not drop it — 2 h old token, 15 min limit.
        var host = StartHost("00:15:00", customMapper: true);
        var response = await host.GetTestClient().SendAsync(PlainRequest(IssueToken(TimeSpan.FromHours(2))));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        await host.StopAsync();
    }

    [Fact]
    public async Task CustomMapper_FreshIat_MaxTokenAge_Admits_200()
    {
        // The ADR-0004 swap path stays open: a custom mapper with a fresh token is
        // admitted exactly as the default one. If this cell turns 401, the
        // feature-level check broke the documented replacement seam — its own bug.
        var host = StartHost("00:15:00", customMapper: true);
        var response = await host.GetTestClient().SendAsync(PlainRequest(IssueToken(TimeSpan.FromMinutes(1))));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        await host.StopAsync();
    }

    [Fact]
    public async Task FutureIat_BeyondSkew_MaxTokenAge_401()
    {
        // D-F2: an iat in the future is not freshness — a negative age is inside
        // every bound, so without an upper gate a +10 h token never expires.
        var host = StartHost("00:15:00");
        var response = await host.GetTestClient().SendAsync(PlainRequest(IssueToken(TimeSpan.FromHours(-10))));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        await host.StopAsync();
    }

    [Fact]
    public async Task FutureIat_WithinSkew_MaxTokenAge_Admits_200()
    {
        // Skew tolerance cuts both ways: a token two minutes ahead of this clock is
        // still fresh, mirroring what the JWT bearer handler itself accepts.
        var host = StartHost("00:15:00");
        var response = await host.GetTestClient().SendAsync(PlainRequest(IssueToken(TimeSpan.FromMinutes(-2))));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        await host.StopAsync();
    }
}
