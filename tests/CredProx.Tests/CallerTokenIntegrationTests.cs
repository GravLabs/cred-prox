using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;

namespace CredProx.Tests;

/// <summary>
/// M39 outcome B end to end: a validated caller token (stock JWT bearer, offline keys —
/// Authority nulled, RSA signing key supplied directly) maps through the registered
/// mapper to a caller; the caller's own Authorization header never reaches the upstream
/// on the token path (the vendor credential is what the upstream sees); an unlisted
/// client, a bad signature and an expired token all answer 401 before anything is
/// forwarded or fetched; the API-key path stays byte-for-byte, including its exact 401
/// problem detail on hosts that never registered token validation.
/// </summary>
public sealed class CallerTokenIntegrationTests : IAsyncLifetime
{
    private const string Issuer = "https://idp.example";
    private const string Audience = "credprox-api";
    private const string KeyA = "caller-key-alpha";
    private const string KeyB = "caller-key-beta";

    private static readonly RSA IssuerRsa = RSA.Create(2048);
    private static readonly RSA AttackerRsa = RSA.Create(2048);

    /// <summary>Stand-in for a host's own validation keys (Microsoft.Identity.Web,
    /// another OIDC issuer, introspection) registered through the registerScheme swap
    /// point (M39, ADR-0004). Deliberately a different key than the config-side issuer.</summary>
    private static readonly RSA CustomHostRsa = RSA.Create(2048);

    private static Action<AuthenticationBuilder> CustomHandlerScheme(RSA key) => builder => builder.AddJwtBearer(
        CredProxAuth.CallerTokenScheme,
        options =>
        {
            options.MapInboundClaims = false;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidIssuer = Issuer,
                ValidAudience = Audience,
                IssuerSigningKey = new RsaSecurityKey(key.ExportParameters(false)),
                RoleClaimType = "roles",
                ClockSkew = TimeSpan.FromSeconds(30),
            };
        });

    private readonly StubHttpHandler _tokenHandler;
    private readonly IHost _upstream;
    private readonly List<string> _upstreamPaths = [];
    private readonly List<Dictionary<string, string?>> _upstreamHeaders = [];

    public CallerTokenIntegrationTests()
    {
        var tokens = new Queue<string>(["token-1", "token-2", "token-3", "token-4"]);
        _tokenHandler = new StubHttpHandler((_, _) =>
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(tokens.Dequeue()) });

        _upstream = new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.Configure(app => app.Run(context =>
                {
                    _upstreamPaths.Add(context.Request.Path + context.Request.QueryString);
                    _upstreamHeaders.Add(new Dictionary<string, string?>
                    {
                        ["Authorization"] = context.Request.Headers.Authorization.ToString(),
                        ["X-CredProx-Key"] = context.Request.Headers["X-CredProx-Key"],
                    });
                    return context.Response.WriteAsync("upstream-ok");
                }));
            })
            .Start();
    }

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        await _upstream.StopAsync();
        _upstream.Dispose();
    }

    private void ResetUpstream()
    {
        _upstreamPaths.Clear();
        _upstreamHeaders.Clear();
    }

    private static string Hash(string value) =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    /// <summary>agent-1 takes keys AND a token client; agent-2 is key-only; agent-3 is
    /// token-only. The partition allow-list covers all three so the vendor account
    /// resolves per caller whichever scheme authenticated. agent-1 and agent-3 declare
    /// one catch-all entry NAMED 'proxy-call': a token must carry that role to get
    /// through (fold-2 ruling — on the token path only a named match admits), while the
    /// key path ignores the name entirely.</summary>
    private static Dictionary<string, string?> CallerEntries() => new()
    {
        ["CredProx:Callers:agent-1:Keys:0:KeyId"] = "k1",
        ["CredProx:Callers:agent-1:Keys:0:KeyHash"] = Hash(KeyA),
        ["CredProx:Callers:agent-1:TokenClientIds:0"] = "client-sec-a",
        ["CredProx:Callers:agent-1:Operations:0:Name"] = "proxy-call",
        ["CredProx:Callers:agent-2:Keys:0:KeyId"] = "k1",
        ["CredProx:Callers:agent-2:Keys:0:KeyHash"] = Hash(KeyB),
        ["CredProx:Callers:agent-3:TokenClientIds:0"] = "client-sec-c",
        ["CredProx:Callers:agent-3:Operations:0:Name"] = "proxy-call",

        ["CredProx:CallerToken:Authority"] = Issuer,
        ["CredProx:CallerToken:Audience"] = Audience,

        ["CredProx:Destinations:acme:Template"] = "http://upstream.example/",

        ["CredProx:Credentials:contoso:Type"] = "LoginExchange",
        ["CredProx:Credentials:contoso:LoginEndpoint"] = "http://token.example/{partition}/login",
        ["CredProx:Credentials:contoso:Method"] = "POST",
        ["CredProx:Credentials:contoso:Form:User"] = "user-{partition}",
        ["CredProx:Credentials:contoso:Form:Password"] = "secret:{partition}-pass",
        ["CredProx:Credentials:contoso:AttachPrefix"] = "Bearer",
        ["CredProx:Credentials:contoso:Partition:From"] = "caller:",
        ["CredProx:Credentials:contoso:Partition:Allowed:0"] = "agent-1",
        ["CredProx:Credentials:contoso:Partition:Allowed:1"] = "agent-2",
        ["CredProx:Credentials:contoso:Partition:Allowed:2"] = "agent-3",
        ["CredProx:Secrets:agent-1-pass"] = "pass-a",
        ["CredProx:Secrets:agent-2-pass"] = "pass-b",
        ["CredProx:Secrets:agent-3-pass"] = "pass-c",
    };

    private static readonly RouteConfig AcmeRoute = new()
    {
        RouteId = "acme",
        ClusterId = "acme",
        Match = new RouteMatch { Path = "/api/{**catch-all}" },
        Metadata = new Dictionary<string, string>
        {
            [CredProxMetadata.Destination] = "acme",
            [CredProxMetadata.Credential] = "contoso",
        },
    };

    // The same route without a credential: what the caller presents in Authorization is
    // then exactly what the upstream sees.
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

    private (IHost Host, List<string?> Logs) StartProxyHost(
        bool tokenAuth = true,
        Dictionary<string, string?>? callerEntries = null,
        IReadOnlyList<RouteConfig>? routes = null,
        Action<AuthenticationBuilder>? registerScheme = null)
    {
        var entries = CallerEntries();
        if (callerEntries is not null)
        {
            foreach (var (key, value) in callerEntries)
            {
                entries[key] = value;
            }
        }

        var transport = _upstream.GetTestServer().CreateHandler();
        var logs = new List<string?>();

        var host = new HostBuilder()
            .ConfigureAppConfiguration(build => build.AddInMemoryCollection(entries))
            .ConfigureServices((context, services) =>
            {
                services.AddCredProxTokenCache();
                services.AddCredProxConfigurationSecrets(context.Configuration);
                services.AddCredProxBuiltInCredentials();
                services.AddCredProxCredentials(context.Configuration);
                services.AddCredProxCallerAuthentication(context.Configuration);
                if (tokenAuth)
                {
                    // The registerScheme path hands validation to the host, so the offline
                    // override below (which tunes the stock handler) is not applied — the
                    // host's own handler carries its own key.
                    services.AddCredProxCallerTokenAuthentication(context.Configuration, registerScheme);

                    if (registerScheme is null)
                    {
                        // Offline validation: no metadata endpoint exists in tests, so null
                        // the Authority and hand the handler the RSA key directly. The config
                        // section still carries the dummy Authority/Audience that registration
                        // demands; with Authority nulled no metadata fetch ever happens.
                        services.Configure<JwtBearerOptions>(CredProxAuth.CallerTokenScheme, o =>
                        {
                            o.Authority = null;
                            o.RequireHttpsMetadata = false;
                            o.TokenValidationParameters = new TokenValidationParameters
                            {
                                ValidIssuer = Issuer,
                                ValidAudience = Audience,
                                IssuerSigningKey = new RsaSecurityKey(IssuerRsa.ExportParameters(false)),
                                ClockSkew = TimeSpan.FromSeconds(30),
                            };
                        });
                    }
                }

                services.AddRouting();
                services.AddReverseProxy().LoadFromMemory(routes ?? [AcmeRoute], [AcmeCluster]).AddCredProx(context.Configuration);

                services.AddHttpClient(CredProxHttpClientNames.TokenClient)
                    .ConfigurePrimaryHttpMessageHandler(() => _tokenHandler);

                services.AddSingleton<IForwarderHttpClientFactory>(
                    sp => new StubTransportFactory(sp, transport));
            })
            .ConfigureLogging(logging => logging.AddProvider(new CapturingLoggerProvider(logs)))
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

        return (host, logs);
    }

    private static string IssueToken(
        RSA? signingKey = null,
        string? azp = "client-sec-a",
        string? uti = "tok-1",
        string? role = null,
        TimeSpan? lifetime = null,
        string audience = Audience,
        string issuer = Issuer,
        TimeSpan? issuedAgo = null)
    {
        var start = DateTimeOffset.UtcNow;
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            NotBefore = start.AddMinutes(-1).UtcDateTime,
            Expires = start.Add(lifetime ?? TimeSpan.FromMinutes(5)).UtcDateTime,
            SigningCredentials = new SigningCredentials(
                new RsaSecurityKey(signingKey ?? IssuerRsa), SecurityAlgorithms.RsaSha256),
        };

        if (issuedAgo is { } ago)
        {
            // nbf and exp stay fresh: only iat goes backwards — what the CredProx-side
            // MaxTokenAge check reads, independent of the handler doing validation.
            descriptor.IssuedAt = start.Subtract(ago).UtcDateTime;
        }

        var claims = new Dictionary<string, object>();
        if (azp is not null)
        {
            claims["azp"] = azp;
        }

        if (uti is not null)
        {
            claims["uti"] = uti;
        }

        if (role is not null)
        {
            claims["roles"] = role;
        }

        if (claims.Count > 0)
        {
            descriptor.Claims = claims;
        }

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    private static HttpRequestMessage WithBearer(string token)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy/api/thing");
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + token);
        return request;
    }

    [Fact]
    public async Task ValidToken_IsForwarded_VendorBearerReachesUpstream()
    {
        ResetUpstream();
        var (host, _) = StartProxyHost();

        var response = await host.GetTestClient().SendAsync(WithBearer(IssueToken(role: "proxy-call")));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("/api/thing", Assert.Single(_upstreamPaths));
        // The caller's own JWT never reaches the upstream — the vendor credential does.
        Assert.Equal("Bearer token-1", Assert.Single(_upstreamHeaders)["Authorization"]);
        Assert.Contains("/agent-1/login", _tokenHandler.Requests[0].RequestUri!.ToString());
    }

    [Fact]
    public async Task TokenOnlyCaller_IsForwarded()
    {
        ResetUpstream();
        var (host, _) = StartProxyHost();

        var response = await host.GetTestClient()
            .SendAsync(WithBearer(IssueToken(azp: "client-sec-c", uti: "tok-c", role: "proxy-call")));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("/agent-3/login", _tokenHandler.Requests[0].RequestUri!.ToString());
    }

    [Fact]
    public async Task UnlistedClient_401_NoForwardNoToken()
    {
        ResetUpstream();
        var (host, _) = StartProxyHost();

        var response = await host.GetTestClient().SendAsync(WithBearer(IssueToken(azp: "client-evil")));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType!.MediaType);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("credprox.caller_unauthenticated", body);
        // Token hosts name both accepted credentials in the problem detail.
        Assert.Contains("A valid caller API key or caller token is required.", body);
        Assert.Empty(_upstreamPaths);
        Assert.Empty(_tokenHandler.Requests);
    }

    [Fact]
    public async Task TokenWithoutClientClaim_401()
    {
        ResetUpstream();
        var (host, _) = StartProxyHost();

        var response = await host.GetTestClient().SendAsync(WithBearer(IssueToken(azp: null)));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Empty(_upstreamPaths);
    }

    [Fact]
    public async Task BadSignature_401_NoForward()
    {
        ResetUpstream();
        var (host, _) = StartProxyHost();

        var response = await host.GetTestClient()
            .SendAsync(WithBearer(IssueToken(signingKey: AttackerRsa)));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Empty(_upstreamPaths);
        Assert.Empty(_tokenHandler.Requests);
    }

    [Fact]
    public async Task ExpiredToken_401_NoForward()
    {
        ResetUpstream();
        var (host, _) = StartProxyHost();

        var response = await host.GetTestClient()
            .SendAsync(WithBearer(IssueToken(lifetime: TimeSpan.FromMinutes(-2))));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Empty(_upstreamPaths);
    }

    [Fact]
    public async Task ValidKey_StillWorks_OnTokenHost()
    {
        ResetUpstream();
        var (host, _) = StartProxyHost();

        var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy/api/thing");
        request.Headers.Add("X-CredProx-Key", KeyA);
        var response = await host.GetTestClient().SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("Bearer token-1", Assert.Single(_upstreamHeaders)["Authorization"]);
    }

    [Fact]
    public async Task KeyAndBearer_KeyWins_CallerBearerStillForwarded()
    {
        // Pinned deliberately (and disclosed on the handoff): on the KEY path nothing
        // strips Authorization — existing caller-header semantics are byte-for-byte.
        // Only the token path strips it, because there the bearer IS the credential.
        ResetUpstream();
        var (host, _) = StartProxyHost(routes: [PlainRoute]);

        var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy/plain/thing");
        request.Headers.Add("X-CredProx-Key", KeyA);
        var callerJwt = IssueToken(azp: "client-sec-a");
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + callerJwt);
        var response = await host.GetTestClient().SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("Bearer " + callerJwt, Assert.Single(_upstreamHeaders)["Authorization"]);
    }

    [Fact]
    public async Task TokenPath_StripsCallerBearer_EvenWithoutCredential()
    {
        ResetUpstream();
        var (host, _) = StartProxyHost(routes: [PlainRoute]);

        var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy/plain/thing");
        var callerJwt = IssueToken(azp: "client-sec-c", uti: "tok-c", role: "proxy-call");
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + callerJwt);
        var response = await host.GetTestClient().SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(string.IsNullOrEmpty(Assert.Single(_upstreamHeaders)["Authorization"]));
    }

    [Fact]
    public async Task KeyOnlyHost_KeepsTheExactLegacy401Detail()
    {
        // A host that never ran AddCredProxCallerTokenAuthentication keeps the original
        // problem detail text — byte-for-byte, no "or caller token".
        ResetUpstream();
        var (host, _) = StartProxyHost(tokenAuth: false);

        var response = await host.GetTestClient().GetAsync("http://proxy/api/thing");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("A valid caller API key is required.", body);
        Assert.DoesNotContain("caller token", body, StringComparison.OrdinalIgnoreCase);
    }

    // ---- M39 outcome C: roles/scp intersect the caller's named rules end to end ----

    /// <summary>agent-4 is token-only with two NAMED rules: plain-read admits one
    /// segment under /plain, plain-admin admits one segment under /plain/admin.</summary>
    private static Dictionary<string, string?> NamedRulesCallerEntries() => new()
    {
        ["CredProx:Callers:agent-4:TokenClientIds:0"] = "client-sec-d",
        ["CredProx:Callers:agent-4:Operations:0:Route"] = "plain",
        ["CredProx:Callers:agent-4:Operations:0:Methods:0"] = "GET",
        ["CredProx:Callers:agent-4:Operations:0:Paths:0"] = "/plain/*",
        ["CredProx:Callers:agent-4:Operations:0:Name"] = "plain-read",
        ["CredProx:Callers:agent-4:Operations:1:Route"] = "plain",
        ["CredProx:Callers:agent-4:Operations:1:Paths:0"] = "/plain/admin/*",
        ["CredProx:Callers:agent-4:Operations:1:Name"] = "plain-admin",
    };

    private static HttpRequestMessage PlainRequest(string token, string path = "/plain/doc")
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy" + path);
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + token);
        return request;
    }

    [Fact]
    public async Task TokenWithMatchingRole_NamedRuleIsAdmitted()
    {
        ResetUpstream();
        var (host, _) = StartProxyHost(
            callerEntries: NamedRulesCallerEntries(), routes: [AcmeRoute, PlainRoute]);

        var response = await host.GetTestClient().SendAsync(
            PlainRequest(IssueToken(azp: "client-sec-d", role: "plain-read")));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        // The token path also strips the caller bearer on the way out (outcome B),
        // even on a credential-less route.
        Assert.True(string.IsNullOrEmpty(Assert.Single(_upstreamHeaders)["Authorization"]));
    }

    [Fact]
    public async Task TokenWithNoRole_NamedRulesDeny_WithTheStandard403()
    {
        // ADR-0004: a valid token for the right app carrying no roles gets nothing from
        // a fully-named rule set — the exact 403 of today's allow-list denial, and
        // nothing reaches the upstream.
        ResetUpstream();
        var (host, _) = StartProxyHost(
            callerEntries: NamedRulesCallerEntries(), routes: [AcmeRoute, PlainRoute]);

        var response = await host.GetTestClient().SendAsync(
            PlainRequest(IssueToken(azp: "client-sec-d", role: null)));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("credprox.operation_not_allowed", body);
        Assert.Empty(_upstreamPaths);
    }

    [Fact]
    public async Task TokenWithWrongRole_NamedRuleDenies()
    {
        ResetUpstream();
        var (host, _) = StartProxyHost(
            callerEntries: NamedRulesCallerEntries(), routes: [AcmeRoute, PlainRoute]);

        var response = await host.GetTestClient().SendAsync(
            PlainRequest(IssueToken(azp: "client-sec-d", role: "plain-admin"), "/plain/doc"));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(_upstreamPaths);
    }

    [Fact]
    public async Task TokenWithAdminRole_AdminPathIsAdmitted()
    {
        ResetUpstream();
        var (host, _) = StartProxyHost(
            callerEntries: NamedRulesCallerEntries(), routes: [AcmeRoute, PlainRoute]);

        var response = await host.GetTestClient().SendAsync(
            PlainRequest(IssueToken(azp: "client-sec-d", role: "plain-admin"), "/plain/admin/x"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task ReadRole_AdminPathStaysDenied_RoleGrantsNothingBeyondItsName()
    {
        // The never-widen direction end to end: plain-read cannot slip through the
        // admin rule the way a union would allow.
        ResetUpstream();
        var (host, _) = StartProxyHost(
            callerEntries: NamedRulesCallerEntries(), routes: [AcmeRoute, PlainRoute]);

        var response = await host.GetTestClient().SendAsync(
            PlainRequest(IssueToken(azp: "client-sec-d", role: "plain-read"), "/plain/admin/x"));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(_upstreamPaths);
    }

    [Fact]
    public async Task RegisterScheme_HostHandlerAdmitsItsOwnKey_DefaultIssuerKeyRefused()
    {
        // The swap point (M39, ADR-0004): the host validates with its own handler and
        // its own keys; CredProx still maps the validated principal to a caller, still
        // enforces named rules, and never answers 500. The config-side Authority/Audience
        // stay untouched — the custom handler ignores them.
        ResetUpstream();
        var (host, _) = StartProxyHost(
            callerEntries: NamedRulesCallerEntries(),
            routes: [AcmeRoute, PlainRoute],
            registerScheme: CustomHandlerScheme(CustomHostRsa));

        var admitted = await host.GetTestClient().SendAsync(
            PlainRequest(IssueToken(signingKey: CustomHostRsa, azp: "client-sec-d", role: "plain-read")));
        Assert.Equal(HttpStatusCode.OK, admitted.StatusCode);

        // The key the stock path would have trusted is meaningless to this handler.
        var refused = await host.GetTestClient().SendAsync(
            PlainRequest(IssueToken(azp: "client-sec-d", role: "plain-read")));
        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
        Assert.Contains("credprox.caller_unauthenticated", await refused.Content.ReadAsStringAsync());
        Assert.Single(_upstreamPaths); // only the admitted request forwarded
    }

    [Fact]
    public async Task RegisterScheme_MaxTokenAgeSurvivesTheSwap()
    {
        // MaxTokenAge is CredProx-side, read from CallerTokenOptions in the
        // caller-authentication stage — swapping the validation handler cannot disarm it.
        ResetUpstream();
        var entries = NamedRulesCallerEntries();
        entries["CredProx:CallerToken:MaxTokenAge"] = "00:15:00";
        var (host, _) = StartProxyHost(
            callerEntries: entries,
            routes: [AcmeRoute, PlainRoute],
            registerScheme: CustomHandlerScheme(CustomHostRsa));

        // Fresh token through the custom handler first: proves the 401 below is the
        // age bound, not the custom key failing validation.
        var fresh = await host.GetTestClient().SendAsync(
            PlainRequest(IssueToken(signingKey: CustomHostRsa, azp: "client-sec-d", role: "plain-read")));
        Assert.Equal(HttpStatusCode.OK, fresh.StatusCode);

        var stale = await host.GetTestClient().SendAsync(
            PlainRequest(IssueToken(
                signingKey: CustomHostRsa, azp: "client-sec-d", role: "plain-read",
                issuedAgo: TimeSpan.FromHours(2))));
        Assert.Equal(HttpStatusCode.Unauthorized, stale.StatusCode);
        Assert.Contains("credprox.caller_unauthenticated", await stale.Content.ReadAsStringAsync());
        Assert.Single(_upstreamPaths);
    }

    [Fact]
    public async Task RegisterScheme_AuthorityAndAudienceAreNotRequired()
    {
        // With a custom handler, Authority and Audience are the host's business: the
        // config-side required checks belong to the default path only, and no JwtBearer
        // config is bound. A section with neither must start fine.
        ResetUpstream();
        var entries = NamedRulesCallerEntries();
        entries["CredProx:CallerToken:Authority"] = null;
        entries["CredProx:CallerToken:Audience"] = null;
        var (host, _) = StartProxyHost(
            callerEntries: entries,
            routes: [AcmeRoute, PlainRoute],
            registerScheme: CustomHandlerScheme(CustomHostRsa));

        var response = await host.GetTestClient().SendAsync(
            PlainRequest(IssueToken(signingKey: CustomHostRsa, azp: "client-sec-d", role: "plain-read")));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public void RegisterScheme_NullKeepsTheRequiredChecks_FailClosed()
    {
        // The default path is byte-for-byte unchanged: without registerScheme the
        // required-value checks still refuse registration naming what is missing.
        var entries = new Dictionary<string, string?>
        {
            ["CredProx:CallerToken:MaxTokenAge"] = "00:15:00",
        };
        var config = new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
        var services = new ServiceCollection();
        services.AddLogging();

        var error = Assert.Throws<OptionsValidationException>(
            () => services.AddCredProxCallerTokenAuthentication(config));
        Assert.Contains("Authority", error.Message);
    }

    private sealed class StubTransportFactory(IServiceProvider services, HttpMessageHandler transport)
        : CredProxForwarderHttpClientFactory(services)
    {
        protected override HttpMessageHandler WrapHandler(
            ForwarderHttpClientContext context, HttpMessageHandler handler)
        {
            handler.Dispose();
            return ComposePipeline(context, transport);
        }
    }
}
