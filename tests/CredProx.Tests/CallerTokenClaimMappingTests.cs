using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
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
/// M39 fold F3 (review verdict): the caller-token scheme turns OFF inbound claim mapping,
/// so the mapper and the host's <c>HttpContext.User</c> see Entra's raw claim names —
/// <c>roles</c>, <c>scp</c>, <c>azp</c>, <c>appid</c>, <c>uti</c> — which is what makes
/// ADR-0004's "claim names are met by configuration" true. With mapping off the handler's
/// role claim type is pinned to the raw <c>roles</c> so <see cref="ClaimsPrincipal.IsInRole(string)"/>
/// keeps working for hosts. These facts run through the real JWT bearer scheme on the real
/// request path (offline keys): the mapper alone cannot see the rename.
/// </summary>
public sealed class CallerTokenClaimMappingTests : IAsyncLifetime
{
    private const string Issuer = "https://idp.example";
    private const string Audience = "credprox-api";

    private static readonly RSA IssuerRsa = RSA.Create(2048);

    private readonly IHost _upstream;

    public CallerTokenClaimMappingTests()
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

    private static string Hash(string value) =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    /// <summary>agent-4 is token-only with three NAMED rules: plain-read (/plain/*),
    /// plain-admin (/plain/admin/*) and a delegated shape on /plain/delegated/* that an
    /// <c>scp</c>-shaped token is expected to admit.</summary>
    private static Dictionary<string, string?> Entries() => new()
    {
        ["CredProx:Callers:agent-4:TokenClientIds:0"] = "client-sec-d",
        ["CredProx:Callers:agent-4:Operations:0:Route"] = "plain",
        ["CredProx:Callers:agent-4:Operations:0:Methods:0"] = "GET",
        ["CredProx:Callers:agent-4:Operations:0:Paths:0"] = "/plain/*",
        ["CredProx:Callers:agent-4:Operations:0:Name"] = "plain-read",
        ["CredProx:Callers:agent-4:Operations:1:Route"] = "plain",
        ["CredProx:Callers:agent-4:Operations:1:Paths:0"] = "/plain/admin/*",
        ["CredProx:Callers:agent-4:Operations:1:Name"] = "plain-admin",
        ["CredProx:Callers:agent-4:Operations:2:Route"] = "plain",
        ["CredProx:Callers:agent-4:Operations:2:Paths:0"] = "/plain/delegated/*",
        ["CredProx:Callers:agent-4:Operations:2:Name"] = "delegated-read",

        ["CredProx:CallerToken:Authority"] = Issuer,
        ["CredProx:CallerToken:Audience"] = Audience,

        ["CredProx:Destinations:acme:Template"] = "http://upstream.example/",
    };

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

    private sealed class CapturingCallerTokenMapper(
        CallerRegistryProvider registryProvider,
        CallerTokenOptions options,
        IConfiguration configuration) : ICallerTokenMapper
    {
        private readonly DefaultCallerTokenMapper _inner = new(registryProvider, options, configuration);

        public ClaimsPrincipal? Captured { get; private set; }

        public CallerTokenMapping? MapToken(ClaimsPrincipal principal)
        {
            Captured = principal;
            return _inner.MapToken(principal);
        }
    }

    private (IHost Host, CapturingCallerTokenMapper Mapper) StartHost()
    {
        var transport = _upstream.GetTestServer().CreateHandler();

        var host = new HostBuilder()
            .ConfigureAppConfiguration(build => build.AddInMemoryCollection(Entries()))
            .ConfigureServices((context, services) =>
            {
                services.AddCredProxTokenCache();
                services.AddCredProxConfigurationSecrets(context.Configuration);
                services.AddCredProxBuiltInCredentials();
                services.AddCredProxCredentials(context.Configuration);
                services.AddCredProxCallerAuthentication(context.Configuration);
                services.AddCredProxCallerTokenAuthentication(context.Configuration);

                // The captured principal must be the production mapper's input. Registered
                // after the token extension; ASP.NET Core DI resolves the LAST registration,
                // and the extension's TryAddSingleton leaves both in place.
                services.AddSingleton<ICallerTokenMapper>(sp => new CapturingCallerTokenMapper(
                    sp.GetRequiredService<CallerRegistryProvider>(),
                    sp.GetRequiredService<CallerTokenOptions>(),
                    sp.GetRequiredService<IConfiguration>()));

                // Offline validation only: null the Authority, hand over the RSA key. The
                // production claim-shape settings (MapInboundClaims, RoleClaimType) stay as
                // the product set them.
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

        var mapper = host.Services.GetServices<ICallerTokenMapper>().OfType<CapturingCallerTokenMapper>().FirstOrDefault()
            ?? throw new InvalidOperationException("capturing mapper was not resolved (last-registration-wins failed?)");
        return (host, mapper);
    }

    private static string IssueToken(
        string? azp = "client-sec-d",
        string? uti = "tok-f3",
        string? role = null,
        string? scp = null)
    {
        var start = DateTimeOffset.UtcNow;
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            Audience = Audience,
            NotBefore = start.AddMinutes(-1).UtcDateTime,
            Expires = start.AddMinutes(5).UtcDateTime,
            SigningCredentials = new SigningCredentials(
                new RsaSecurityKey(IssuerRsa), SecurityAlgorithms.RsaSha256),
        };

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

        if (scp is not null)
        {
            claims["scp"] = scp;
        }

        descriptor.Claims = claims;
        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    private static HttpRequestMessage PlainRequest(string token, string path = "/plain/doc")
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy" + path);
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + token);
        return request;
    }

    [Fact]
    public async Task EntraRolesToken_RealScheme_PopulatesScopes_AndIntersectsRules()
    {
        var (host, mapper) = StartHost();
        var client = host.GetTestClient();

        var admitted = await client.SendAsync(
            PlainRequest(IssueToken(role: "plain-read"), "/plain/doc"));
        Assert.Equal(HttpStatusCode.OK, admitted.StatusCode);

        // The mapper saw the raw claim name — the rename never happened.
        var captured = mapper.Captured!;
        Assert.NotNull(captured.FindFirst("roles"));
        Assert.Null(captured.FindFirst(
            "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"));
        Assert.Contains("plain-read", captured.FindAll("roles").Select(c => c.Value));
        Assert.Contains("plain-read", mapper.MapToken(captured)!.Scopes);

        // azp/uti still arrive under their raw names (they never mapped, and stay raw).
        Assert.Equal("client-sec-d", captured.FindFirst("azp")?.Value);
        Assert.Equal("tok-f3", captured.FindFirst("uti")?.Value);

        // The intersection runs on the real path: the same role cannot open the admin rule.
        var denied = await client.SendAsync(
            PlainRequest(IssueToken(role: "plain-read", uti: "tok-f3b"), "/plain/admin/x"));
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
    }

    [Fact]
    public async Task DelegatedScpToken_RealScheme_PopulatesScopes_AndAdmitsNamedRule()
    {
        var (host, mapper) = StartHost();
        var client = host.GetTestClient();

        var admitted = await client.SendAsync(
            PlainRequest(IssueToken(scp: "delegated-read"), "/plain/delegated/doc"));
        Assert.Equal(HttpStatusCode.OK, admitted.StatusCode);

        var captured = mapper.Captured!;
        Assert.NotNull(captured.FindFirst("scp"));
        Assert.Null(captured.FindFirst(
            "http://schemas.microsoft.com/identity/claims/scope"));
        Assert.Contains("delegated-read", mapper.MapToken(captured)!.Scopes);
    }

    [Fact]
    public async Task TokenPath_HostSeesRawNames_AndIsInRoleWorks()
    {
        var (host, mapper) = StartHost();
        var client = host.GetTestClient();

        var response = await client.SendAsync(
            PlainRequest(IssueToken(role: "plain-read"), "/plain/doc"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // What the host sees as HttpContext.User (the same principal the feature publishes):
        // raw claim names present, and IsInRole keyed to the raw "roles" name.
        var user = mapper.Captured!;
        Assert.True(user.IsInRole("plain-read"));
        Assert.False(user.IsInRole("plain-admin"));
        Assert.Contains(user.Claims, c => c.Type == "roles" && c.Value == "plain-read");
        Assert.Contains(user.Claims, c => c.Type == "azp");

        // CredProx's own identity claims ride along unchanged.
        Assert.Equal("agent-4", user.FindFirst(CallerIdentity.CallerClaimType)?.Value);
        Assert.Equal("token:tok-f3", user.FindFirst(CallerIdentity.KeyIdClaimType)?.Value);
    }

    private sealed class StubTransportFactory(HttpMessageHandler transport) : IForwarderHttpClientFactory
    {
        public HttpMessageInvoker CreateClient(ForwarderHttpClientContext context) =>
            new(transport);
    }
}
