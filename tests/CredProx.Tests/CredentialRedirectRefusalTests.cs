using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using CredProx;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using Yarp.ReverseProxy.Configuration;

namespace CredProx.Tests;

/// <summary>
/// M45 security finding F-1: a credential-acquisition call must never follow a redirect.
/// A 3xx from JWKS, discovery, a token endpoint or a login endpoint is a refusal — the
/// response of some other host must never be believed as if it were the configured one.
/// These pins run the real client stack against real loopback sockets (the way the
/// shipped clients work): a stub handler does not follow redirects, so only the real
/// default transport shows the defect the BCL default carries. RED at a56b4c1, GREEN
/// once the credential-acquisition clients refuse 3xx.
/// </summary>
public sealed class CredentialRedirectRefusalTests : IAsyncLifetime
{
    private const string Issuer = "credprox-pin-issuer";
    private const string Audience = "credprox-api";
    private static readonly RSA IssuerRsa = RSA.Create(2048);
    private static readonly RSA AttackerRsa = RSA.Create(2048);

    private readonly IHost _idp;
    private readonly IHost _evil;
    private readonly ConcurrentQueue<string> _evilHits = new();
    private readonly int _idpPort;
    private readonly int _evilPort;

    public CredentialRedirectRefusalTests()
    {
        _evil = new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseKestrel(o => o.Listen(IPAddress.Loopback, 0));
                web.ConfigureLogging(l => l.ClearProviders());
                web.Configure(app => app.Run(async ctx =>
                {
                    var path = ctx.Request.Path.Value ?? string.Empty;
                    _evilHits.Enqueue(path);
                    ctx.Response.ContentType = "application/json";
                    if (path.Contains("openid-configuration", StringComparison.Ordinal))
                    {
                        await ctx.Response.WriteAsync(
                            "{\"issuer\":\"" + Issuer
                            + "\",\"jwks_uri\":\"http://127.0.0.1:" + PortOf(ctx) + "/jwks\""
                            + ",\"token_endpoint\":\"http://127.0.0.1:" + PortOf(ctx) + "/token-target\"}");
                        return;
                    }

                    await ctx.Response.WriteAsync(path.Contains("target", StringComparison.Ordinal)
                        ? """{"access_token":"EVIL-TOKEN","expires_in":3600,"token_type":"Bearer"}"""
                        : JwksJson(AttackerRsa));
                }));
            })
            .Start();
        _evilPort = ReadPort(_evil);

        // The evil discovery document must name its own jwks_uri; rewrite the placeholder
        // now that the port is known.
        _idp = new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseKestrel(o => o.Listen(IPAddress.Loopback, 0));
                web.ConfigureLogging(l => l.ClearProviders());
                web.Configure(app => app.Run(async ctx =>
                {
                    var path = ctx.Request.Path.Value ?? string.Empty;
                    switch (path)
                    {
                        case "/.well-known/jwks.json":
                            ctx.Response.ContentType = "application/json";
                            await ctx.Response.WriteAsync(JwksJson(IssuerRsa));
                            return;
                        case "/.well-known/openid-configuration":
                            ctx.Response.ContentType = "application/json";
                            await ctx.Response.WriteAsync(
                                "{\"issuer\":\"" + Issuer + "\""
                                + ",\"jwks_uri\":\"" + Idp("/.well-known/jwks.json") + "\""
                                + ",\"token_endpoint\":\"" + Idp("/token") + "\"}");
                            return;
                        case "/.well-known/jwks-302.json":
                            ctx.Response.StatusCode = 302;
                            ctx.Response.Headers.Location = $"http://127.0.0.1:{_evilPort}/jwks";
                            return;
                        case "/disc302/.well-known/openid-configuration":
                            ctx.Response.StatusCode = 302;
                            ctx.Response.Headers.Location =
                                $"http://127.0.0.1:{_evilPort}/.well-known/openid-configuration";
                            return;
                        case "/token":
                        case "/cc-token":
                            ctx.Response.ContentType = "application/json";
                            await ctx.Response.WriteAsync(
                                """{"access_token":"GOOD-TOKEN","expires_in":3600,"token_type":"Bearer"}""");
                            return;
                        case "/token-302":
                        case "/cc-302":
                        case "/login-302":
                        case "/jwt-302":
                            ctx.Response.StatusCode = 302;
                            ctx.Response.Headers.Location = $"http://127.0.0.1:{_evilPort}/token-target";
                            return;
                    }

                    ctx.Response.StatusCode = 404;
                }));
            })
            .Start();
        _idpPort = ReadPort(_idp);
    }

    private static int ReadPort(IHost host) => new Uri(host.Services.GetRequiredService<IServer>()
        .Features.Get<IServerAddressesFeature>()!.Addresses.First()).Port;

    private static int PortOf(HttpContext ctx) => ctx.Connection.LocalPort;

    private string Idp(string path) => $"http://127.0.0.1:{_idpPort}{path}";

    private static string JwksJson(RSA key)
    {
        var p = key.ExportParameters(false);
        static string B64(byte[] bytes) =>
            Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return System.Text.Json.JsonSerializer.Serialize(new
        {
            keys = new[]
            {
                new { kty = "RSA", use = "sig", alg = "RS256", n = B64(p.Modulus!), e = B64(p.Exponent!) },
            },
        });
    }

    private static string IssueToken(RSA signingKey, string subject = "user-A")
    {
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            Audience = Audience,
            NotBefore = DateTime.UtcNow.AddMinutes(-1),
            Expires = DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(signingKey), SecurityAlgorithms.RsaSha256),
            Claims = new Dictionary<string, object> { ["sub"] = subject },
        };
        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    private static InMemoryTokenCache Cache() =>
        new(Options.Create(new TokenCacheOptions()), TimeProvider.System);

    /// <summary>A factory over the same named-client registrations the shipped packages use —
    /// the real transport, with its real defaults. No handler is swapped: the point is what
    /// the shipped client does.</summary>
    private static IHttpClientFactory RealTokenFactory()
    {
        var services = new ServiceCollection();
        services.AddCredProxOAuth();
        services.AddCredProxLoginExchange();
        return services.BuildServiceProvider().GetRequiredService<IHttpClientFactory>();
    }

    private static ISecretAccessor NoSecrets() => TestSecrets.AccessorFor([]);

    // ---- pin 1: direct JWKS behind a 302 ----------------------------------------------
    [Fact]
    public async Task JwksRedirect_IsRefused_AndTheAttackerKeyIsNeverTrusted()
    {
        var provider = new TokenExchangeProvider(Cache(), RealTokenFactory(), TimeProvider.System);
        var options = new TokenExchangeOptions
        {
            Issuer = Issuer,
            InboundAudience = Audience,
            JwksUri = Idp("/.well-known/jwks-302.json"),
            RequireHttpsMetadata = false,
            TokenEndpoint = Idp("/token"),
            ClientId = "cid",
            ClientSecret = "csec",
        };
        var context = new CredentialRequestContext
        {
            CredentialName = "test",
            Partition = "p1",
            InboundToken = IssueToken(AttackerRsa, "admin"),
        };

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => provider
            .GetCredentialAsync(options, NoSecrets(), context, default).AsTask());

        // The refusal names the configured JWKS endpoint and the status; the attacker host
        // is never contacted (AllowAutoRedirect=false refuses before reconnecting).
        Assert.Contains("could not be retrieved", ex.Message, StringComparison.Ordinal);
        Assert.Contains("jwks-302.json", ex.Message, StringComparison.Ordinal);
        Assert.Contains("302", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("EVIL", ex.Message, StringComparison.Ordinal);
        Assert.Empty(_evilHits);
    }

    // ---- pin 2: the discovery document behind a 302 ------------------------------------
    [Fact]
    public async Task DiscoveryRedirect_IsRefused_AndTheAttackerKeyIsNeverTrusted()
    {
        var provider = new TokenExchangeProvider(Cache(), RealTokenFactory(), TimeProvider.System);
        var options = new TokenExchangeOptions
        {
            Issuer = Issuer,
            InboundAudience = Audience,
            Authority = $"http://127.0.0.1:{_idpPort}/disc302",
            RequireHttpsMetadata = false,
            ClientId = "cid",
            ClientSecret = "csec",
        };
        var context = new CredentialRequestContext
        {
            CredentialName = "test",
            Partition = "p1",
            InboundToken = IssueToken(AttackerRsa, "admin"),
        };

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => provider
            .GetCredentialAsync(options, NoSecrets(), context, default).AsTask());

        Assert.Contains("could not be retrieved", ex.Message, StringComparison.Ordinal);
        Assert.Contains("302", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("EVIL", ex.Message, StringComparison.Ordinal);
        Assert.Empty(_evilHits);
    }

    // ---- pin 3: the token-exchange endpoint behind a 302 --------------------------------
    [Fact]
    public async Task TokenExchangeEndpointRedirect_IsRefused_AndNoTokenIsMinted()
    {
        var provider = new TokenExchangeProvider(Cache(), RealTokenFactory(), TimeProvider.System);
        var options = new TokenExchangeOptions
        {
            Issuer = Issuer,
            InboundAudience = Audience,
            JwksUri = Idp("/.well-known/jwks.json"),
            RequireHttpsMetadata = false,
            TokenEndpoint = Idp("/token-302"),
            ClientId = "cid",
            ClientSecret = "csec",
        };
        var context = new CredentialRequestContext
        {
            CredentialName = "test",
            Partition = "p1",
            InboundToken = IssueToken(IssuerRsa),
        };

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => provider
            .GetCredentialAsync(options, NoSecrets(), context, default).AsTask());

        Assert.Contains("test", ex.Message, StringComparison.Ordinal);
        Assert.Empty(_evilHits);
    }

    // ---- pin 4: the client-credentials token endpoint behind a 302 -----------------------
    [Fact]
    public async Task ClientCredentialsTokenEndpointRedirect_IsRefused()
    {
        var provider = new OAuthClientCredentialsProvider(Cache(), RealTokenFactory(), TimeProvider.System);
        var options = new OAuthClientCredentialsOptions
        {
            TokenEndpoint = Idp("/cc-302"),
            ClientId = "cid",
            ClientSecret = "csec",
        };
        var context = new CredentialRequestContext { CredentialName = "test", Partition = "p1" };

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => provider
            .GetCredentialAsync(options, NoSecrets(), context, default).AsTask());

        Assert.Contains("test", ex.Message, StringComparison.Ordinal);
        Assert.Empty(_evilHits);
    }

    // ---- pin 5: the login endpoint behind a 302 ------------------------------------------
    [Fact]
    public async Task LoginEndpointRedirect_IsRefused()
    {
        var provider = new LoginExchangeProvider(Cache(), RealTokenFactory(), TimeProvider.System);
        var options = new LoginExchangeOptions
        {
            LoginEndpoint = Idp("/login-302"),
            Method = "GET",
        };
        var context = new CredentialRequestContext { CredentialName = "acme", Partition = "uat" };

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => provider
            .GetCredentialAsync(options, NoSecrets(), context, default).AsTask());

        Assert.Contains("acme", ex.Message, StringComparison.Ordinal);
        Assert.Empty(_evilHits);
    }

    // ---- pin 6: the per-connection (certificate-carrying) client refuses too --------------
    [Fact]
    public async Task PerConnectionClient_TokenEndpointRedirect_IsRefused()
    {
        using var cert = TestCertificates.CreateSelfSigned("token-client-contoso");
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CredProx:Credentials:conn:Type"] = "TokenExchange",
            ["CredProx:Credentials:conn:Issuer"] = Issuer,
            ["CredProx:Credentials:conn:InboundAudience"] = Audience,
            ["CredProx:Credentials:conn:JwksUri"] = Idp("/.well-known/jwks.json"),
            ["CredProx:Credentials:conn:RequireHttpsMetadata"] = "false",
            ["CredProx:Credentials:conn:TokenEndpoint"] = Idp("/token-302"),
            ["CredProx:Credentials:conn:ClientId"] = "cid",
            ["CredProx:Credentials:conn:ClientSecret"] = "secret:conn-secret",
            ["CredProx:Credentials:conn:Connection"] = "contoso",
            ["CredProx:Connections:contoso:ClientCertificate"] = "secret:conn-cert",
            ["CredProx:Secrets:conn-secret"] = "csec",
            ["CredProx:Secrets:conn-cert"] = TestCertificates.PfxBase64(cert),
        }).Build();

        var services = new ServiceCollection();
        services.AddCredProxTokenCache();
        services.AddCredProxConfigurationSecrets(config);
        services.AddCredProxBuiltInCredentials();
        services.AddCredProxOAuth();
        services.AddCredProxCredentials(config);
        services.AddRouting();
        services.AddReverseProxy().LoadFromMemory([], []).AddCredProx(config);
        var registry = services.BuildServiceProvider().GetRequiredService<CredentialRegistry>();

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => registry
            .Get("conn").GetCredential(
                new CredentialRequestContext
                {
                    CredentialName = "conn",
                    Partition = "p1",
                    InboundToken = IssueToken(IssuerRsa),
                },
                default).AsTask());

        Assert.Contains("conn", ex.Message, StringComparison.Ordinal);
        Assert.Empty(_evilHits);
    }

    // ---- pin 7: the JWT-assertion exchange rides the same clients -------------------------
    [Fact]
    public async Task JwtAssertionEndpointRedirect_IsRefused()
    {
        var provider = new JwtAssertionProvider(Cache(), RealTokenFactory(), TimeProvider.System);
        var options = new JwtAssertionOptions
        {
            Algorithm = JwtAssertionAlgorithm.RS256,
            SigningKey = IssuerRsa.ExportRSAPrivateKeyPem(),
            Issuer = "cid",
            Subject = "cid",
            Audience = Issuer,
            TokenEndpoint = Idp("/jwt-302"),
            ClientId = "cid",
        };
        var context = new CredentialRequestContext { CredentialName = "test", Partition = "p1" };

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => provider
            .GetCredentialAsync(options, NoSecrets(), context, default).AsTask());

        Assert.Contains("test", ex.Message, StringComparison.Ordinal);
        Assert.Empty(_evilHits);
    }

    // ---- pin 8: legitimate (no redirect) acquisition still succeeds — non-regression -----
    [Fact]
    public async Task LegitimateTokenExchange_StillSucceeds()
    {
        var provider = new TokenExchangeProvider(Cache(), RealTokenFactory(), TimeProvider.System);
        var options = new TokenExchangeOptions
        {
            Issuer = Issuer,
            InboundAudience = Audience,
            JwksUri = Idp("/.well-known/jwks.json"),
            RequireHttpsMetadata = false,
            TokenEndpoint = Idp("/token"),
            ClientId = "cid",
            ClientSecret = "csec",
        };
        var context = new CredentialRequestContext
        {
            CredentialName = "test",
            Partition = "p1",
            InboundToken = IssueToken(IssuerRsa),
        };

        var token = await provider.GetCredentialAsync(options, NoSecrets(), context, default);

        Assert.Equal("GOOD-TOKEN", token);
        Assert.Empty(_evilHits);
    }

    // ---- pin 9: legitimate authority discovery still succeeds — non-regression -----------
    [Fact]
    public async Task LegitimateAuthorityDiscovery_StillSucceeds()
    {
        var provider = new TokenExchangeProvider(Cache(), RealTokenFactory(), TimeProvider.System);
        var options = new TokenExchangeOptions
        {
            Issuer = Issuer,
            InboundAudience = Audience,
            Authority = $"http://127.0.0.1:{_idpPort}",
            RequireHttpsMetadata = false,
            ClientId = "cid",
            ClientSecret = "csec",
        };
        var context = new CredentialRequestContext
        {
            CredentialName = "test",
            Partition = "p1",
            InboundToken = IssueToken(IssuerRsa),
        };

        var token = await provider.GetCredentialAsync(options, NoSecrets(), context, default);

        Assert.Equal("GOOD-TOKEN", token);
        Assert.Empty(_evilHits);
    }

    // ---- pin 10: a host's own redirecting primary handler cannot re-enable following -----
    // The host replaced the primary handler (the BCL default follows); the guard refuses
    // the followed response before any of it is believed. The evil host may be contacted
    // — the host asked for following — what must not happen is the token being minted.
    [Fact]
    public async Task HostSuppliedFollowingPrimaryHandler_CannotReEnableFollowing()
    {
        var services = new ServiceCollection();
        services.AddCredProxOAuth();
        services.AddCredProxLoginExchange();
        services.AddHttpClient(CredProxHttpClientNames.TokenClient)
            .ConfigurePrimaryHttpMessageHandler(static () => new SocketsHttpHandler());
        var factory = services.BuildServiceProvider().GetRequiredService<IHttpClientFactory>();

        var provider = new OAuthClientCredentialsProvider(Cache(), factory, TimeProvider.System);
        var options = new OAuthClientCredentialsOptions
        {
            TokenEndpoint = Idp("/cc-302"),
            ClientId = "cid",
            ClientSecret = "csec",
        };
        var context = new CredentialRequestContext { CredentialName = "test", Partition = "p1" };

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => provider
            .GetCredentialAsync(options, NoSecrets(), context, default).AsTask());

        Assert.Contains("never follows redirects", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("EVIL", ex.Message, StringComparison.Ordinal);
    }

    // ---- pin 11: discovery keys cannot be forged through a following host handler --------
    [Fact]
    public async Task HostSuppliedFollowingPrimaryHandler_CannotForgeDiscoveryKeys()
    {
        var services = new ServiceCollection();
        services.AddCredProxOAuth();
        services.AddCredProxLoginExchange();
        services.AddHttpClient(CredProxHttpClientNames.TokenClient)
            .ConfigurePrimaryHttpMessageHandler(static () => new SocketsHttpHandler());
        var factory = services.BuildServiceProvider().GetRequiredService<IHttpClientFactory>();

        var provider = new TokenExchangeProvider(Cache(), factory, TimeProvider.System);
        var options = new TokenExchangeOptions
        {
            Issuer = Issuer,
            InboundAudience = Audience,
            Authority = $"http://127.0.0.1:{_idpPort}/disc302",
            RequireHttpsMetadata = false,
            ClientId = "cid",
            ClientSecret = "csec",
        };
        var context = new CredentialRequestContext
        {
            CredentialName = "test",
            Partition = "p1",
            InboundToken = IssueToken(AttackerRsa, "admin"),
        };

        await Assert.ThrowsAsync<InvalidOperationException>(() => provider
            .GetCredentialAsync(options, NoSecrets(), context, default).AsTask());
    }

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        await _idp.StopAsync();
        _idp.Dispose();
        await _evil.StopAsync();
        _evil.Dispose();
    }
}
