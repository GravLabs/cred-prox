using System.Net;
using System.Security.Cryptography;
using CredProx;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The caller-token half of M45 security finding F-1: inbound validation fetches OIDC
/// metadata and keys through the JwtBearer backchannel, which CredProx did not configure.
/// An authority that answers discovery (or the JWKS fetch) with a redirect to another
/// host hands the validation path that host's key set — a token the real issuer never
/// signed then authenticates the caller. These pins drive the real sockets over loopback
/// (a stub handler never follows redirects, so only real ones measure this) and assert
/// the forged token is refused. The honest-authority pins are the non-regression net:
/// fixing the redirect must not break normal discovery.
/// </summary>
public sealed class CallerTokenDiscoveryRedirectTests : IAsyncLifetime
{
    private const string Audience = "api://credprox-test";
    private static readonly RSA IssuerRsa = RSA.Create(2048);
    private static readonly RSA AttackerRsa = RSA.Create(2048);

    private readonly IHost _idp;
    private readonly IHost _evil;
    private readonly int _idpPort;
    private readonly int _evilPort;

    public CallerTokenDiscoveryRedirectTests()
    {
        _evil = new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseKestrel(o => o.Listen(IPAddress.Loopback, 0));
                web.ConfigureLogging(l => l.ClearProviders());
                web.Configure(app => app.Run(async ctx =>
                {
                    ctx.Response.ContentType = "application/json";
                    if (ctx.Request.Path.StartsWithSegments("/metadata"))
                    {
                        // Echo the issuer the redirecting idp asked us to claim, so the
                        // forged metadata passes issuer validation exactly as a real
                        // compromised-authority answer would.
                        await ctx.Response.WriteAsync(Metadata(
                            ctx.Request.Query["issuer"].ToString(),
                            $"http://127.0.0.1:{_evilPort}/jwks"));
                        return;
                    }

                    await ctx.Response.WriteAsync(Jwks(AttackerRsa, "evil-key"));
                }));
            })
            .Start();
        _evilPort = ReadPort(_evil);

        _idp = new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseKestrel(o => o.Listen(IPAddress.Loopback, 0));
                web.ConfigureLogging(l => l.ClearProviders());
                web.Configure(app => app.Run(async ctx =>
                {
                    var path = ctx.Request.Path.Value ?? "/";
                    if (path.StartsWith("/disc-redirect/", StringComparison.Ordinal)
                        && path.EndsWith("/.well-known/openid-configuration", StringComparison.Ordinal))
                    {
                        // Discovery itself redirects to another host.
                        ctx.Response.StatusCode = 302;
                        ctx.Response.Headers.Location =
                            $"http://127.0.0.1:{_evilPort}/metadata?issuer="
                            + Uri.EscapeDataString($"http://127.0.0.1:{_idpPort}/disc-redirect");
                        return;
                    }

                    if (path == "/jwks-redirect/.well-known/openid-configuration")
                    {
                        ctx.Response.ContentType = "application/json";
                        await ctx.Response.WriteAsync(Metadata(
                            $"http://127.0.0.1:{_idpPort}/jwks-redirect",
                            $"http://127.0.0.1:{_idpPort}/jwks-redirect/jwks"));
                        return;
                    }

                    if (path == "/jwks-redirect/jwks")
                    {
                        // Honest metadata; the key fetch alone redirects.
                        ctx.Response.StatusCode = 302;
                        ctx.Response.Headers.Location = $"http://127.0.0.1:{_evilPort}/jwks";
                        return;
                    }

                    if (path == "/good/.well-known/openid-configuration")
                    {
                        ctx.Response.ContentType = "application/json";
                        await ctx.Response.WriteAsync(Metadata(
                            $"http://127.0.0.1:{_idpPort}/good",
                            $"http://127.0.0.1:{_idpPort}/good/jwks"));
                        return;
                    }

                    if (path == "/good/jwks")
                    {
                        ctx.Response.ContentType = "application/json";
                        await ctx.Response.WriteAsync(Jwks(IssuerRsa, "idp-key"));
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

    private static string Metadata(string issuer, string jwksUri) =>
        $$"""{"issuer":"{{issuer}}","jwks_uri":"{{jwksUri}}","subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]}""";

    private static string Jwks(RSA key, string kid)
    {
        var p = key.ExportParameters(false);
        return $$"""{"keys":[{"kty":"RSA","use":"sig","kid":"{{kid}}","alg":"RS256","n":"{{Base64UrlEncoder.Encode(p.Modulus!)}}","e":"{{Base64UrlEncoder.Encode(p.Exponent!)}}"}]}""";
    }

    private IHost StartApi(string mode)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CredProx:CallerToken:Authority"] = $"http://127.0.0.1:{_idpPort}/{mode}",
            ["CredProx:CallerToken:Audience"] = Audience,
            // The offline knob, applied exactly as documented: an http authority is
            // admitted here because it is loopback, which is what makes the redirect
            // testable — the redirect refusal must hold regardless of this knob.
            ["CredProx:CallerToken:RequireHttpsMetadata"] = "false",
            ["CredProx:Callers:agent-1:TokenClientIds:0"] = "client-sec-a",
        }).Build();
        return new HostBuilder()
            .ConfigureServices(services =>
            {
                services.AddCredProxConfigurationSecrets(configuration);
                services.AddCredProxCallerTokenAuthentication(configuration);
            })
            .ConfigureLogging(l => l.ClearProviders())
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.Configure(app => app.Run(async ctx =>
                {
                    var result = await ctx.AuthenticateAsync(CallerTokenOptions.Scheme);
                    if (!result.Succeeded)
                    {
                        ctx.Response.StatusCode = 401;
                        return;
                    }

                    await ctx.Response.WriteAsync("caller-authenticated");
                }));
            })
            .Start();
    }

    private static string IssueToken(RSA signingKey, string kid, string issuer)
    {
        var start = DateTimeOffset.UtcNow;
        // The key's KeyId becomes the header kid, which is what routes validation to
        // the matching JWKS entry.
        var securityKey = new RsaSecurityKey(signingKey) { KeyId = kid };
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = Audience,
            NotBefore = start.AddMinutes(-1).UtcDateTime,
            Expires = start.AddMinutes(5).UtcDateTime,
            SigningCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256),
        };
        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    private static async Task<HttpStatusCode> AuthenticateAsync(IHost api, string token)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy/anything");
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + token);
        using var response = await api.GetTestClient().SendAsync(request);
        return response.StatusCode;
    }

    [Fact]
    public async Task DiscoveryRedirectsToEvil_ForgedToken_IsRefused()
    {
        using var api = StartApi("disc-redirect");
        var forged = IssueToken(AttackerRsa, "evil-key", $"http://127.0.0.1:{_idpPort}/disc-redirect");
        Assert.Equal(HttpStatusCode.Unauthorized, await AuthenticateAsync(api, forged));
    }

    [Fact]
    public async Task JwksFetchRedirectsToEvil_ForgedToken_IsRefused()
    {
        using var api = StartApi("jwks-redirect");
        var forged = IssueToken(AttackerRsa, "evil-key", $"http://127.0.0.1:{_idpPort}/jwks-redirect");
        Assert.Equal(HttpStatusCode.Unauthorized, await AuthenticateAsync(api, forged));
    }

    [Fact]
    public async Task HonestAuthority_ForgedToken_IsRefused()
    {
        // Control for the two pins above: the same attacker key is refused the moment
        // no redirect moved the trust to it — a pass here proves a refusal below is
        // the fix refusing the fetch, not the harness failing to authenticate at all.
        using var api = StartApi("good");
        var forged = IssueToken(AttackerRsa, "evil-key", $"http://127.0.0.1:{_idpPort}/good");
        Assert.Equal(HttpStatusCode.Unauthorized, await AuthenticateAsync(api, forged));
    }

    [Fact]
    public async Task HonestAuthority_IssuerSignedToken_IsAccepted()
    {
        using var api = StartApi("good");
        var honest = IssueToken(IssuerRsa, "idp-key", $"http://127.0.0.1:{_idpPort}/good");
        Assert.Equal(HttpStatusCode.OK, await AuthenticateAsync(api, honest));
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
