using System.Net;
using CredProx;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The TLS shape of M45 security finding F-1: an https endpoint that redirects to another
/// https host is followed by the BCL default (measured over TLS in the M45 evidence), and
/// the redirect target's key set or token response is then believed. Over TLS the shipped
/// clients themselves are pinned by the plain-HTTP suite plus the handler property pins —
/// a test cannot install a trust root for them — so this file pins the case a test can
/// honestly drive: a host-supplied primary handler (with its own trust policy, the
/// supported host shape) must still have its followed response refused by the guard.
/// </summary>
public sealed class CredentialRedirectTlsRefusalTests : IAsyncLifetime
{
    private readonly X509CertificatesHolder _certs = new();
    private readonly IHost _idp;
    private readonly IHost _evil;
    private readonly int _idpPort;
    private readonly int _evilPort;

    public CredentialRedirectTlsRefusalTests()
    {
        _evil = new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseKestrel(o => o.Listen(IPAddress.Loopback, 0, l => l.UseHttps(_certs.Evil)));
                web.ConfigureLogging(l => l.ClearProviders());
                web.Configure(app => app.Run(ctx => ctx.Response.WriteAsync(
                    """{"access_token":"EVIL-TOKEN","expires_in":3600,"token_type":"Bearer"}""")));
            })
            .Start();
        _evilPort = ReadPort(_evil);

        _idp = new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseKestrel(o => o.Listen(IPAddress.Loopback, 0, l => l.UseHttps(_certs.Idp)));
                web.ConfigureLogging(l => l.ClearProviders());
                web.Configure(app => app.Run(ctx =>
                {
                    // https -> https, cross-authority: measured to be followed by the
                    // BCL default.
                    ctx.Response.StatusCode = 302;
                    ctx.Response.Headers.Location = $"https://127.0.0.1:{_evilPort}/token-target";
                    return Task.CompletedTask;
                }));
            })
            .Start();
        _idpPort = ReadPort(_idp);
    }

    private static int ReadPort(IHost host) => new Uri(host.Services.GetRequiredService<IServer>()
        .Features.Get<IServerAddressesFeature>()!.Addresses.First()).Port;

    [Fact]
    public async Task HostSuppliedTlsPrimaryHandler_FollowedResponseIsRefused()
    {
        var services = new ServiceCollection();
        services.AddCredProxOAuth();
        services.AddCredProxLoginExchange();
        // The supported host shape for a private trust root: their own primary handler
        // with a trust callback. Its AllowAutoRedirect default follows — the guard must
        // still refuse whatever comes back.
        services.AddHttpClient(CredProxHttpClientNames.TokenClient)
            .ConfigurePrimaryHttpMessageHandler(static () => new SocketsHttpHandler
            {
                SslOptions = { RemoteCertificateValidationCallback = static (_, _, _, _) => true },
            });
        var factory = services.BuildServiceProvider().GetRequiredService<IHttpClientFactory>();

        var cache = new InMemoryTokenCache(Options.Create(new TokenCacheOptions()), TimeProvider.System);
        var provider = new OAuthClientCredentialsProvider(cache, factory, TimeProvider.System);
        var options = new OAuthClientCredentialsOptions
        {
            TokenEndpoint = $"https://127.0.0.1:{_idpPort}/token",
            ClientId = "cid",
            ClientSecret = "csec",
        };
        var context = new CredentialRequestContext { CredentialName = "test", Partition = "p1" };

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => provider
            .GetCredentialAsync(options, TestSecrets.AccessorFor([]), context, default).AsTask());

        Assert.Contains("never follows redirects", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("EVIL", ex.Message, StringComparison.Ordinal);
    }

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        await _idp.StopAsync();
        _idp.Dispose();
        await _evil.StopAsync();
        _evil.Dispose();
        _certs.Dispose();
    }

    private sealed class X509CertificatesHolder : IDisposable
    {
        public X509CertificatesHolder()
        {
            Idp = TestCertificates.CreateSelfSigned("pin-redirect-tls-idp");
            Evil = TestCertificates.CreateSelfSigned("pin-redirect-tls-evil");
        }

        public System.Security.Cryptography.X509Certificates.X509Certificate2 Idp { get; }
        public System.Security.Cryptography.X509Certificates.X509Certificate2 Evil { get; }

        public void Dispose()
        {
            Idp.Dispose();
            Evil.Dispose();
        }
    }
}
