using System.Net;
using System.Security.Cryptography.X509Certificates;
using CredProx;
using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Configurations;
using DotNet.Testcontainers.Containers;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;
using Yarp.ReverseProxy.Forwarder;

namespace CredProx.E2ETests;

/// <summary>
/// The plan §5.2 Connections row over a real socket: nginx with
/// <c>ssl_verify_client on</c> presents the client certificate subject, so CredProx's
/// per-cluster client certificate and the rotation path (rotated secret + config reload →
/// next connection presents the new certificate) are verified from the server's side, not
/// from inside CredProx's own objects.
/// </summary>
public sealed class NginxMTlsTests : IClassFixture<NginxMTlsFixture>
{
    private readonly NginxMTlsFixture _nginx;

    public NginxMTlsTests(NginxMTlsFixture nginx) => _nginx = nginx;

    [DockerFact]
    public async Task ClusterWithConnection_PresentsItsClientCertificate_VerifiedByNginx()
    {
        var host = StartProxy(_nginx, out _);
        using (host)
        {
            var client = host.GetTestClient();

            var response = await client.GetAsync("http://proxy/hello");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Contains("CN=client-alpha", await response.Content.ReadAsStringAsync());

            // The control: a cluster without a connection has no certificate to offer, and
            // nginx really is enforcing verification.
            var refused = await client.GetAsync("http://proxy/anon/hello");
            Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        }
    }

    [DockerFact]
    public async Task RotatedClientCertificate_NextConnectionPresentsTheNewCertificate()
    {
        var host = StartProxy(_nginx, out var reloadable);
        using (host)
        {
            var client = host.GetTestClient();
            Assert.Contains("CN=client-alpha", await client.GetStringAsync("http://proxy/hello"));

            // One reload carries both signals: the rotated secret value and YARP's proxy
            // config reload. The reuse stamp (connection name, version) changes, the
            // cluster client is rebuilt, and the new TLS connection presents client-beta.
            reloadable.Set("CredProx:Secrets:alpha-cert", _nginx.Pki.ClientBetaBundlePem);
            reloadable.Reload();

            await WaitFor(async () =>
            {
                try
                {
                    return (await client.GetStringAsync("http://proxy/hello"))
                        .Contains("CN=client-beta", StringComparison.Ordinal);
                }
                catch (HttpRequestException)
                {
                    return false; // mid-rebuild: the old client may already be gone
                }
            }, "nginx to see the rotated client certificate");
        }
    }

    private IHost StartProxy(NginxMTlsFixture nginx, out ReloadableMemoryConfigurationProvider reloadable)
    {
        var entries = new Dictionary<string, string?>
        {
            ["CredProx:Connections:alpha:ClientCertificate"] = "secret:alpha-cert",
            ["CredProx:Secrets:alpha-cert"] = nginx.Pki.ClientAlphaBundlePem,
            ["ReverseProxy:Routes:secure:ClusterId"] = "secure",
            ["ReverseProxy:Routes:secure:Match:Path"] = "/{**catch-all}",
            ["ReverseProxy:Clusters:secure:Destinations:nginx:Address"] = $"https://localhost:{nginx.Port}/",
            ["ReverseProxy:Clusters:secure:Metadata:CredProx.Connection"] = "alpha",
            // No Connection metadata: nginx must refuse this cluster.
            ["ReverseProxy:Routes:anon:ClusterId"] = "anon",
            ["ReverseProxy:Routes:anon:Match:Path"] = "/anon/{**catch-all}",
            ["ReverseProxy:Clusters:anon:Destinations:nginx:Address"] = $"https://localhost:{nginx.Port}/",
        };
        var source = new ReloadableMemoryConfigurationSource(entries);

        var host = new HostBuilder()
            .ConfigureAppConfiguration(build => build.Add(source))
            .ConfigureServices((context, services) =>
            {
                services.AddCredProxTokenCache();
                services.AddCredProxConfigurationSecrets(context.Configuration);
                services.AddCredProxBuiltInCredentials();
                services.AddCredProxCredentials(context.Configuration);
                services.AddRouting();
                services.AddReverseProxy()
                    .LoadFromConfig(context.Configuration.GetSection("ReverseProxy"))
                    .AddCredProx(context.Configuration);

                // Real sockets transport; the throwaway CA is not in the machine trust
                // store, so the factory pins the server certificate it expects instead.
                services.AddSingleton<IForwarderHttpClientFactory>(sp =>
                    new PinnedServerTrustFactory(sp, nginx.Pki.ServerCertificateThumbprint));
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

        reloadable = ((IConfigurationRoot)host.Services.GetRequiredService<IConfiguration>()).Providers
            .OfType<ReloadableMemoryConfigurationProvider>().Single();
        return host;
    }

    private sealed class PinnedServerTrustFactory(IServiceProvider services, string serverThumbprint)
        : CredProxForwarderHttpClientFactory(services)
    {
        protected override void ConfigureHandler(ForwarderHttpClientContext context, SocketsHttpHandler handler)
        {
            base.ConfigureHandler(context, handler);
            handler.SslOptions.RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                certificate is not null
                && string.Equals(
                    certificate.GetCertHashString(),
                    serverThumbprint,
                    StringComparison.OrdinalIgnoreCase);
        }
    }

    private static async Task WaitFor(Func<Task<bool>> condition, string because)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(30);
        while (DateTime.UtcNow < deadline)
        {
            if (await condition())
            {
                return;
            }

            await Task.Delay(200);
        }

        throw new TimeoutException($"Timed out waiting for: {because}");
    }
}

/// <summary>
/// One nginx container for the class: PKI generated in a temp directory, bind-mounted,
/// <c>ssl_verify_client on</c>, and every accepted request answered with the client
/// certificate subject nginx saw.
/// </summary>
public sealed class NginxMTlsFixture : IAsyncLifetime
{
    private const string NginxConf = """
        pid /tmp/nginx.pid;
        error_log /dev/stderr warn;
        events { worker_connections 128; }
        http {
            access_log off;
            server {
                listen 443 ssl;
                ssl_certificate /etc/nginx/e2e/server.crt;
                ssl_certificate_key /etc/nginx/e2e/server.key;
                ssl_client_certificate /etc/nginx/e2e/ca.crt;
                ssl_verify_client on;
                location / { return 200 "$ssl_client_s_dn\n"; }
            }
        }
        """;

    private string _directory = null!;

    internal E2ECertificates.TestPki Pki { get; private set; } = null!;

    public IContainer Nginx { get; private set; } = null!;

    public int Port { get; private set; }

    public async Task InitializeAsync()
    {
        if (!DockerFactAttribute.IsAvailable)
        {
            return; // the tests skip; xunit still builds the fixture, so stay inert
        }

        Pki = E2ECertificates.Create();
        _directory = Path.Combine(Path.GetTempPath(), "credprox-e2e-nginx-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_directory);
        File.WriteAllText(Path.Combine(_directory, "ca.crt"), Pki.CaCertificatePem);
        File.WriteAllText(Path.Combine(_directory, "server.crt"), Pki.ServerCertificatePem);
        File.WriteAllText(Path.Combine(_directory, "server.key"), Pki.ServerPrivateKeyPem);
        File.WriteAllText(Path.Combine(_directory, "nginx.conf"), NginxConf);

        Nginx = new ContainerBuilder("nginx:1.27-alpine")
            .WithBindMount(_directory, "/etc/nginx/e2e", AccessMode.ReadOnly)
            .WithCommand("nginx", "-c", "/etc/nginx/e2e/nginx.conf", "-g", "daemon off;")
            .WithPortBinding(443, true)
            .WithWaitStrategy(Wait.ForUnixContainer().UntilExternalTcpPortIsAvailable(443))
            .Build();
        await Nginx.StartAsync();
        Port = Nginx.GetMappedPublicPort(443);
    }

    public async Task DisposeAsync()
    {
        if (Nginx is null)
        {
            return;
        }

        try
        {
            await Nginx.StopAsync();
            await Nginx.DisposeAsync();
        }
        finally
        {
            try
            {
                Directory.Delete(_directory, recursive: true);
            }
            catch (IOException)
            {
                // Best effort: the temp directory is not the test's assertion.
            }
        }
    }
}
