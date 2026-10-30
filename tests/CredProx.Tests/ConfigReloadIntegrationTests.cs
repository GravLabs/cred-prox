using System.Net;
using CredProx;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;
using Yarp.ReverseProxy.Forwarder;

namespace CredProx.Tests;

/// <summary>
/// The config-reload story (M5, notes N1/N2) through the real YARP pipeline: a reload that
/// adds a destination and a route referencing it starts serving without a restart, and a
/// reload that introduces an unknown <c>CredProx.Credential</c> reference is refused by the
/// YARP validation hook — the previously applied configuration keeps serving.
/// </summary>
public sealed class ConfigReloadIntegrationTests : IAsyncLifetime
{
    private readonly IHost _upstream;
    private readonly List<string> _upstreamPaths = [];
    private readonly List<Dictionary<string, string?>> _upstreamHeaders = [];

    public ConfigReloadIntegrationTests()
    {
        _upstream = new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.Configure(app => app.Run(context =>
                {
                    _upstreamPaths.Add(context.Request.Path + context.Request.QueryString);
                    _upstreamHeaders.Add(new Dictionary<string, string?>
                    {
                        ["X-Contoso"] = context.Request.Headers["X-Contoso"],
                        ["X-API-Key"] = context.Request.Headers["X-API-Key"],
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

    private static Dictionary<string, string?> BaseEntries() => new()
    {
        // A healthy starting point: one route, one destination, one static-key credential.
        ["CredProx:Destinations:acme:Template"] = "http://upstream.example/acme",
        ["CredProx:Credentials:contoso:Type"] = "StaticKey",
        ["CredProx:Credentials:contoso:Secret"] = "secret:contoso-key",
        ["CredProx:Credentials:contoso:Name"] = "X-Contoso",
        ["CredProx:Secrets:contoso-key"] = "contoso-key-value",
        ["ReverseProxy:Routes:acme:ClusterId"] = "acme",
        ["ReverseProxy:Routes:acme:Match:Path"] = "/acme/{**catch-all}",
        ["ReverseProxy:Routes:acme:Metadata:CredProx.Destination"] = "acme",
        ["ReverseProxy:Routes:acme:Metadata:CredProx.Credential"] = "contoso",
        ["ReverseProxy:Clusters:acme:Destinations:static:Address"] = "http://static.example/",
    };

    private (IHost Host, ReloadableMemoryConfigurationProvider Reloadable) StartProxyHost()
    {
        var source = new ReloadableMemoryConfigurationSource(BaseEntries());
        var transport = _upstream.GetTestServer().CreateHandler();

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

                // The forwarder's transport is the in-process upstream (the plan's
                // subclass extension point), so the reload path is exercised without sockets.
                services.AddSingleton<IForwarderHttpClientFactory>(
                    sp => new StubTransportFactory(sp, transport));
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

        var reloadable = ((IConfigurationRoot)host.Services.GetRequiredService<IConfiguration>()).Providers
            .OfType<ReloadableMemoryConfigurationProvider>().Single();
        return (host, reloadable);
    }

    private sealed class StubTransportFactory(IServiceProvider services, HttpMessageHandler transport)
        : CredProxForwarderHttpClientFactory(services)
    {
        protected override HttpMessageHandler WrapHandler(
            ForwarderHttpClientContext context, HttpMessageHandler handler)
        {
            handler.Dispose(); // the sockets transport is not used in-process
            return ComposePipeline(context, transport);
        }
    }

    private static async Task WaitFor(Func<Task<bool>> condition, string because)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(10);
        while (DateTime.UtcNow < deadline)
        {
            if (await condition())
            {
                return;
            }

            await Task.Delay(50);
        }

        throw new TimeoutException($"Timed out waiting for: {because}");
    }

    [Fact]
    public async Task Reload_AddsDestinationAndRoute_ServedWithoutRestart()
    {
        var (host, reloadable) = StartProxyHost();
        using (host)
        {
            var client = host.GetTestClient();
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("http://proxy/acme/thing")).StatusCode);

            // The same reload adds a destination and the route that references it.
            reloadable.Set("CredProx:Destinations:late:Template", "http://upstream.example/late");
            reloadable.Set("ReverseProxy:Routes:late:ClusterId", "late");
            reloadable.Set("ReverseProxy:Routes:late:Match:Path", "/late/{**catch-all}");
            reloadable.Set("ReverseProxy:Routes:late:Metadata:CredProx.Destination", "late");
            reloadable.Set("ReverseProxy:Routes:late:Metadata:CredProx.Credential", "contoso");
            reloadable.Set("ReverseProxy:Clusters:late:Destinations:static:Address", "http://static.example/");
            reloadable.Reload();

            await WaitFor(
                async () => (await client.GetAsync("http://proxy/late/thing")).StatusCode == HttpStatusCode.OK,
                "the reload-added route to serve");

            var path = _upstreamPaths.Last();
            Assert.Contains("/late/late/thing", path); // destination prefix replaced, path preserved
            Assert.Equal("contoso-key-value", _upstreamHeaders.Last()["X-Contoso"]); // credential attached
        }
    }

    [Fact]
    public async Task Reload_UnknownCredentialReference_Refused_OldConfigKeepsServing()
    {
        var (host, reloadable) = StartProxyHost();
        using (host)
        {
            var client = host.GetTestClient();
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("http://proxy/acme/thing")).StatusCode);

            // A route referencing a credential that exists nowhere: the validation hook
            // refuses the whole load, so the good configuration stays live.
            reloadable.Set("ReverseProxy:Routes:ghost:ClusterId", "ghost");
            reloadable.Set("ReverseProxy:Routes:ghost:Match:Path", "/ghost/{**catch-all}");
            reloadable.Set("ReverseProxy:Routes:ghost:Metadata:CredProx.Credential", "nowhere");
            reloadable.Set("ReverseProxy:Clusters:ghost:Destinations:static:Address", "http://static.example/");
            reloadable.Reload();

            // Give YARP's reload loop time to process (and reject) the change, then confirm
            // the old configuration still serves and the refused route never appears.
            await Task.Delay(500);
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("http://proxy/acme/thing")).StatusCode);
            Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("http://proxy/ghost/thing")).StatusCode);
            Assert.All(_upstreamPaths, p => Assert.DoesNotContain("/ghost", p));
        }
    }

    [Fact]
    public async Task Reload_CredentialAddedByReload_RouteThatReferencedItStartsWorking()
    {
        // The route exists from the start but its credential arrives only with the reload.
        var entries = BaseEntries();
        entries.Remove("ReverseProxy:Routes:acme:Metadata:CredProx.Credential");
        var source = new ReloadableMemoryConfigurationSource(entries);
        var transport = _upstream.GetTestServer().CreateHandler();
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
                services.AddSingleton<IForwarderHttpClientFactory>(
                    sp => new StubTransportFactory(sp, transport));
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
        using (host)
        {
            var reloadable = ((IConfigurationRoot)host.Services.GetRequiredService<IConfiguration>()).Providers
                .OfType<ReloadableMemoryConfigurationProvider>().Single();
            var client = host.GetTestClient();

            // No credential metadata: the route forwards without attaching anything.
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("http://proxy/acme/thing")).StatusCode);
            Assert.True(string.IsNullOrEmpty(_upstreamHeaders.Last()["X-Contoso"]));

            reloadable.Set("ReverseProxy:Routes:acme:Metadata:CredProx.Credential", "contoso");
            reloadable.Reload();

            await WaitFor(
                async () =>
                {
                    _upstreamPaths.Clear();
                    _upstreamHeaders.Clear();
                    return (await client.GetAsync("http://proxy/acme/thing")).StatusCode == HttpStatusCode.OK
                        && _upstreamHeaders.LastOrDefault()?["X-Contoso"] == "contoso-key-value";
                },
                "the reload-added credential to attach");
        }
    }
}
