using System.Net;
using System.Net.Http;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Xunit;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;

namespace CredProx.Tests;

/// <summary>
/// Follow-up (d) (M8 review): the buffered-body retry on the REAL pipeline. The
/// handler-level tests replay re-readable <c>StringContent</c>, which cannot catch a
/// regression where the clone path loses the body on a non-re-readable content type —
/// exactly what the live path hands the resilience handler (a forward-only Kestrel
/// request stream behind YARP's content). These tests PUT a known-length body through
/// the full host: the upstream 503s the first attempt and 200s the retry, and BOTH
/// attempts must have carried the full body.
/// </summary>
public sealed class ResilienceRetryHostTests : IAsyncLifetime
{
    private const string Payload = "the quick brown fox jumps over the lazy dog — 0123456789";

    private readonly IHost _upstream;
    private readonly IHost _proxy;
    private readonly int _port;
    private readonly List<string> _upstreamBodies = [];
    private int _attempts;

    public ResilienceRetryHostTests()
    {
        // The upstream records each attempt's full body; the first attempt fails.
        _upstream = new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.Configure(app => app.Run(async context =>
                {
                    var body = await new StreamReader(context.Request.Body, Encoding.UTF8).ReadToEndAsync();
                    lock (_upstreamBodies)
                    {
                        _upstreamBodies.Add(body);
                    }

                    context.Response.StatusCode =
                        Interlocked.Increment(ref _attempts) == 1
                            ? StatusCodes.Status503ServiceUnavailable
                            : StatusCodes.Status200OK;
                }));
            })
            .Start();

        var transport = _upstream.GetTestServer().CreateHandler();
        var entries = new Dictionary<string, string?>
        {
            ["CredProx:Resilience:MaxRetries"] = "1",
            ["CredProx:Resilience:RetryBaseDelay"] = "00:00:00.010",
        };

        _proxy = new HostBuilder()
            .ConfigureAppConfiguration(build => build.AddInMemoryCollection(entries))
            .ConfigureServices((context, services) =>
            {
                services.AddCredProxTokenCache();
                services.AddCredProxConfigurationSecrets(context.Configuration);
                services.AddCredProxBuiltInCredentials();
                services.AddCredProxCredentials(context.Configuration);
                services.AddCredProxResilience(context.Configuration);
                services.AddRouting();
                services.AddReverseProxy()
                    .LoadFromMemory([Route], [Cluster])
                    .AddCredProx(context.Configuration);
                services.AddSingleton<IForwarderHttpClientFactory>(
                    sp => new StubTransportFactory(sp, transport));
            })
            .ConfigureLogging(logging => logging.ClearProviders())
            .ConfigureWebHost(web =>
            {
                web.UseKestrel(options => options.Listen(IPAddress.Loopback, 0));
                web.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints => endpoints.MapReverseProxy());
                });
            })
            .Start();

        _port = new Uri(_proxy.Services
            .GetRequiredService<IServer>()
            .Features.Get<IServerAddressesFeature>()!
            .Addresses.First()).Port;
    }

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        await _proxy.StopAsync();
        _proxy.Dispose();
        await _upstream.StopAsync();
        _upstream.Dispose();
    }

    private static readonly RouteConfig Route = new()
    {
        RouteId = "put",
        ClusterId = "v",
        Match = new RouteMatch { Path = "/data" },
    };

    private static readonly ClusterConfig Cluster = new()
    {
        ClusterId = "v",
        Destinations = new Dictionary<string, DestinationConfig>
        {
            ["static"] = new() { Address = "http://cluster.example/" },
        },
    };

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

    [Fact]
    public async Task Put_KnownLengthBody_503Then200_BothAttemptsCarryTheFullBody()
    {
        using var client = new HttpClient();
        using var request = new HttpRequestMessage(HttpMethod.Put, $"http://127.0.0.1:{_port}/data")
        {
            // Known-length content: the retry-eligible shape (an unknown-length stream
            // is never buffered, never retried — pinned at handler level).
            Content = new StringContent(Payload, Encoding.UTF8, "text/plain"),
        };

        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        string[] bodies;
        lock (_upstreamBodies)
        {
            bodies = [.. _upstreamBodies];
        }

        Assert.Equal(2, bodies.Length); // the retry reached the upstream
        Assert.Equal(Payload, bodies[0]); // first attempt carried the body
        Assert.Equal(Payload, bodies[1]); // the clone replayed it in full
    }
}
