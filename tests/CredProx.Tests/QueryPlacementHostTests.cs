using System.Net;
using System.Net.Http;
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
/// F1 (M9 review) on the real user path: query-location credential placement against a
/// live Kestrel host. On the wire <c>ProxyRequest.RequestUri</c> is null while features
/// run, which made query placement throw into the catch-all (500, upstream never
/// reached). These tests pin the fixed behavior: the credential reaches the upstream
/// exactly once with the caller's value replaced, pass-through parameters and the
/// rewritten path survive, and the URI the upstream sees matches the header-placement
/// control route's — proving the URI the feature builds equals YARP's own assembly.
/// </summary>
public sealed class QueryPlacementHostTests : IAsyncLifetime
{
    private readonly IHost _upstream;
    private readonly IHost _proxy;
    private readonly int _port;

    public QueryPlacementHostTests()
    {
        // The upstream echoes the full URI it received — the vendor's view is the claim.
        // The /qe echo route opts into a text content type so the M20 scrubber's
        // eligibility gate engages (the TestServer transport loses the type WriteAsync
        // infers — it lands after the headers are captured). The M9 routes deliberately
        // stay without one: their claim is the upstream's URI, which scrubbing would
        // hide from the caller by design.
        _upstream = new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.Configure(app => app.Run(context =>
                {
                    if (context.Request.Path.StartsWithSegments("/qe"))
                    {
                        context.Response.ContentType = "text/plain";
                    }

                    return context.Response.WriteAsync(
                        $"{context.Request.Scheme}://{context.Request.Host}{context.Request.Path}{context.Request.QueryString}");
                }));
            })
            .Start();

        var transport = _upstream.GetTestServer().CreateHandler();
        var entries = new Dictionary<string, string?>
        {
            ["CredProx:Credentials:qkey:Type"] = "StaticKey",
            ["CredProx:Credentials:qkey:Secret"] = "secret:q-key",
            ["CredProx:Credentials:qkey:Name"] = "api_key",
            ["CredProx:Credentials:qkey:Location"] = "Query",
            ["CredProx:Credentials:hkey:Type"] = "StaticKey",
            ["CredProx:Credentials:hkey:Secret"] = "secret:h-key",
            ["CredProx:Credentials:hkey:Name"] = "X-Api-Key",
            ["CredProx:Credentials:qenc:Type"] = "StaticKey",
            ["CredProx:Credentials:qenc:Secret"] = "secret:q-enc",
            ["CredProx:Credentials:qenc:Name"] = "api_key",
            ["CredProx:Credentials:qenc:Location"] = "Query",
            ["CredProx:Secrets:q-key"] = "query-cred-value",
            ["CredProx:Secrets:h-key"] = "header-cred-value",
            ["CredProx:Secrets:q-enc"] = "q echo/secret",
        };

        _proxy = new HostBuilder()
            .ConfigureAppConfiguration(build => build.AddInMemoryCollection(entries))
            .ConfigureServices((context, services) =>
            {
                services.AddCredProxTokenCache();
                services.AddCredProxConfigurationSecrets(context.Configuration);
                services.AddCredProxBuiltInCredentials();
                services.AddCredProxCredentials(context.Configuration);
                services.AddRouting();
                services.AddReverseProxy()
                    .LoadFromMemory([QueryRoute, HeaderRoute, QencRoute], [Cluster])
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

    // No CredProx.Destination metadata on either route: the live pipeline must fall back
    // to the selected cluster destination address when building the query URI.
    private static readonly RouteConfig QueryRoute = new()
    {
        RouteId = "q",
        ClusterId = "v",
        Match = new RouteMatch { Path = "/q/{**catch-all}" },
        Transforms = [new Dictionary<string, string> { ["PathRemovePrefix"] = "/q" }],
        Metadata = new Dictionary<string, string> { [CredProxMetadata.Credential] = "qkey" },
    };

    private static readonly RouteConfig HeaderRoute = new()
    {
        RouteId = "h",
        ClusterId = "v",
        Match = new RouteMatch { Path = "/h/{**catch-all}" },
        Transforms = [new Dictionary<string, string> { ["PathRemovePrefix"] = "/h" }],
        Metadata = new Dictionary<string, string> { [CredProxMetadata.Credential] = "hkey" },
    };

    // No prefix removal here: the upstream keys its text content type off the /qe path,
    // and the un-transformed path also proves the echo carries the full outbound URI.
    private static readonly RouteConfig QencRoute = new()
    {
        RouteId = "qe",
        ClusterId = "v",
        Match = new RouteMatch { Path = "/qe/{**catch-all}" },
        Metadata = new Dictionary<string, string> { [CredProxMetadata.Credential] = "qenc" },
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
    public async Task QueryPlacement_LiveHost_CredentialReachesUpstreamOnceCallerValueReplaced()
    {
        using var client = new HttpClient();
        var response = await client.GetAsync(
            $"http://127.0.0.1:{_port}/q/data?x=1&api_key=caller-value");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var seen = await response.Content.ReadAsStringAsync();

        // Rewritten path survives; the caller's api_key is replaced exactly once; the
        // pass-through parameter is preserved.
        Assert.Equal("http://cluster.example/data?x=1&api_key=query-cred-value", seen);
    }

    [Fact]
    public async Task QueryPlacement_UpstreamUriMatchesHeaderPlacementControl()
    {
        using var client = new HttpClient();
        var query = await client.GetAsync(
            $"http://127.0.0.1:{_port}/q/data?x=1&api_key=caller-value");
        var header = await client.GetAsync(
            $"http://127.0.0.1:{_port}/h/data?x=1&api_key=caller-value");

        Assert.Equal(HttpStatusCode.OK, query.StatusCode);
        Assert.Equal(HttpStatusCode.OK, header.StatusCode);

        // The header route leaves the query untouched; the query route differs only in
        // the api_key VALUE. Same scheme/host/path skeleton and same pass-through
        // parameters prove the feature-built URI equals YARP's own assembly.
        var querySeen = await query.Content.ReadAsStringAsync();
        var headerSeen = await header.Content.ReadAsStringAsync();
        Assert.Equal(
            headerSeen.Replace("api_key=caller-value", "api_key=query-cred-value", StringComparison.Ordinal),
            querySeen);
    }

    /// <summary>
    /// M20 review F2: the query placement's third integration surface — an upstream that
    /// echoes the URL back in a text body. The credential travels percent-encoded, so
    /// this is the live end-to-end proof of the registry's encoded form: the caller sees
    /// the marker, never the raw or the encoded secret.
    /// </summary>
    [Fact]
    public async Task QueryPlacement_EchoedUrlScrubbed_EncodedSecretNeverReachesCaller()
    {
        using var client = new HttpClient();
        var response = await client.GetAsync($"http://127.0.0.1:{_port}/qe/data?x=1");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal("http://cluster.example/qe/data?x=1&api_key=[redacted]", body);
        Assert.DoesNotContain("q echo/secret", body, StringComparison.Ordinal);
        Assert.DoesNotContain("q%20echo%2Fsecret", body, StringComparison.Ordinal);
    }
}
