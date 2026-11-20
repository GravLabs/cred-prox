using System.Collections.Concurrent;
using System.Net;
using CredProx;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
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
/// M45 security finding F-4, the documented consequence: header hygiene removes the
/// presented credential, the caller-auth key and the partition header — on routes whose
/// credential is not a caller header value (query placement and friends) the caller's
/// own <c>Authorization</c> and <c>Cookie</c> ride to the vendor unchanged. The control
/// leg measures that status quo; the mitigation leg proves the operator's documented
/// door really closes: YARP's <c>RequestHeaderRemove</c> transform on the route strips
/// both without disturbing credential placement (one entry per header — the plural
/// name circulating in the public discussion does not exist in YARP 2.3.0).
/// </summary>
public sealed class CallerHeaderRideTests : IAsyncLifetime
{
    private readonly IHost _upstream;
    private readonly IHost _proxy;
    private readonly int _port;
    private readonly ConcurrentDictionary<string, (string Auth, string Cookie)> _vendorView = new();

    public CallerHeaderRideTests()
    {
        _upstream = new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.Configure(app => app.Run(context =>
                {
                    var route = (context.Request.Path.Value ?? "/").Split('/')[1];
                    _vendorView[route] = (
                        context.Request.Headers.Authorization.ToString(),
                        context.Request.Headers.Cookie.ToString());
                    return context.Response.WriteAsync(
                        $"{context.Request.Path}{context.Request.QueryString}");
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
            ["CredProx:Secrets:q-key"] = "query-cred-value",
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
                    .LoadFromMemory([PlainRoute, StrippedRoute], [Cluster])
                    .AddCredProx(context.Configuration);
                services.AddSingleton<IForwarderHttpClientFactory>(
                    sp => new StubTransportFactory(sp, transport));
            })
            .ConfigureLogging(logging => logging.ClearProviders())
            .ConfigureWebHost(web =>
            {
                web.UseKestrel(options => options.Listen(System.Net.IPAddress.Loopback, 0));
                web.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints => endpoints.MapReverseProxy());
                });
            })
            .Start();

        _port = new Uri(_proxy.Services
            .GetRequiredService<Microsoft.AspNetCore.Hosting.Server.IServer>()
            .Features.Get<Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature>()!
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

    // No prefix removal: the upstream keys its capture off the first path segment, and
    // the raw outbound path is also part of the claim.
    private static RouteConfig Route(string id, params Dictionary<string, string>[] transforms) => new()
    {
        RouteId = id,
        ClusterId = "v",
        Match = new RouteMatch { Path = $"/{id}/{{**catch-all}}" },
        Transforms = [.. transforms],
        Metadata = new Dictionary<string, string> { [CredProxMetadata.Credential] = "qkey" },
    };

    private static readonly RouteConfig PlainRoute = Route("plain");

    // YARP 2.3.0's name is RequestHeaderRemove — one header per entry; the plural
    // "RequestHeadersRemove" cited by the public discussion does not exist in this
    // version (the Unknown-transform config failure was this pin's first witness).
    private static readonly RouteConfig StrippedRoute = Route(
        "stripped",
        new Dictionary<string, string> { ["RequestHeaderRemove"] = "Authorization" },
        new Dictionary<string, string> { ["RequestHeaderRemove"] = "Cookie" });

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

    private static HttpRequestMessage CallerRequest(string path)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer CALLER-OWN-TOKEN");
        request.Headers.TryAddWithoutValidation("Cookie", "sess=caller-session-cookie");
        return request;
    }

    // ---- the documented status quo: the caller's own secrets ride on ----

    [Fact]
    public async Task QueryPlacedRoute_Control_CallerAuthorizationAndCookieReachVendor()
    {
        using var client = new HttpClient();
        var response = await client.SendAsync(
            CallerRequest($"http://127.0.0.1:{_port}/plain/data?x=1"), HttpCompletionOption.ResponseContentRead);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("/plain/data?x=1&api_key=query-cred-value", await response.Content.ReadAsStringAsync());
        Assert.Equal(("Bearer CALLER-OWN-TOKEN", "sess=caller-session-cookie"), _vendorView["plain"]);
    }

    // ---- the documented mitigation, proven to work ----

    [Fact]
    public async Task QueryPlacedRoute_RequestHeaderRemove_VendorSeesNeitherCallerHeader()
    {
        using var client = new HttpClient();
        var response = await client.SendAsync(
            CallerRequest($"http://127.0.0.1:{_port}/stripped/data?x=1"), HttpCompletionOption.ResponseContentRead);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        // The credential placement itself is untouched by the strip:
        Assert.Equal("/stripped/data?x=1&api_key=query-cred-value", await response.Content.ReadAsStringAsync());
        var (auth, cookie) = _vendorView["stripped"];
        Assert.Equal(string.Empty, auth);
        Assert.Equal(string.Empty, cookie);
    }
}
