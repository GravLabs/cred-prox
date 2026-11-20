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
/// M45 security finding F-4, the default change: header hygiene now removes the caller's
/// own <c>Authorization</c> and <c>Cookie</c> on every route, so a credential of the
/// caller's cannot ride to a third party. A route opts out with metadata
/// <c>CredProx.CallerHeaderStrip = "off"</c> (ADR-0006: a switch that says off is off;
/// any other value strips like every other route). CredProx's own attachments survive:
/// a header-placed vendor credential replaces the stripped slot (attachment runs after
/// hygiene), and query placement is untouched by it. YARP's <c>RequestHeaderRemove</c>
/// transform still works alongside the default (one entry per header — the plural name
/// circulating in the public discussion does not exist in YARP 2.3.0).
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
            // Header placement (the default): the attached credential owns the vendor's
            // Authorization slot and must survive the caller-header strip.
            ["CredProx:Credentials:hkey:Type"] = "StaticKey",
            ["CredProx:Credentials:hkey:Secret"] = "secret:h-key",
            ["CredProx:Credentials:hkey:Name"] = "Authorization",
            ["CredProx:Secrets:h-key"] = "vendor-h-key-value",
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
                    .LoadFromMemory([PlainRoute, StrippedRoute, RidingRoute, MisspeltRoute, HeaderPlacedRoute], [Cluster])
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
    private static RouteConfig Route(string id, string credential = "qkey", params Dictionary<string, string>[] transforms) => new()
    {
        RouteId = id,
        ClusterId = "v",
        Match = new RouteMatch { Path = $"/{id}/{{**catch-all}}" },
        Transforms = [.. transforms],
        Metadata = new Dictionary<string, string> { [CredProxMetadata.Credential] = credential },
    };

    private static RouteConfig WithMetadata(RouteConfig route, string key, string value)
    {
        var metadata = new Dictionary<string, string>(route.Metadata!) { [key] = value };
        return new RouteConfig
        {
            RouteId = route.RouteId,
            ClusterId = route.ClusterId,
            Match = route.Match,
            Transforms = route.Transforms,
            Metadata = metadata,
        };
    }

    private static readonly RouteConfig PlainRoute = Route("plain");

    // YARP 2.3.0's name is RequestHeaderRemove — one header per entry; the plural
    // "RequestHeadersRemove" cited by the public discussion does not exist in this
    // version (the Unknown-transform config failure was this pin's first witness).
    private static readonly RouteConfig StrippedRoute = Route(
        "stripped",
        transforms: [
            new Dictionary<string, string> { ["RequestHeaderRemove"] = "Authorization" },
            new Dictionary<string, string> { ["RequestHeaderRemove"] = "Cookie" },
        ]);

    // The M47 F-4 door: this route alone keeps the old ride.
    private static readonly RouteConfig RidingRoute =
        WithMetadata(Route("riding"), CredProxMetadata.CallerHeaderStrip, "off");

    private static readonly RouteConfig MisspeltRoute =
        WithMetadata(Route("ridingmisspelt"), CredProxMetadata.CallerHeaderStrip, "nope");

    private static readonly RouteConfig HeaderPlacedRoute = Route("hdr", credential: "hkey");

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

    // ---- the new default: the caller's own secrets do not ride ----

    [Fact]
    public async Task QueryPlacedRoute_Default_CallerAuthorizationAndCookieAreStripped()
    {
        using var client = new HttpClient();
        var response = await client.SendAsync(
            CallerRequest($"http://127.0.0.1:{_port}/plain/data?x=1"), HttpCompletionOption.ResponseContentRead);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        // The route's own credential placement is untouched by the strip:
        Assert.Equal("/plain/data?x=1&api_key=query-cred-value", await response.Content.ReadAsStringAsync());
        var (auth, cookie) = _vendorView["plain"];
        Assert.Equal(string.Empty, auth);
        Assert.Equal(string.Empty, cookie);
    }

    // ---- the documented door still works alongside the default ----

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

    // ---- the per-route switch (ADR-0006: off means off; anything else is the default) ----

    [Fact]
    public async Task CallerHeaderStripOff_CallerAuthorizationAndCookieStillRide()
    {
        using var client = new HttpClient();
        var response = await client.SendAsync(
            CallerRequest($"http://127.0.0.1:{_port}/riding/data?x=1"), HttpCompletionOption.ResponseContentRead);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("/riding/data?x=1&api_key=query-cred-value", await response.Content.ReadAsStringAsync());
        Assert.Equal(("Bearer CALLER-OWN-TOKEN", "sess=caller-session-cookie"), _vendorView["riding"]);
    }

    [Fact]
    public async Task CallerHeaderStripMisspelt_StripsLikeEveryRoute()
    {
        using var client = new HttpClient();
        var response = await client.SendAsync(
            CallerRequest($"http://127.0.0.1:{_port}/ridingmisspelt/data?x=1"), HttpCompletionOption.ResponseContentRead);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var (auth, cookie) = _vendorView["ridingmisspelt"];
        Assert.Equal(string.Empty, auth);
        Assert.Equal(string.Empty, cookie);
    }

    // ---- the survival case: the credential CredProx attaches IS the header ----

    [Fact]
    public async Task HeaderPlacedCredential_SurvivesTheDefaultStrip()
    {
        using var client = new HttpClient();
        var response = await client.SendAsync(
            CallerRequest($"http://127.0.0.1:{_port}/hdr/data?x=1"), HttpCompletionOption.ResponseContentRead);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("/hdr/data?x=1", await response.Content.ReadAsStringAsync());
        var (auth, cookie) = _vendorView["hdr"];
        // Only the vendor's own credential arrives: the caller's token is gone, the
        // attached one replaced the stripped slot (attachment runs after hygiene).
        Assert.Equal("vendor-h-key-value", auth);
        Assert.Equal(string.Empty, cookie);
    }
}
