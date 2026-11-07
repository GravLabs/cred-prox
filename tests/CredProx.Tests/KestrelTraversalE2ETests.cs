using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using CredProx;
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
/// The real-user-path traversal check (carried from the M6 review): the allow-list's raw
/// path scan is verified against a live Kestrel wire, not just TestServer. Kestrel
/// percent-decodes and dot-segment-normalizes the path but deliberately keeps <c>%2F</c>
/// encoded, so the shapes that matter on the wire are: a clean path (admitted), a
/// surviving <c>%2f</c> (refused by the raw scan), and <c>%2e%2e</c> (normalized away
/// from the allowed prefix, refused by the match). Requests go out as raw socket bytes so
/// no client-side URI normalization can alter the wire target.
/// </summary>
public sealed class KestrelTraversalE2ETests : IAsyncLifetime
{
    private const string KeyA = "kestrel-traversal-key";

    private readonly IHost _upstream;
    private readonly IHost _proxy;
    private readonly int _port;

    public KestrelTraversalE2ETests()
    {
        var tokenHandler = new StubHttpHandler((_, _) =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    "{\"access_token\":\"tok-1\",\"expires_in\":3600}",
                    Encoding.UTF8,
                    "application/json"),
            });

        _upstream = new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.Configure(app => app.Run(context => context.Response.WriteAsync("upstream-ok")));
            })
            .Start();

        var transport = _upstream.GetTestServer().CreateHandler();
        var entries = new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash(KeyA),
            // The caller may only touch /allowed/* on this route.
            ["CredProx:Callers:app-a:Operations:0:Route"] = "acme",
            ["CredProx:Callers:app-a:Operations:0:Paths:0"] = "/allowed/*",

            ["CredProx:Destinations:acme:Template"] = "http://upstream.example/",
            ["CredProx:Credentials:contoso:Type"] = "OAuthClientCredentials",
            ["CredProx:Credentials:contoso:TokenEndpoint"] = "http://token.example/oauth/token",
            ["CredProx:Credentials:contoso:ClientId"] = "client",
            ["CredProx:Credentials:contoso:ClientSecret"] = "secret:contoso-secret",
            ["CredProx:Secrets:contoso-secret"] = "s3cr3t-value",
        };

        _proxy = new HostBuilder()
            .ConfigureAppConfiguration(build => build.AddInMemoryCollection(entries))
            .ConfigureServices((context, services) =>
            {
                services.AddCredProxTokenCache();
                services.AddCredProxConfigurationSecrets(context.Configuration);
                services.AddCredProxBuiltInCredentials();
                services.AddCredProxCredentials(context.Configuration);
                services.AddCredProxCallerAuthentication(context.Configuration);
                services.AddRouting();
                services.AddReverseProxy()
                    .LoadFromMemory([TraversalRoute], [TraversalCluster])
                    .AddCredProx(context.Configuration);
                services.AddHttpClient(CredProxHttpClientNames.TokenClient)
                    .ConfigurePrimaryHttpMessageHandler(() => tokenHandler);
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

    private static readonly RouteConfig TraversalRoute = new()
    {
        RouteId = "acme",
        ClusterId = "acme",
        Match = new RouteMatch { Path = "/{**catch-all}" },
        Metadata = new Dictionary<string, string>
        {
            [CredProxMetadata.Destination] = "acme",
            [CredProxMetadata.Credential] = "contoso",
        },
    };

    private static readonly ClusterConfig TraversalCluster = new()
    {
        ClusterId = "acme",
        Destinations = new Dictionary<string, DestinationConfig>
        {
            ["static"] = new() { Address = "http://static.example/" },
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

    /// <summary>
    /// Sends one HTTP/1.1 GET with the exact raw target over a socket — no client URI
    /// normalization between the test and the wire — and returns the status code.
    /// </summary>
    private async Task<int> RawGetAsync(string rawTarget, bool withKey)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, _port);
        var stream = client.GetStream();

        var request = new StringBuilder()
            .Append("GET ").Append(rawTarget).Append(" HTTP/1.1\r\n")
            .Append("Host: 127.0.0.1\r\n");
        if (withKey)
        {
            request.Append("X-CredProx-Key: ").Append(KeyA).Append("\r\n");
        }

        request.Append("Connection: close\r\n\r\n");

        var bytes = Encoding.ASCII.GetBytes(request.ToString());
        await stream.WriteAsync(bytes);
        await stream.FlushAsync();

        using var reader = new StreamReader(stream, Encoding.ASCII);
        var statusLine = await reader.ReadLineAsync() ?? throw new IOException("No status line.");
        var parts = statusLine.Split(' ');
        return int.Parse(parts[1]);
    }

    [Fact]
    public async Task CleanPath_IsForwarded()
    {
        Assert.Equal(200, await RawGetAsync("/allowed/thing", withKey: true));
    }

    [Fact]
    public async Task EncodedSlash_SurvivesTheWireAndIsRefused()
    {
        // Kestrel keeps %2f encoded in the decoded path; the raw scan refuses it before
        // the allow-list could ever match /allowed/%2f/admin against /allowed/*.
        Assert.Equal(403, await RawGetAsync("/allowed/%2f/admin", withKey: true));
    }

    [Fact]
    public async Task DotSegments_AreNormalizedAwayFromThePrefixAndRefused()
    {
        // Kestrel decodes %2e to '.' and removes the dot segment: the path arrives as
        // /admin, which no longer matches /allowed/*.
        Assert.Equal(403, await RawGetAsync("/allowed/%2e%2e/admin", withKey: true));
    }

    [Fact]
    public async Task NoKey_IsUnauthorized_OnTheWire()
    {
        Assert.Equal(401, await RawGetAsync("/allowed/thing", withKey: false));
    }

    private static string Hash(string keyValue) =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(keyValue))).ToLowerInvariant();
}
