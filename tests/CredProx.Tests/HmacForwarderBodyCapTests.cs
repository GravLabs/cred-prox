using System.Net;
using System.Text;
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
/// The HMAC size cap on the REAL forwarder path, where the body length is unknown:
/// the signing stage counts bytes from the request stream itself, so the verdicts
/// must come from that count alone.
///   - a chunked (unknown-length) body OVER the cap answers
///     <c>413 credprox.body_too_large_to_sign</c> and nothing reaches the upstream —
///     the counted read consumes the inbound body, so a missed overrun could not be
///     caught downstream;
///   - a streamed body whose counted length is EXACTLY the cap is a legal body: it is
///     signed and forwarded whole, with its measured length on the wire.
/// </summary>
public sealed class HmacForwarderBodyCapTests : IDisposable
{
    private const string SharedKey = "cap-shared-key";

    private readonly List<string> _upstreamBodies = [];
    private readonly List<string?> _upstreamSignatures = [];
    private readonly List<long?> _upstreamContentLengths = [];
    private readonly IHost _upstream;

    public HmacForwarderBodyCapTests()
    {
        _upstream = new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.Configure(app => app.Run(async context =>
                {
                    using var reader = new StreamReader(context.Request.Body, Encoding.UTF8);
                    _upstreamBodies.Add(await reader.ReadToEndAsync());
                    _upstreamSignatures.Add(context.Request.Headers["X-Signature"].ToString());
                    _upstreamContentLengths.Add(context.Request.ContentLength);
                    context.Response.StatusCode = StatusCodes.Status200OK;
                    await context.Response.WriteAsync("upstream");
                }));
            })
            .Start();
    }

    public void Dispose()
    {
        _upstream.StopAsync().GetAwaiter().GetResult();
        _upstream.Dispose();
    }

    private static Dictionary<string, string?> Entries(long maxBodyBytes) => new()
    {
        ["CredProx:Destinations:vendor:Template"] = "http://upstream.invalid/",
        ["CredProx:Credentials:signer:Type"] = "Hmac",
        ["CredProx:Credentials:signer:Secret"] = "secret:hmac-key",
        ["CredProx:Credentials:signer:Algorithm"] = "SHA256",
        ["CredProx:Credentials:signer:Encoding"] = "HexLower",
        ["CredProx:Credentials:signer:Components:0"] = "method",
        ["CredProx:Credentials:signer:Components:1"] = "path",
        ["CredProx:Credentials:signer:Components:2"] = "timestamp",
        ["CredProx:Credentials:signer:Components:3"] = "bodyHash",
        ["CredProx:Credentials:signer:Separator"] = "\n",
        ["CredProx:Credentials:signer:TimestampFormat"] = "UnixSeconds",
        ["CredProx:Credentials:signer:SignatureHeader"] = "X-Signature",
        ["CredProx:Credentials:signer:TimestampHeader"] = "X-Timestamp",
        ["CredProx:Credentials:signer:BufferBody"] = "true",
        ["CredProx:Credentials:signer:MaxBodyBytes"] = maxBodyBytes.ToString(),
        ["CredProx:Secrets:hmac-key"] = SharedKey,
    };

    private static readonly RouteConfig ApiRoute = new()
    {
        RouteId = "api",
        ClusterId = "vendor",
        Match = new RouteMatch { Path = "/api/{**catch-all}" },
        Metadata = new Dictionary<string, string>
        {
            [CredProxMetadata.Destination] = "vendor",
            [CredProxMetadata.Credential] = "signer",
        },
    };

    private static readonly ClusterConfig VendorCluster = new()
    {
        ClusterId = "vendor",
        Destinations = new Dictionary<string, DestinationConfig>
        {
            ["static"] = new() { Address = "http://upstream.invalid/" },
        },
    };

    private readonly List<string?> _proxyLogs = [];

    private IHost StartProxyHost(Dictionary<string, string?> entries)
    {
        var transport = _upstream.GetTestServer().CreateHandler();

        return new HostBuilder()
            .ConfigureAppConfiguration(build => build.AddInMemoryCollection(entries))
            .ConfigureServices((context, services) =>
            {
                services.AddCredProxTokenCache();
                services.AddCredProxConfigurationSecrets(context.Configuration);
                services.AddCredProxBuiltInCredentials();
                services.AddCredProxHmac();
                services.AddCredProxCredentials(context.Configuration);
                services.AddRouting();
                services.AddReverseProxy().LoadFromMemory([ApiRoute], [VendorCluster]).AddCredProx(context.Configuration);
                services.AddSingleton<IForwarderHttpClientFactory>(
                    sp => new StubTransportFactory(sp, transport));
            })
            .ConfigureLogging(logging => logging.AddProvider(new CapturingLoggerProvider(_proxyLogs)))
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
    }

    private string Logs() => string.Join(Environment.NewLine, _proxyLogs);

    [Fact]
    public async Task ChunkedBodyOverCap_ForwarderPathAnswers413AndForwardsNothing()
    {
        var entries = Entries(maxBodyBytes: 64);
        using var host = StartProxyHost(entries);

        var request = new HttpRequestMessage(HttpMethod.Post, "http://proxy.invalid/api/verify");
        var content = new StreamContent(new MemoryStream(Encoding.UTF8.GetBytes(new string('q', 4096))));
        content.Headers.ContentLength = null; // unknown length: nothing tells the stage the size
        request.Content = content;

        var response = await host.GetTestClient().SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();

        Assert.True(
            (int)response.StatusCode == 413,
            $"expected 413, got {(int)response.StatusCode}; proxy logs:{Environment.NewLine}{Logs()}");
        Assert.Contains("credprox.body_too_large_to_sign", body, StringComparison.Ordinal);
        Assert.Empty(_upstreamBodies); // never forwarded, never signed
    }

    [Fact]
    public async Task StreamingBodyExactlyAtCap_ForwarderPathSignsAndForwardsItWhole()
    {
        var entries = Entries(maxBodyBytes: 64);
        using var host = StartProxyHost(entries);

        var bodyText = new string('b', 64); // exactly the cap: the counter must not trip
        var request = new HttpRequestMessage(HttpMethod.Post, "http://proxy.invalid/api/verify");
        var content = new StreamContent(new MemoryStream(Encoding.UTF8.GetBytes(bodyText)));
        content.Headers.ContentLength = null; // streamed, so the cap is measured byte by byte
        request.Content = content;

        var response = await host.GetTestClient().SendAsync(request);
        var responseBody = await response.Content.ReadAsStringAsync();

        Assert.True(
            response.StatusCode == HttpStatusCode.OK,
            $"expected 200 for a body exactly at the cap, got {(int)response.StatusCode}: {responseBody}; proxy logs:{Environment.NewLine}{Logs()}");
        Assert.Single(_upstreamBodies);
        Assert.Equal(bodyText, _upstreamBodies[0]);
        Assert.Equal(64, _upstreamContentLengths[0]);
        Assert.False(string.IsNullOrEmpty(_upstreamSignatures[0]));
    }

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
}
