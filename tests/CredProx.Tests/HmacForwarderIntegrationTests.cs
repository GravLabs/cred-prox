using System.Net;
using System.Security.Cryptography;
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
/// The HMAC signing stage on the REAL forwarder path: the request content the forwarder
/// hands the pipeline is its own streamed copy, which refuses the stream shortcut and
/// may not be replaced after the transforms. A streamed, unknown-length body must still
/// be counted, hashed, signed, and forwarded byte-for-byte with its measured length —
/// proven end to end through <c>MapReverseProxy</c> and the forwarder, against an
/// upstream that checks the signature over the bytes it actually received.
/// </summary>
public sealed class HmacForwarderIntegrationTests : IDisposable
{
    private const string SharedKey = "integration-shared-key";

    private readonly IHost _upstream;
    private string _receivedBody = "";
    private long? _receivedContentLength;
    private bool _signatureValidAtUpstream;

    public HmacForwarderIntegrationTests()
    {
        _upstream = new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.Configure(app => app.Run(async context =>
                {
                    // The vendor: an independent verifier of the documented layout
                    // (METHOD \n PATH \n UNIX-SECONDS \n sha256-hex(body)) over the bytes
                    // this side actually received, sharing no code with CredProx.
                    using var reader = new StreamReader(context.Request.Body, Encoding.UTF8);
                    _receivedBody = await reader.ReadToEndAsync();
                    _receivedContentLength = context.Request.ContentLength;
                    var signature = context.Request.Headers["X-Signature"].ToString();
                    var timestamp = context.Request.Headers["X-Timestamp"].ToString();
                    var canonical = string.Join('\n',
                        context.Request.Method,
                        context.Request.Path,
                        timestamp,
                        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(_receivedBody))).ToLowerInvariant());
                    var expected = Convert.ToHexString(HMACSHA256.HashData(
                        Encoding.UTF8.GetBytes(SharedKey), Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
                    _signatureValidAtUpstream = signature == expected;
                    context.Response.StatusCode = _signatureValidAtUpstream
                        ? StatusCodes.Status200OK
                        : StatusCodes.Status401Unauthorized;
                    await context.Response.WriteAsync(_signatureValidAtUpstream ? "signature valid" : "signature invalid");
                }));
            })
            .Start();
    }

    public void Dispose()
    {
        _upstream.StopAsync().GetAwaiter().GetResult();
        _upstream.Dispose();
    }

    private static Dictionary<string, string?> HmacEntries() => new()
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
        ["CredProx:Credentials:signer:MaxBodyBytes"] = "1048576",
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

    private List<string?> _proxyLogs = [];

    private IHost StartProxyHost()
    {
        var transport = _upstream.GetTestServer().CreateHandler();

        return new HostBuilder()
            .ConfigureAppConfiguration(build => build.AddInMemoryCollection(HmacEntries()))
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

    [Fact]
    public async Task StreamedUnknownLengthBody_IsSignedForwardedAndVerifiedThroughTheForwarder()
    {
        var body = new string('z', 4096) + "-streamed-through-the-forwarder";
        using var host = StartProxyHost();

        var request = new HttpRequestMessage(HttpMethod.Post, "http://proxy.invalid/api/verify");
        var content = new StreamContent(new MemoryStream(Encoding.UTF8.GetBytes(body)));
        content.Headers.ContentLength = null; // unknown length: chunked framing all the way
        request.Content = content;

        var response = await host.GetTestClient().SendAsync(request);

        Assert.True(
            response.StatusCode == HttpStatusCode.OK,
            $"expected 200, got {(int)response.StatusCode}; proxy logs:{Environment.NewLine}{string.Join(Environment.NewLine, _proxyLogs)}");
        Assert.True(_signatureValidAtUpstream, "the upstream verifier rejected the signature over the bytes it received");
        Assert.Equal(body, _receivedBody); // byte-for-byte, not truncated, not doubled
        Assert.Equal(Encoding.UTF8.GetByteCount(body), _receivedContentLength); // the measured length on the wire
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
