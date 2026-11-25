using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using BenchmarkDotNet.Attributes;
using CredProx;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Yarp.ReverseProxy.Configuration;

namespace CredProx.Benchmarks;

/// <summary>
/// The metering cost report (M50 row): the same loopback request through CredProx with
/// the Operations add-on registered but unarmed, then armed (`CredProx:Metering`), then
/// armed with the route opted into usage (`CredProx.Metering.Usage`) against a payload
/// that really reports usage — the AiGateway sample's production shape. Every arm sees
/// identical request and response bytes, so the same-run ratios are the cost deltas:
/// OpsNoMetering → the add-on registration itself (this is also the OFF posture the
/// §5.6 gate protects: metering unregistered must cost nothing on the gated arms, which
/// OverheadBenchmarks measures without the add-on at all); Metered → the request counter
/// and byte histograms; MeteredUsage → plus the usage peek/parse on the opted-in route.
///
/// Report, not gate: no committed baseline contains these arms, so bench-compare passes
/// them over. The absolute and ratio numbers are what the M50 handoff reports. Scrubbing
/// is off on every CredProx arm so the deltas stay metering-only; the scrubbing arms are
/// already gated in OverheadBenchmarks. The upstream answers with an Anthropic-shaped
/// usage report so the opted-in arm runs the real non-streaming reader path.
/// </summary>
[MemoryDiagnoser]
[ExcludeFromCodeCoverage]
public class MeteringOverheadBenchmarks
{
    private const string StubStaticKey = "stub-static-key-0123456789";
    private const string CallerKeyValue = "bench-metering-demo-key-0123456789";
    private const string UsagePayload =
        "{\"id\":\"msg_bench\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"ok\"}],\"usage\":{\"input_tokens\":11,\"output_tokens\":23}}";

    private IHost _upstream = null!;
    private readonly List<IHost> _proxies = [];
    private readonly List<HttpClient> _clients = [];

    private HttpClient _plain = null!;
    private HttpClient _opsOff = null!;
    private HttpClient _metered = null!;
    private HttpClient _meteredUsage = null!;

    [GlobalSetup]
    public void Setup()
    {
        _upstream = StartUpstream();
        var upstreamAddress = AddressOf(_upstream);

        // The plain-YARP arm pays no caller authentication, so it is the yardstick the
        // add-on arms are read against, exactly as in OverheadBenchmarks.
        _plain = StartProxy(plainYarp: true, entries: null, usageRoute: false, upstreamAddress);

        Dictionary<string, string?> OpsEntries() => new()
        {
            ["CredProx:Credentials:bench:Type"] = "StaticKey",
            ["CredProx:Credentials:bench:Name"] = "X-Test-Key",
            ["CredProx:Credentials:bench:Secret"] = "secret:bench-key",
            ["CredProx:Secrets:bench-key"] = StubStaticKey,
            ["CredProx:Scrubbing:Enabled"] = "false",
            ["CredProx:Callers:bench:Keys:0:KeyId"] = "bench-key-1",
            ["CredProx:Callers:bench:Keys:0:KeyHash"] = "sha256:" + Convert.ToHexString(
                SHA256.HashData(Encoding.UTF8.GetBytes(CallerKeyValue))).ToLowerInvariant(),
        };

        _opsOff = StartProxy(plainYarp: false, OpsEntries(), usageRoute: false, upstreamAddress);

        var armed = OpsEntries();
        armed["CredProx:Metering:MaxUsageParseBytes"] = "1048576";
        _metered = StartProxy(plainYarp: false, armed, usageRoute: false, upstreamAddress);
        _meteredUsage = StartProxy(plainYarp: false, armed, usageRoute: true, upstreamAddress);

        _clients.AddRange([_plain, _opsOff, _metered, _meteredUsage]);

        foreach (var client in _clients)
        {
            client.DefaultRequestHeaders.Add("X-CredProx-Key", CallerKeyValue);
        }

        // Warm every arm: connection pool, JIT, caller-auth cache.
        for (var warm = 0; warm < 3; warm++)
        {
            foreach (var client in _clients)
            {
                client.GetStringAsync("/ignored").GetAwaiter().GetResult();
            }
        }
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        foreach (var client in _clients)
        {
            client.Dispose();
        }

        foreach (var host in _proxies)
        {
            host.StopAsync().GetAwaiter().GetResult();
            host.Dispose();
        }

        _proxies.Clear();
        _clients.Clear();

        _upstream.StopAsync().GetAwaiter().GetResult();
        _upstream.Dispose();
    }

    [Benchmark(Baseline = true)]
    public async Task PlainYarp() => await _plain.GetStringAsync("/ignored");

    [Benchmark]
    public async Task OpsNoMetering() => await _opsOff.GetStringAsync("/ignored");

    [Benchmark]
    public async Task Metered() => await _metered.GetStringAsync("/ignored");

    [Benchmark]
    public async Task MeteredUsage() => await _meteredUsage.GetStringAsync("/ignored");

    /// <summary>
    /// One proxy per arm on the documented chain; arms differ only in the metering
    /// arming entries and the route usage metadata, so byte counts stay identical.
    /// </summary>
    private HttpClient StartProxy(
        bool plainYarp,
        Dictionary<string, string?>? entries,
        bool usageRoute,
        string upstreamAddress)
    {
        var metadata = plainYarp
            ? null
            : new Dictionary<string, string> { [CredProxMetadata.Credential] = "bench" };
        if (usageRoute)
        {
            metadata![CredProxMetering.UsageRouteMetadata] = "anthropic";
        }

        var route = new RouteConfig
        {
            RouteId = "bench",
            ClusterId = "bench-cluster",
            Match = new RouteMatch { Path = "/{**catch-all}" },
            Metadata = metadata,
        };
        var cluster = new ClusterConfig
        {
            ClusterId = "bench-cluster",
            Destinations = new Dictionary<string, DestinationConfig>
            {
                ["stub"] = new() { Address = upstreamAddress },
            },
        };

        var builder = new HostBuilder()
            .ConfigureAppConfiguration(build => build.AddInMemoryCollection(entries ?? []))
            .ConfigureServices((context, services) =>
            {
                if (!plainYarp)
                {
                    services.AddCredProx(context.Configuration).AddOperations();
                }

                services.AddRouting();
                var reverseProxy = services.AddReverseProxy().LoadFromMemory([route], [cluster]);
                if (!plainYarp)
                {
                    reverseProxy.AddCredProx();
                }
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

        _proxies.Add(builder);
        return new HttpClient(new System.Net.Http.SocketsHttpHandler { PooledConnectionLifetime = Timeout.InfiniteTimeSpan })
        {
            BaseAddress = new Uri(AddressOf(builder)),
        };
    }

    /// <summary>
    /// The stub vendor: the same fixed Anthropic-shaped usage report on every request,
    /// with no per-request bytes to stabilise the response allocation.
    /// </summary>
    private static IHost StartUpstream()
    {
        var builder = new HostBuilder()
            .ConfigureLogging(logging => logging.ClearProviders())
            .ConfigureServices(services => services.AddRouting())
            .ConfigureWebHost(web =>
            {
                web.UseKestrel(options => options.Listen(System.Net.IPAddress.Loopback, 0));
                web.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapGet("/ignored", async (HttpContext context) =>
                        {
                            context.Response.ContentType = "application/json";
                            await context.Response.WriteAsync(UsagePayload);
                        });
                    });
                });
            })
            .Start();

        return builder;
    }

    private static string AddressOf(IHost host)
    {
        var addresses = host.Services
            .GetRequiredService<IServer>()
            .Features.Get<IServerAddressesFeature>()!;
        return addresses.Addresses.First();
    }
}
