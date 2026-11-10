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
/// The headline per-request overhead suites (plan §5.6): the same loopback HTTP request
/// through plain YARP versus the same request through CredProx, against one shared stub
/// upstream, all hosts in this process on real Kestrel loopback sockets.
///
/// Arms (the plain-YARP arm is the BenchmarkDotNet baseline, so the ratios in the report
/// are the per-request overhead in the SAME run — absolute times on a shared machine are
/// not comparable across runs):
///  - PlainYarp:           plain YARP pass-through, no credential, no scrubbing.
///  - StaticKeyAttach:     static-key header attach, scrubbing off.
///  - OAuthCacheHit:       OAuth client-credentials on a warm token cache, scrubbing off.
///  - OAuthCacheHitScrub:  the same plus response scrubbing on (the production default).
///  - SsePlain / SseCredProx: time-to-first-event on an SSE stream, plain YARP versus
///    CredProx with static-key attach and scrubbing on (per-event scrubbing is M22's
///    default posture for text/event-stream). The SSE payload carries no secret bytes —
///    the arm measures the stream-scrubbing gate and the per-event machinery, not the
///    redaction work itself, so it understates the cost of per-event redaction. The SSE
///    op includes connection setup and teardown — identical treatment in both arms keeps
///    the difference meaningful.
///
/// The upstream echoes the credential-bearing headers into the response body (so the
/// scrubber has real work to do when it is on, exactly like an echo-style vendor),
/// serves the OAuth token endpoint, and streams the SSE events.
/// </summary>
[MemoryDiagnoser]
public class OverheadBenchmarks
{
    private const string StubToken = "stub-bearer-token-0123456789";
    private const string StubStaticKey = "stub-static-key-0123456789";

    private IHost _upstream = null!;
    private readonly List<IHost> _proxies = [];
    private readonly List<HttpClient> _clients = [];

    private HttpClient _plain = null!;
    private HttpClient _static = null!;
    private HttpClient _oauthOff = null!;
    private HttpClient _oauthOn = null!;
    private HttpClient _ssePlain = null!;
    private HttpClient _sseCredProx = null!;

    [GlobalSetup]
    public void Setup()
    {
        _upstream = StartUpstream();
        var upstreamAddress = AddressOf(_upstream);

        // (a) plain YARP: no CredProx registration, no route metadata.
        _plain = StartProxy(plainYarp: true, credential: null, scrubbing: null, upstreamAddress);

        // (b) static key, scrubbing explicitly off.
        var staticCreds = new Dictionary<string, string?>
        {
            ["CredProx:Credentials:bench:Type"] = "StaticKey",
            ["CredProx:Credentials:bench:Name"] = "X-Test-Key",
            ["CredProx:Credentials:bench:Secret"] = "secret:bench-key",
            ["CredProx:Secrets:bench-key"] = StubStaticKey,
            ["CredProx:Scrubbing:Enabled"] = "false",
        };
        _static = StartProxy(plainYarp: false, staticCreds, scrubbing: null, upstreamAddress);

        // (c)/(d) OAuth client-credentials against the stub token endpoint; scrubbing off
        // versus on (default).
        static Dictionary<string, string?> OAuthCreds(string endpoint) => new()
        {
            ["CredProx:Credentials:bench:Type"] = "OAuthClientCredentials",
            ["CredProx:Credentials:bench:TokenEndpoint"] = endpoint,
            ["CredProx:Credentials:bench:ClientId"] = "bench-client",
            ["CredProx:Credentials:bench:ClientSecret"] = "secret:bench-oauth",
            ["CredProx:Secrets:bench-oauth"] = StubStaticKey,
        };
        _oauthOff = StartProxy(plainYarp: false, OAuthCreds($"{upstreamAddress}/token"), scrubbing: "false", upstreamAddress);
        _oauthOn = StartProxy(plainYarp: false, OAuthCreds($"{upstreamAddress}/token"), scrubbing: "true", upstreamAddress);

        // (e) SSE: static-key attach with the production-default scrubbing versus plain YARP.
        _ssePlain = StartProxy(plainYarp: true, credential: null, scrubbing: null, upstreamAddress);
        var sseCreds = new Dictionary<string, string?>
        {
            ["CredProx:Credentials:bench:Type"] = "StaticKey",
            ["CredProx:Credentials:bench:Name"] = "X-Test-Key",
            ["CredProx:Credentials:bench:Secret"] = "secret:bench-key",
            ["CredProx:Secrets:bench-key"] = StubStaticKey,
        };
        _sseCredProx = StartProxy(plainYarp: false, sseCreds, scrubbing: null, upstreamAddress);

        _clients.AddRange([_plain, _static, _oauthOff, _oauthOn, _ssePlain, _sseCredProx]);

        // The stub upstream branches on this header: echo response versus SSE stream.
        // It is an ordinary (non-credential) header, forwarded by both arm kinds.
        _plain.DefaultRequestHeaders.Add("X-Bench", "echo");
        _static.DefaultRequestHeaders.Add("X-Bench", "echo");
        _oauthOff.DefaultRequestHeaders.Add("X-Bench", "echo");
        _oauthOn.DefaultRequestHeaders.Add("X-Bench", "echo");
        _ssePlain.DefaultRequestHeaders.Add("X-Bench", "sse");
        _sseCredProx.DefaultRequestHeaders.Add("X-Bench", "sse");

        // Warm every arm: connection pool, JIT, and — for the OAuth arms — the token cache.
        // The first OAuth request fetches the token from the stub; everything after it
        // rides the cache, which is the state every subsequent benchmark iteration wants.
        for (var warm = 0; warm < 3; warm++)
        {
            _plain.GetStringAsync("/ignored").GetAwaiter().GetResult();
            _static.GetStringAsync("/ignored").GetAwaiter().GetResult();
            _oauthOff.GetStringAsync("/ignored").GetAwaiter().GetResult();
            _oauthOn.GetStringAsync("/ignored").GetAwaiter().GetResult();
        }
        PrimeSse(_ssePlain);
        PrimeSse(_sseCredProx);
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
    public async Task StaticKeyAttach() => await _static.GetStringAsync("/ignored");

    [Benchmark]
    public async Task OAuthCacheHit() => await _oauthOff.GetStringAsync("/ignored");

    [Benchmark]
    public async Task OAuthCacheHitScrub() => await _oauthOn.GetStringAsync("/ignored");

    [Benchmark]
    public Task SsePlain() => TimeToFirstEvent(_ssePlain);

    [Benchmark]
    public Task SseCredProx() => TimeToFirstEvent(_sseCredProx);

    /// <summary>
    /// Reads until the first SSE event arrives, then abandons the response. The whole op
    /// is the client-side time-to-first-event; both SSE arms run it identically.
    /// </summary>
    private static async Task TimeToFirstEvent(HttpClient client)
    {
        using var response = await client.GetAsync(
            "/ignored", HttpCompletionOption.ResponseHeadersRead);
        response.EnsureSuccessStatusCode();
        await using var body = await response.Content.ReadAsStreamAsync();
        var buffer = new byte[64];
        while (await body.ReadAsync(buffer) > 0)
        {
            // The upstream flushes the first event before anything else, so the first
            // non-empty read is the first-event moment.
            return;
        }
    }

    private static void PrimeSse(HttpClient client)
    {
        TimeToFirstEvent(client).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Starts one proxy in front of the stub upstream. A plain-YARP proxy is plain YARP —
    /// no CredProx registration at all — so its numbers are what a YARP-only deployment
    /// pays for the same bytes. A CredProx proxy gets the documented registration chain
    /// with in-memory configuration; route metadata carries the credential name.
    /// </summary>
    private HttpClient StartProxy(
        bool plainYarp,
        Dictionary<string, string?>? credential,
        string? scrubbing,
        string upstreamAddress)
    {
        var entries = new Dictionary<string, string?>(credential ?? []);
        if (scrubbing is not null)
        {
            entries["CredProx:Scrubbing:Enabled"] = scrubbing;
        }

        // No path transforms: the client request path reaches the stub upstream verbatim,
        // and the upstream branches per arm on the X-Bench client header (which both the
        // plain and the CredProx proxy forward untouched). Keeps the compared routes
        // byte-identical apart from the credential metadata.
        var route = new RouteConfig
        {
            RouteId = "bench",
            ClusterId = "bench-cluster",
            Match = new RouteMatch { Path = "/{**catch-all}" },
            Metadata = plainYarp
                ? null
                : new Dictionary<string, string> { [CredProxMetadata.Credential] = "bench" },
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
            .ConfigureAppConfiguration(build => build.AddInMemoryCollection(entries))
            .ConfigureServices((context, services) =>
            {
                if (!plainYarp)
                {
                    services.AddCredProxTokenCache();
                    services.AddCredProxConfigurationSecrets(context.Configuration);
                    services.AddCredProxBuiltInCredentials();
                    services.AddCredProxCredentials(context.Configuration);
                }

                services.AddRouting();
                var reverseProxy = services.AddReverseProxy().LoadFromMemory([route], [cluster]);
                if (!plainYarp)
                {
                    reverseProxy.AddCredProx(context.Configuration);
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
        return new HttpClient(new SocketsHttpHandler { PooledConnectionLifetime = Timeout.InfiniteTimeSpan })
        {
            BaseAddress = new Uri(AddressOf(builder)),
        };
    }

    /// <summary>
    /// The stub vendor: an echo endpoint that mirrors the credential-bearing headers into
    /// the (text) body, the OAuth token endpoint, and a flushed SSE stream. Text content
    /// types matter: the M20 scrubber's eligibility gate engages only on them.
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
                            if (context.Request.Headers["X-Bench"] == "sse")
                            {
                                context.Response.ContentType = "text/event-stream";
                                context.Response.Headers["Cache-Control"] = "no-cache";
                                await context.Response.WriteAsync("data: first\n\n");
                                await context.Response.Body.FlushAsync();
                                try
                                {
                                    for (var n = 0; n < 100; n++)
                                    {
                                        await Task.Delay(50, context.RequestAborted);
                                        await context.Response.WriteAsync("data: tick\n\n");
                                        await context.Response.Body.FlushAsync();
                                    }
                                }
                                catch (OperationCanceledException)
                                {
                                    // The benchmark abandons the stream after the first event.
                                }

                                return;
                            }

                            context.Response.ContentType = "text/plain";
                            var key = context.Request.Headers["X-Test-Key"].ToString();
                            var auth = context.Request.Headers.Authorization.ToString();
                            await context.Response.WriteAsync(
                                $"echo: key={key} auth={auth} body=bench-response-payload");
                        });
                        endpoints.MapPost("/token", (HttpContext context) =>
                        {
                            context.Response.ContentType = "application/json";
                            return context.Response.WriteAsync(
                                $"{{\"access_token\":\"{StubToken}\",\"expires_in\":3600,\"token_type\":\"Bearer\"}}");
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
