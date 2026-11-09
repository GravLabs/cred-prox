using System.Diagnostics;
using System.Net.Sockets;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Extensions.AspNetCore.Configuration.Secrets;
using Azure.Security.KeyVault.Secrets;
using CredProx;

// M33 soak host (plan §5.5): the proxy under test, configured entirely from appsettings.json
// (mounted read-write in the container so fault 5/6 can rotate config live). The only code is
// the pipeline, the fault-6 Key Vault provider wiring, and a stats collector writing the
// §5.5 soak metrics CSV.
var builder = WebApplication.CreateBuilder(args);

// Fault 6 (design decision): the real AddAzureKeyVault provider with ReloadInterval drives
// the polling reload path; only the transport reaches the loopback KV stub on WireMock
// (M29 reloadproof pattern - plain config sources do not count). The KV secret
// CredProx--Secrets--vendor-gen2-key overrides the static appsettings placeholder, so the
// rotation witness exercises the provider poll, not the file watcher.
var kvStubBase = Environment.GetEnvironmentVariable("SOAK_KV_STUB_BASE");
if (!string.IsNullOrEmpty(kvStubBase))
{
    var reloadSeconds = int.TryParse(Environment.GetEnvironmentVariable("SOAK_KV_RELOAD_S"), out var r) ? r : 10;

    // Readiness, not just ordering: depends_on starts WireMock before us but the provider's
    // Load fires at boot with two fast retries, which beat the stub's JVM accept loop
    // (smoke #1: Connection refused). Wait for a TCP accept before wiring the provider.
    var kvStubUri = new Uri(kvStubBase);
    using (var probe = new TcpClient())
    {
        using var ready = new CancellationTokenSource(TimeSpan.FromSeconds(120));
        while (true)
        {
            try
            {
                await probe.ConnectAsync(kvStubUri.DnsSafeHost, kvStubUri.Port, ready.Token);
                break;
            }
            catch (SocketException) when (!ready.IsCancellationRequested)
            {
                await Task.Delay(500);
            }
            catch (OperationCanceledException)
            {
                throw new InvalidOperationException($"KV stub {kvStubBase} not reachable within 120 s");
            }
        }
    }

    var kvClient = new SecretClient(
        new Uri("https://credprox-m33-stub.vault.local/"),
        new KvSmokeTokenCredential(),
        new SecretClientOptions { Transport = new StubEndpointTransport(new HttpClientTransport(), kvStubBase) });
    builder.Configuration.AddAzureKeyVault(kvClient, new AzureKeyVaultConfigurationOptions
    {
        ReloadInterval = TimeSpan.FromSeconds(reloadSeconds)
    });
}

builder.Services.AddCredProxTokenCache();
builder.Services.AddCredProxConfigurationSecrets(builder.Configuration);
builder.Services.AddCredProxBuiltInCredentials();
builder.Services.AddCredProxCredentials(builder.Configuration);
builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx(builder.Configuration);
// B3 (design decision 2026-11-09): throttle + resilience are opt-in registrations (documented inert
// otherwise) and their config binds only inside these calls - wire them so faults 2/3 reach
// the pause/breaker behaviour under test. Config keys must name a live ClusterId (vendor).
builder.Services.AddCredProxThrottling(builder.Configuration);
builder.Services.AddCredProxResilience(builder.Configuration);
builder.Services.AddSingleton<StatsCollector>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<StatsCollector>());

builder.WebHost.UseUrls("http://0.0.0.0:8080");

var app = builder.Build();

app.MapGet("/healthz", () => Results.Ok(new { ok = true }));
app.MapGet("/soak/stats", (StatsCollector stats) => Results.Text(stats.LatestCsvLine(), "text/plain"));
app.MapReverseProxy();

app.Run();
return 0;

/// <summary>
/// Per-interval row of the soak metrics (§5.5 "Steady soak"): RSS, GC heap, gen2/LOH sizes,
/// managed thread count, established TCP sockets. Written to SOAK_STATS_PATH so the collector
/// survives container restarts within a run; the runner collects the file into the run dir.
/// </summary>
internal sealed class StatsCollector : BackgroundService
{
    private readonly string _path = Environment.GetEnvironmentVariable("SOAK_STATS_PATH")
        ?? Path.Combine(Path.GetTempPath(), "soak-stats.csv");
    private readonly TimeSpan _interval = TimeSpan.FromSeconds(
        double.TryParse(Environment.GetEnvironmentVariable("SOAK_STATS_INTERVAL_S"), out var s) ? s : 30);
    private volatile string _latest = string.Empty;

    public string LatestCsvLine() => _latest;

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        var fresh = !File.Exists(_path);
        using var writer = new StreamWriter(_path, append: true) { AutoFlush = true };
        if (fresh)
        {
            await writer.WriteLineAsync("unix_s,rss_bytes,heap_bytes,gen2_bytes,loh_bytes,threads,tcp_established");
        }

        while (!ct.IsCancellationRequested)
        {
            var process = Process.GetCurrentProcess();
            process.Refresh();
            var heap = GC.GetGCMemoryInfo();
            var gen2 = heap.GenerationInfo.Length > 2 ? heap.GenerationInfo[2].SizeAfterBytes : 0L;
            var loh = heap.GenerationInfo.Length > 3 ? heap.GenerationInfo[3].SizeAfterBytes : 0L;
            var tcp = CountEstablishedTcp();
            var line = string.Format(
                System.Globalization.CultureInfo.InvariantCulture,
                "{0:0},{1},{2},{3},{4},{5},{6}",
                DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                process.WorkingSet64,
                heap.TotalCommittedBytes,
                gen2,
                loh,
                process.Threads.Count,
                tcp);
            _latest = line;
            await writer.WriteLineAsync(line);
            process.Dispose();

            try
            {
                await Task.Delay(_interval, ct);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    private static int CountEstablishedTcp()
    {
        var count = 0;
        foreach (var file in new[] { "/proc/net/tcp", "/proc/net/tcp6" })
        {
            try
            {
                foreach (var line in File.ReadLines(file).Skip(1))
                {
                    var fields = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (fields.Length > 3 && fields[3] == "01")
                    {
                        count++;
                    }
                }
            }
            catch (IOException)
            {
                // /proc not mounted (dev run outside a container): count stays partial.
            }
        }

        return count;
    }
}

/// <summary>Fixed-token stand-in (M29 reloadproof pattern): auth is not what fault 6 tests.</summary>
internal sealed class KvSmokeTokenCredential : TokenCredential
{
    public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        => new(new AccessToken("soak-stub-token", DateTimeOffset.UtcNow.AddHours(1)));

    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
        => new("soak-stub-token", DateTimeOffset.UtcNow.AddHours(1));
}

/// <summary>
/// Rewrites only scheme/host/port to the loopback stub, preserving the real vault URI form
/// the SecretClient was built with (M29 verdict: everything except the HTTP endpoint must be
/// the shipped path). Ported from the ACA sample's reloadproof transport.
/// </summary>
internal sealed class StubEndpointTransport : HttpPipelineTransport
{
    private readonly HttpPipelineTransport _inner;
    private readonly Uri _stubBase;

    public StubEndpointTransport(HttpPipelineTransport inner, string stubBase)
    {
        _inner = inner;
        _stubBase = new Uri(stubBase, UriKind.Absolute);
    }

    public override Request CreateRequest() => _inner.CreateRequest();

    public override void Process(HttpMessage message)
    {
        var original = Rewrite(message);
        try
        {
            _inner.Process(message);
        }
        finally
        {
            Restore(message, original);
        }
    }

    public override async ValueTask ProcessAsync(HttpMessage message)
    {
        var original = Rewrite(message);
        try
        {
            await _inner.ProcessAsync(message).ConfigureAwait(false);
        }
        finally
        {
            Restore(message, original);
        }
    }

    private (string? Scheme, string? Host, int Port) Rewrite(HttpMessage message)
    {
        var uri = message.Request.Uri;
        var original = (uri.Scheme, uri.Host, uri.Port);
        if (!string.IsNullOrEmpty(uri.Host))
        {
            message.Request.Headers.SetValue("X-Stub-Vault-Host", uri.Host);
        }

        uri.Scheme = _stubBase.Scheme;
        uri.Host = _stubBase.Host;
        uri.Port = _stubBase.Port;
        return original;
    }

    // The rewrite must not outlive the attempt: the retry policy re-runs the pipeline with
    // the SAME message, and a persisted http Uri trips BearerTokenAuthenticationPolicy's
    // non-TLS guard on attempt 2 (smoke #1's second inner exception), masking the real fault.
    private static void Restore(HttpMessage message, (string? Scheme, string? Host, int Port) original)
    {
        var uri = message.Request.Uri;
        uri.Scheme = original.Scheme;
        uri.Host = original.Host;
        uri.Port = original.Port;
    }
}
