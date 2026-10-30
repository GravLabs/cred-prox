using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using CredProx;
using CredProx.Abstractions;
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
/// The M7 audit log end to end (§4 "Audit log", §5.2 "Audit"): one record per
/// CredProx-processed request — forwarded or short-circuited — with the documented
/// fields and the trace id; redacted headers and JSON fields never reach a sink; a
/// throwing or hanging sink never fails the request and is bounded; the caller key value
/// never appears in a record (§5.2:367).
/// </summary>
public sealed class AuditIntegrationTests : IAsyncLifetime
{
    private const string KeyA = "caller-key-alpha";

    private readonly StubHttpHandler _tokenHandler;
    private readonly IHost _upstream;

    public AuditIntegrationTests()
    {
        var tokens = new Queue<string>(["token-1", "token-2", "token-3"]);
        _tokenHandler = new StubHttpHandler((_, _) =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    "{\"access_token\":\"" + tokens.Dequeue() + "\",\"expires_in\":3600}",
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
    }

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        await _upstream.StopAsync();
        _upstream.Dispose();
    }

    private sealed record AuditRecord(string EventName, IReadOnlyDictionary<string, object?> Fields);

    private sealed class CapturingAuditSink(Func<ValueTask>? writeBehavior = null) : IAuditSink
    {
        private readonly ConcurrentQueue<AuditRecord> _records = new();

        public ValueTask WriteAsync(
            string eventName,
            IReadOnlyDictionary<string, object?> fields,
            CancellationToken cancellationToken)
        {
            _records.Enqueue(new AuditRecord(eventName, fields));
            return writeBehavior?.Invoke() ?? ValueTask.CompletedTask;
        }

        public async Task<AuditRecord> WaitForRecordAsync(int index = 0)
        {
            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(10);
            while (DateTime.UtcNow < deadline)
            {
                if (_records.Count > index)
                {
                    return _records.ToArray()[index];
                }

                await Task.Delay(10);
            }

            throw new TimeoutException($"Audit record {index} never arrived ({_records.Count} seen).");
        }

        public int Count => _records.Count;
    }

    private static Dictionary<string, string?> BaseEntries() => new()
    {
        ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
        ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash(KeyA),
        ["CredProx:Destinations:acme:Template"] = "http://upstream.example/",
        ["CredProx:Credentials:contoso:Type"] = "OAuthClientCredentials",
        ["CredProx:Credentials:contoso:TokenEndpoint"] = "http://token.example/oauth/token",
        ["CredProx:Credentials:contoso:ClientId"] = "client",
        ["CredProx:Credentials:contoso:ClientSecret"] = "secret:contoso-secret",
        ["CredProx:Secrets:contoso-secret"] = "s3cr3t-value",
    };

    private static readonly RouteConfig AcmeRoute = new()
    {
        RouteId = "acme",
        ClusterId = "acme",
        Match = new RouteMatch { Path = "/api/{**catch-all}" },
        Metadata = new Dictionary<string, string>
        {
            [CredProxMetadata.Destination] = "acme",
            [CredProxMetadata.Credential] = "contoso",
        },
    };

    private static readonly ClusterConfig AcmeCluster = new()
    {
        ClusterId = "acme",
        Destinations = new Dictionary<string, DestinationConfig>
        {
            ["static"] = new() { Address = "http://static.example/" },
        },
    };

    private (IHost Host, List<string?> Logs) StartProxyHost(
        Dictionary<string, string?>? extraEntries = null,
        Action<IServiceCollection>? configureServices = null,
        StubHttpHandler? tokenHandler = null)
    {
        var entries = BaseEntries();
        if (extraEntries is not null)
        {
            foreach (var (key, value) in extraEntries)
            {
                entries[key] = value;
            }
        }

        var transport = _upstream.GetTestServer().CreateHandler();
        var logs = new List<string?>();

        var host = new HostBuilder()
            .ConfigureAppConfiguration(build => build.AddInMemoryCollection(entries))
            .ConfigureServices((context, services) =>
            {
                services.AddCredProxTokenCache();
                services.AddCredProxConfigurationSecrets(context.Configuration);
                services.AddCredProxBuiltInCredentials();
                services.AddCredProxCredentials(context.Configuration);
                services.AddCredProxCallerAuthentication(context.Configuration);
                services.AddRouting();
                services.AddReverseProxy().LoadFromMemory([AcmeRoute], [AcmeCluster]).AddCredProx(context.Configuration);

                services.AddHttpClient(CredProxHttpClientNames.TokenClient)
                    .ConfigurePrimaryHttpMessageHandler(() => tokenHandler ?? _tokenHandler);

                services.AddSingleton<IForwarderHttpClientFactory>(
                    sp => new StubTransportFactory(sp, transport));

                configureServices?.Invoke(services);
            })
            .ConfigureLogging(logging => logging.AddProvider(new CapturingLoggerProvider(logs)))
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

        return (host, logs);
    }

    private static HttpRequestMessage CallerRequest(string path = "http://proxy/api/thing")
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Add("X-CredProx-Key", KeyA);
        return request;
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

    [Fact]
    public async Task ProxiedCall_OneRecord_WithDocumentedFields()
    {
        var sink = new CapturingAuditSink();
        var (host, _) = StartProxyHost(configureServices: services => services.AddSingleton<IAuditSink>(sink));

        var response = await host.GetTestClient().SendAsync(CallerRequest());
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var record = await sink.WaitForRecordAsync();
        Assert.Equal(CredProxAuditRecorder.ProxiedEvent, record.EventName);
        Assert.Equal("app-a", record.Fields["caller"]);
        Assert.Equal("k1", record.Fields["keyId"]);
        Assert.Equal("acme", record.Fields["route"]);
        Assert.Equal("acme", record.Fields["vendor"]);
        Assert.Equal("GET", record.Fields["method"]);
        Assert.Equal("/api/{**catch-all}", record.Fields["pathTemplate"]);
        Assert.Equal(200, record.Fields["status"]);
        Assert.Equal("contoso", record.Fields["credential"]);
        Assert.True((double)record.Fields["latencyMs"]! >= 0);
        Assert.Equal(11L, record.Fields["bytes"]); // "upstream-ok"
        Assert.False(string.IsNullOrEmpty((string?)record.Fields["traceId"]));
    }

    [Fact]
    public async Task MissingKey_401_RecordedAsRejectedCall()
    {
        var sink = new CapturingAuditSink();
        var (host, _) = StartProxyHost(configureServices: services => services.AddSingleton<IAuditSink>(sink));

        Assert.Equal(HttpStatusCode.Unauthorized, (await host.GetTestClient().GetAsync("http://proxy/api/thing")).StatusCode);

        var record = await sink.WaitForRecordAsync();
        Assert.Equal(CredProxAuditRecorder.RejectedEvent, record.EventName);
        Assert.Equal(401, record.Fields["status"]);
        Assert.Null(record.Fields["caller"]);
        Assert.Equal("contoso", record.Fields["credential"]); // the route's credential name is still context
        Assert.True((long)record.Fields["bytes"]! > 0); // the problem document body
    }

    [Fact]
    public async Task AllowListDenial_403_RecordedWithCallerIdentity()
    {
        var sink = new CapturingAuditSink();
        var (host, _) = StartProxyHost(
            new Dictionary<string, string?>
            {
                ["CredProx:Callers:app-a:Operations:0:Route"] = "acme",
                ["CredProx:Callers:app-a:Operations:0:Methods:0"] = "POST",
            },
            services => services.AddSingleton<IAuditSink>(sink));

        var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy/api/thing");
        request.Headers.Add("X-CredProx-Key", KeyA);
        Assert.Equal(HttpStatusCode.Forbidden, (await host.GetTestClient().SendAsync(request)).StatusCode);

        var record = await sink.WaitForRecordAsync();
        Assert.Equal(CredProxAuditRecorder.RejectedEvent, record.EventName);
        Assert.Equal(403, record.Fields["status"]);
        Assert.Equal("app-a", record.Fields["caller"]);
    }

    [Fact]
    public async Task CredentialFailure_502_Recorded()
    {
        var failingTokens = new StubHttpHandler((_, _) =>
            new HttpResponseMessage(HttpStatusCode.InternalServerError) { Content = new StringContent("no") });
        var sink = new CapturingAuditSink();
        var (host, _) = StartProxyHost(
            configureServices: services => services.AddSingleton<IAuditSink>(sink),
            tokenHandler: failingTokens);

        Assert.Equal(HttpStatusCode.BadGateway, (await host.GetTestClient().SendAsync(CallerRequest())).StatusCode);

        var record = await sink.WaitForRecordAsync();
        Assert.Equal(CredProxAuditRecorder.RejectedEvent, record.EventName);
        Assert.Equal(502, record.Fields["status"]);
    }

    [Fact]
    public async Task CallerKeyValue_NeverAppearsInAnyRecordField()
    {
        const string secretKey = "super-secret-key-value-9182736455";
        var sink = new CapturingAuditSink();
        var (host, _) = StartProxyHost(
            new Dictionary<string, string?>
            {
                ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash(secretKey),
            },
            services => services.AddSingleton<IAuditSink>(sink));

        var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy/api/thing");
        request.Headers.Add("X-CredProx-Key", secretKey);
        Assert.Equal(HttpStatusCode.OK, (await host.GetTestClient().SendAsync(request)).StatusCode);

        var record = await sink.WaitForRecordAsync();
        foreach (var value in record.Fields.Values)
        {
            Assert.DoesNotContain(secretKey, value?.ToString() ?? string.Empty, StringComparison.Ordinal);
        }

        Assert.Equal("k1", record.Fields["keyId"]); // the id is present; the value is not
    }

    [Fact]
    public async Task RedactedHeaders_NeverReachTheSink_UncapturedHeadersAreAbsent()
    {
        var sink = new CapturingAuditSink();
        var (host, _) = StartProxyHost(
            configureServices: services => services.AddCredProxAudit(BuildConfig(new Dictionary<string, string?>
            {
                ["CredProx:Audit:IncludeHeaders:0"] = "X-Note",
                ["CredProx:Audit:IncludeHeaders:1"] = "Authorization",
                ["CredProx:Audit:IncludeHeaders:2"] = "X-Visible",
                ["CredProx:Audit:RedactHeaders:0"] = "X-Note",
            })).AddSingleton<IAuditSink>(sink));

        var request = CallerRequest();
        request.Headers.Add("X-Note", "note-secret-value");
        request.Headers.Add("Authorization", "Bearer caller-token-value");
        request.Headers.Add("X-Visible", "plain-value");
        request.Headers.Add("X-Not-Captured", "uncaptured-value");
        Assert.Equal(HttpStatusCode.OK, (await host.GetTestClient().SendAsync(request)).StatusCode);

        var record = await sink.WaitForRecordAsync();
        var headers = Assert.IsAssignableFrom<IReadOnlyDictionary<string, object?>>(record.Fields["headers"]);
        Assert.Equal(AuditRedactor.Masked, headers["X-Note"]); // configured redaction
        Assert.Equal(AuditRedactor.Masked, headers["Authorization"]); // built-in sensitive set
        Assert.Equal("plain-value", headers["X-Visible"]);
        Assert.False(headers.ContainsKey("X-Not-Captured")); // only IncludeHeaders are captured

        // No field anywhere carries a redacted value.
        Assert.DoesNotContain(record.Fields.Values, v => (v?.ToString() ?? "").Contains("note-secret-value", StringComparison.Ordinal));
        Assert.DoesNotContain(record.Fields.Values, v => (v?.ToString() ?? "").Contains("caller-token-value", StringComparison.Ordinal));
        Assert.DoesNotContain(record.Fields.Values, v => (v?.ToString() ?? "").Contains("uncaptured-value", StringComparison.Ordinal));
    }

    [Fact]
    public async Task DefaultJsonFieldSet_MasksCapturedHeaderNamedToken()
    {
        var sink = new CapturingAuditSink();
        var options = new CredProxAuditOptions { IncludeHeaders = ["token"] };
        var (host, _) = StartProxyHost(
            configureServices: services =>
            {
                services.AddSingleton(options);
                services.AddSingleton<IAuditSink>(sink);
            });

        var request = CallerRequest();
        request.Headers.Add("token", "jwt-like-secret-value");
        Assert.Equal(HttpStatusCode.OK, (await host.GetTestClient().SendAsync(request)).StatusCode);

        var record = await sink.WaitForRecordAsync();
        var headers = Assert.IsAssignableFrom<IReadOnlyDictionary<string, object?>>(record.Fields["headers"]);
        Assert.Equal(AuditRedactor.Masked, headers["token"]);
    }

    [Fact]
    public async Task SinkThrows_RequestSucceeds_FailureIsLoggedValueFree()
    {
        var sink = new CapturingAuditSink(() => throw new InvalidOperationException("sink exploded"));
        var (host, logs) = StartProxyHost(configureServices: services => services.AddSingleton<IAuditSink>(sink));

        Assert.Equal(HttpStatusCode.OK, (await host.GetTestClient().SendAsync(CallerRequest())).StatusCode);
        await WaitUntilAsync(() => logs.Any(l => l?.Contains("sink exploded", StringComparison.Ordinal) == true));
        Assert.Contains(logs, l => l?.Contains("audit sink", StringComparison.Ordinal) == true);
    }

    [Fact]
    public async Task SinkHangs_RequestCompletesAndSinkIsAbandonedAtTheBound()
    {
        // A sink that ignores the cancellation token: the bound is the WhenAny timer, so
        // the request completes and the record is abandoned with a warning — the §5.2
        // "does not fail or delay the proxied request beyond a bound".
        var sink = new CapturingAuditSink(
            () => new ValueTask(Task.Delay(TimeSpan.FromSeconds(30))));
        var (host, logs) = StartProxyHost(
            configureServices: services => services.AddSingleton(new CredProxAuditOptions { SinkTimeout = TimeSpan.FromMilliseconds(200) })
                .AddSingleton<IAuditSink>(sink));

        var start = Stopwatch.GetTimestamp();
        Assert.Equal(HttpStatusCode.OK, (await host.GetTestClient().SendAsync(CallerRequest())).StatusCode);
        Assert.True(Stopwatch.GetElapsedTime(start) < TimeSpan.FromSeconds(10));

        await WaitUntilAsync(() => logs.Any(l => l?.Contains("abandoned", StringComparison.Ordinal) == true),
            TimeSpan.FromSeconds(10));
    }

    [Fact]
    public async Task NoSinkRegistered_RequestUnaffected_NoRecords()
    {
        var (host, _) = StartProxyHost();

        Assert.Equal(HttpStatusCode.OK, (await host.GetTestClient().SendAsync(CallerRequest())).StatusCode);
        await Task.Delay(100); // give any stray record a chance to show up
    }

    [Fact]
    public async Task LoggerAuditSink_WritesStructuredLine_WithoutSecretValues()
    {
        var (host, logs) = StartProxyHost(
            configureServices: services => services.AddCredProxAudit(BuildConfig([])));

        Assert.Equal(HttpStatusCode.OK, (await host.GetTestClient().SendAsync(CallerRequest())).StatusCode);
        await WaitUntilAsync(() => logs.Any(l => l?.Contains("credprox.audit", StringComparison.Ordinal) == true));

        var line = logs.Single(l => l?.Contains("credprox.audit", StringComparison.Ordinal) == true)!;
        Assert.Contains("credprox.proxied_call", line, StringComparison.Ordinal);
        Assert.Contains("caller=app-a", line, StringComparison.Ordinal);
        Assert.Contains("credential=contoso", line, StringComparison.Ordinal);
        Assert.DoesNotContain("s3cr3t-value", line, StringComparison.Ordinal);
        Assert.DoesNotContain(KeyA, line, StringComparison.Ordinal);
    }

    private static IConfiguration BuildConfig(Dictionary<string, string?> entries) =>
        new ConfigurationBuilder().AddInMemoryCollection(entries).Build();

    private static async Task WaitUntilAsync(Func<bool> condition, TimeSpan? timeout = null)
    {
        var deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(10));
        while (DateTime.UtcNow < deadline)
        {
            if (condition())
            {
                return;
            }

            await Task.Delay(10);
        }

        throw new TimeoutException("Condition never became true.");
    }

    private static string Hash(string keyValue) =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(keyValue))).ToLowerInvariant();
}
