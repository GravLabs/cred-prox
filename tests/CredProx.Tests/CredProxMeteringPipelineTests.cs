using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using CredProx;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OpenTelemetry;
using OpenTelemetry.Metrics;
using Xunit;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;

namespace CredProx.Tests;

/// <summary>
/// §5.2 (M50 row): the metering legs on a REAL host (Kestrel on an ephemeral loopback
/// port — the record rides <c>Response.OnCompleted</c>, which never fires on a fake
/// context), upstream stubbed through the TestServer transport. Byte identity through the
/// wrapping (chunked both directions, and an aborted stream), tag integrity (nothing
/// traffic-shaped or secret-shaped reaches a tag; the five fixed tag keys only), the
/// per-route usage opt-in (same body, unmetered without the key; a provider reporting no
/// usage stays unmetered), the cumulative stream rule end to end, and short-circuited
/// requests never metering. Every cell uses unique caller and route ids so the
/// process-wide instrument bleed can never satisfy an assertion.
/// </summary>
public sealed class CredProxMeteringPipelineTests : IAsyncLifetime
{
    private const string UsageOptInKey = "CredProx.Metering.Usage";
    private const string UpstreamOk = "upstream-ok";
    private const string UsageJson = "{\"type\":\"message\",\"usage\":{\"input_tokens\":11,\"output_tokens\":7}}";

    // M54 measured shapes (Foundry Local 2.5.0 CPU server, docs/foundry-local-notes.md):
    private const string OpenAiUsageJson =
        "{\"id\":\"chatcmpl-abc\",\"object\":\"chat.completion\",\"model\":\"local-qwen:3\",\"choices\":[{\"index\":0,\"message\":{\"role\":\"assistant\",\"content\":\"OK\",\"reasoning_content\":\"think\"},\"finish_reason\":\"stop\"}],\"usage\":{\"completion_tokens\":32,\"completion_tokens_details\":{\"reasoning_tokens\":31},\"prompt_tokens\":13,\"prompt_tokens_details\":{\"cached_tokens\":0},\"total_tokens\":45}}";

    private const string OpenAiStreamBody =
        "data: {\"id\":\"chatcmpl-abc\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"OK\"},\"finish_reason\":null}]}\n\n"
        + "data: {\"id\":\"chatcmpl-abc\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n"
        + "data: {\"id\":\"chatcmpl-abc\",\"choices\":[],\"usage\":{\"completion_tokens\":32,\"completion_tokens_details\":{\"reasoning_tokens\":31},\"prompt_tokens\":13,\"total_tokens\":45}}\n\n"
        + "data: [DONE]\n\n";

    private const string OpenAiStreamNoUsageBody =
        "data: {\"id\":\"chatcmpl-abc\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"OK\"},\"finish_reason\":null}]}\n\n"
        + "data: {\"id\":\"chatcmpl-abc\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n"
        + "data: [DONE]\n\n";
    private static readonly byte[] Payload = CreatePayload();

    private static byte[] CreatePayload()
    {
        var payload = new byte[200 * 1024];
        new Random(77).NextBytes(payload);
        return payload;
    }

    private const string StreamBody =
        "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":100,\"output_tokens\":1}}}\n\n"
        + "event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":5}}\n\n"
        + "event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":30}}\n\n";

    private readonly IHost _upstream;

    public CredProxMeteringPipelineTests()
    {
        _upstream = new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.Configure(app => app.Run(async context =>
                {
                    var path = context.Request.Path.Value ?? string.Empty;
                    if (path.EndsWith("/echo", StringComparison.Ordinal))
                    {
                        // Binary echo: CopyToAsync, never a text reader — a StreamReader over
                        // random bytes would replace invalid UTF-8 sequences and inflate the
                        // body, faking a byte-identity failure on the metering cells.
                        await context.Request.Body.CopyToAsync(context.Response.Body, context.RequestAborted);
                        return;
                    }

                    if (path.EndsWith("/usage", StringComparison.Ordinal))
                    {
                        context.Response.ContentType = "application/json";
                        await context.Response.WriteAsync(UsageJson, context.RequestAborted);
                        return;
                    }

                    if (path.EndsWith("/custom", StringComparison.Ordinal))
                    {
                        // A media type no built-in reader claims, so a host-registered
                        // reader is what SelectReader reaches (LOW-3 catch-arm witness).
                        context.Response.ContentType = "application/vnd.credprox.probe";
                        await context.Response.WriteAsync(UpstreamOk, context.RequestAborted);
                        return;
                    }

                    if (path.EndsWith("/stream", StringComparison.Ordinal))
                    {
                        context.Response.ContentType = "text/event-stream";
                        await context.Response.WriteAsync(StreamBody, context.RequestAborted);
                        return;
                    }

                    if (path.EndsWith("/openai-stream-nousage", StringComparison.Ordinal))
                    {
                        context.Response.ContentType = "text/event-stream";
                        await context.Response.WriteAsync(OpenAiStreamNoUsageBody, context.RequestAborted);
                        return;
                    }

                    if (path.EndsWith("/openai-stream", StringComparison.Ordinal))
                    {
                        context.Response.ContentType = "text/event-stream";
                        await context.Response.WriteAsync(OpenAiStreamBody, context.RequestAborted);
                        return;
                    }

                    if (path.EndsWith("/openai", StringComparison.Ordinal))
                    {
                        context.Response.ContentType = "application/json";
                        await context.Response.WriteAsync(OpenAiUsageJson, context.RequestAborted);
                        return;
                    }

                    if (path.EndsWith("/slow", StringComparison.Ordinal))
                    {
                        await context.Response.WriteAsync("0123456789", context.RequestAborted);
                        await context.Response.Body.FlushAsync(context.RequestAborted);
                        // Hold the stream open until the caller goes away.
                        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                        using var reg = context.RequestAborted.Register(() => tcs.TrySetResult());
                        await tcs.Task;
                        return;
                    }

                    await context.Response.WriteAsync(UpstreamOk, context.RequestAborted);
                }));
            })
            .Start();
    }

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        await _upstream.StopAsync();
        _upstream.Dispose();
    }

    private static string Hash(string keyValue) =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(keyValue))).ToLowerInvariant();

    private sealed record Measurement(string Instrument, long Value, Dictionary<string, object?> Tags);

    /// <summary>A metering cell: unique caller+route, a Kestrel proxy host, and a listener.</summary>
    private sealed class Metered(string caller, string key, string route) : IAsyncDisposable
    {
        public string Caller { get; } = caller;
        public string Key { get; } = key;
        public string Route { get; } = route;
        public ConcurrentQueue<Measurement> Measurements { get; init; } = new();

        public required IHost Host { get; init; }
        public required HttpClient Client { get; init; }
        public required MeterListener Listener { get; init; }

        public async Task<IHost> DisposeHostAsync()
        {
            await Host.StopAsync();
            Host.Dispose();
            return Host;
        }

        public async ValueTask DisposeAsync()
        {
            Listener.Dispose();
            Client.Dispose();
            await Host.StopAsync();
            Host.Dispose();
        }

        public bool Has(string instrument, string routeValue) =>
            Measurements.Any(m => m.Instrument == instrument && Equals(m.Tags["credprox.route"], routeValue));

        public Measurement? Find(string instrument) =>
            Measurements.FirstOrDefault(m => m.Instrument == instrument && Equals(m.Tags["credprox.route"], Route));

        public IEnumerable<Measurement> ForRoute() =>
            Measurements.Where(m => Equals(m.Tags["credprox.route"], Route));

        public async Task<Measurement> WaitForAsync(string instrument, TimeSpan? timeout = null)
        {
            var deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(10));
            while (DateTime.UtcNow < deadline)
            {
                var hit = Find(instrument);
                if (hit is not null)
                {
                    return hit;
                }

                await Task.Delay(10);
            }

            throw new TimeoutException(
                $"{instrument} for route {Route} never arrived ({Measurements.Count} total seen).");
        }
    }

    private Metered StartCell(
        string? usageFormat = null,
        bool withCaller = true,
        Action<IServiceCollection>? extraServices = null,
        bool callerless = false)
    {
        var n = Guid.NewGuid().ToString("N")[..12];
        var caller = "m50c-" + n;
        var key = "m50k-" + n;
        var route = "m50r-" + n;

        var entries = new Dictionary<string, string?>
        {
            ["CredProx:Destinations:acme:Template"] = "http://upstream.example/",
            ["CredProx:Credentials:contoso:Type"] = "OAuthClientCredentials",
            ["CredProx:Credentials:contoso:TokenEndpoint"] = "http://token.example/oauth/token",
            ["CredProx:Credentials:contoso:ClientId"] = "client",
            ["CredProx:Credentials:contoso:ClientSecret"] = "secret:contoso-secret",
            ["CredProx:Secrets:contoso-secret"] = "s3cr3t-value",
            ["CredProx:Metering:MaxUsageParseBytes"] = "1048576",
        };
        if (!callerless)
        {
            entries[$"CredProx:Callers:{caller}:Keys:0:KeyId"] = "k1";
            entries[$"CredProx:Callers:{caller}:Keys:0:KeyHash"] = Hash(key);
        }

        var routeMetadata = new Dictionary<string, string>();
        if (!callerless)
        {
            // The callerless cell's route names no credential and no destination either,
            // so the record's fallbacks decide those tags (fold INFO-e).
            routeMetadata[CredProxMetadata.Destination] = "acme";
            routeMetadata[CredProxMetadata.Credential] = "contoso";
        }
        if (usageFormat is not null)
        {
            routeMetadata[UsageOptInKey] = usageFormat;
        }

        var proxyRoute = new RouteConfig
        {
            RouteId = route,
            ClusterId = route,
            Match = new RouteMatch { Path = "/api/{**catch-all}" },
            Metadata = routeMetadata,
        };
        var proxyCluster = new ClusterConfig
        {
            ClusterId = route,
            Destinations = new Dictionary<string, DestinationConfig>
            {
                ["static"] = new() { Address = "http://static.example/" },
            },
        };

        var transport = _upstream.GetTestServer().CreateHandler();
        var tokens = new Queue<string>(["t1", "t2", "t3", "t4"]);
        var tokenHandler = new StubHttpHandler((_, _) =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    "{\"access_token\":\"" + tokens.Dequeue() + "\",\"expires_in\":3600}",
                    Encoding.UTF8,
                    "application/json"),
            });

        var host = new HostBuilder()
            .ConfigureAppConfiguration(build => build.AddInMemoryCollection(entries))
            .ConfigureServices(services =>
            {
                services.AddCredProxTokenCache();
                services.AddCredProxConfigurationSecrets(BuildConfig(entries));
                services.AddCredProxBuiltInCredentials();
                services.AddCredProxOAuth();
                services.AddCredProxCredentials(BuildConfig(entries));
                if (!callerless)
                {
                    // No callers declared at all: the startup guard stays silent and the
                    // request is forwarded unauthenticated (metrics.md: tagged anonymous).
                    services.AddCredProxCallerAuthentication(BuildConfig(entries));
                }
                services.AddRouting();
                services.AddReverseProxy()
                    .LoadFromMemory([proxyRoute], [proxyCluster])
                    .AddCredProx(BuildConfig(entries));
                services.AddCredProx(BuildConfig(entries)).AddOperations();
                services.AddHttpClient(CredProxHttpClientNames.TokenClient)
                    .ConfigurePrimaryHttpMessageHandler(() => tokenHandler);
                services.AddSingleton<IForwarderHttpClientFactory>(
                    sp => new StubTransportFactory(sp, transport));
                extraServices?.Invoke(services);
            })
            .ConfigureLogging(logging => logging.ClearProviders()) // keep host chatter out of test output
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

        var port = new Uri(host.Services
            .GetRequiredService<IServer>()
            .Features.Get<IServerAddressesFeature>()!
            .Addresses.First()).Port;

        var measurements = new ConcurrentQueue<Measurement>();
        var listener = new MeterListener();
        listener.EnableMeasurementEvents(MeteringDiagnostics.Requests);
        listener.EnableMeasurementEvents(MeteringDiagnostics.RequestBytes);
        listener.EnableMeasurementEvents(MeteringDiagnostics.ResponseBytes);
        listener.EnableMeasurementEvents(MeteringDiagnostics.InputTokens);
        listener.EnableMeasurementEvents(MeteringDiagnostics.OutputTokens);
        listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) =>
        {
            // Filter by route up front so the process-wide bleed cannot fill the queue.
            var routeTag = tags.ToArray().FirstOrDefault(t => t.Key == MeteringDiagnostics.RouteTag).Value as string;
            if (routeTag is not null && routeTag.StartsWith("m50r-", StringComparison.Ordinal))
            {
                measurements.Enqueue(new Measurement(
                    instrument.Name, value, tags.ToArray().ToDictionary(t => t.Key, t => t.Value)));
            }
        });
        listener.Start();

        var client = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{port}") };
        if (withCaller)
        {
            client.DefaultRequestHeaders.Add("X-CredProx-Key", key);
        }

        return new Metered(caller, key, route)
        {
            Host = host,
            Client = client,
            Listener = listener,
            Measurements = measurements,
        };
    }

    private static IConfiguration BuildConfig(Dictionary<string, string?> entries) =>
        new ConfigurationBuilder().AddInMemoryCollection(entries).Build();

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
    public async Task ForwardedGet_CountersAndResponseBytes_WithFiveFixedTags()
    {
        await using var cell = StartCell();
        var response = await cell.Client.GetAsync("/api/thing");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(UpstreamOk, await response.Content.ReadAsStringAsync());

        var request = await cell.WaitForAsync("credprox.requests");
        Assert.Equal(1, request.Value);
        await Task.Delay(50); // give any second record time to show
        Assert.True(
            cell.Measurements.Count(m => m.Instrument == "credprox.requests") == 1,
            "one forwarded request must produce exactly one record");
        Assert.Equal(
            new[] { "credprox.caller", "credprox.credential", "credprox.destination", "credprox.route", "credprox.status_class" }
                .OrderBy(x => x, StringComparer.Ordinal),
            request.Tags.Keys.OrderBy(x => x, StringComparer.Ordinal));
        Assert.Equal(cell.Caller, request.Tags["credprox.caller"]);
        Assert.Equal("contoso", request.Tags["credprox.credential"]);
        Assert.Equal("acme", request.Tags["credprox.destination"]);
        Assert.Equal(cell.Route, request.Tags["credprox.route"]);
        Assert.Equal("2xx", request.Tags["credprox.status_class"]);

        var responseBytes = await cell.WaitForAsync("credprox.response.bytes");
        Assert.Equal(UpstreamOk.Length, responseBytes.Value);

        // Bodyless request: no request-bytes histogram event for this route at all.
        Assert.False(cell.Has("credprox.request.bytes", cell.Route));
        // No usage opt-in, no provider report: nothing token-shaped.
        Assert.False(cell.Has("credprox.usage.input_tokens", cell.Route));
    }

    private sealed class ForwardOnlyStream(Stream inner) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => inner.Flush();
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private async Task PostByteIdentityLegAsync(Metered cell, HttpContent content)
    {
        var response = await cell.Client.PostAsync("/api/echo", content);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(
            response.Headers.TryGetValues("Transfer-Encoding", out var frame)
            && frame.Any(v => v.Contains("chunked", StringComparison.OrdinalIgnoreCase))); // response kept streamed, not buffered to a length

        // The client reads through a buffered response content; the byte-identity
        // assertion below covers what survived both counting wrappers in both directions.
        var echoBytes = await response.Content.ReadAsByteArrayAsync();
        Assert.Equal(200 * 1024, echoBytes.Length);
        Assert.Equal(Payload, echoBytes);
        // Request-direction framing is deliberately not asserted here: the in-memory
        // TestServer transport normalizes it (a control run with metering unarmed
        // reported a chunked caller request as non-chunked at upstream too), so the
        // header would test the instrument. Socket-level request framing belongs to
        // the real-Kestrel traversal tests; what metering must preserve here is the
        // bytes themselves — asserted just above — and the streamed response framing
        // checked right before the echo read.

        var req = await cell.WaitForAsync("credprox.request.bytes");
        Assert.Equal(200 * 1024, req.Value);
        var resp = await cell.WaitForAsync("credprox.response.bytes");
        Assert.Equal(Payload.Length, resp.Value);
    }

    [Fact]
    public async Task SizedPost_ByteIdentity_BothDirections_BytesCounted()
    {
        await using var cell = StartCell();
        await PostByteIdentityLegAsync(cell, new StreamContent(new MemoryStream(Payload)));
    }

    [Fact]
    public async Task ChunkedPost_ByteIdentity_BothDirections_BytesCounted()
    {
        await using var cell = StartCell();
        await PostByteIdentityLegAsync(cell, new StreamContent(new ForwardOnlyStream(new MemoryStream(Payload))));
    }

    [Fact]
    public async Task AbortedStream_CallerGetsExactPrefix_MeteringNeverOvercounts()
    {
        await using var cell = StartCell();
        using var cts = new CancellationTokenSource();
        string prefix;
        using (var response = await cell.Client.GetAsync("/api/slow", HttpCompletionOption.ResponseHeadersRead, cts.Token))
        {
            var stream = await response.Content.ReadAsStreamAsync(cts.Token);
            var buffer = new byte[10];
            var read = await stream.ReadAsync(buffer.AsMemory(0, 10), cts.Token);
            Assert.Equal(10, read);
            prefix = Encoding.UTF8.GetString(buffer);
            cts.Cancel(); // caller disconnects mid-stream
        }

        Assert.Equal("0123456789", prefix); // the peek delivered the prefix untouched

        // Give any completion record time to arrive, then assert it never claims more
        // than was delivered. Whether an aborted response completes on the server is the
        // host's business; metering must not overcount either way.
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(1);
        while (DateTime.UtcNow < deadline)
        {
            await Task.Delay(10);
        }

        foreach (var m in cell.ForRoute())
        {
            Assert.True(m.Value <= 10, $"{m.Instrument} claimed {m.Value} bytes but at most 10 were delivered.");
        }
    }

    [Fact]
    public async Task UsageOptIn_JsonReport_Counted_UsageTagsCarryNoStatusClass()
    {
        await using var cell = StartCell(usageFormat: "anthropic");
        var response = await cell.Client.GetAsync("/api/usage");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(UsageJson, await response.Content.ReadAsStringAsync()); // untouched

        var input = await cell.WaitForAsync("credprox.usage.input_tokens");
        Assert.Equal(11, input.Value);
        var output = await cell.WaitForAsync("credprox.usage.output_tokens");
        Assert.Equal(7, output.Value);

        Assert.False(input.Tags.ContainsKey("credprox.status_class"));
        Assert.False(output.Tags.ContainsKey("credprox.status_class"));
        Assert.Equal(cell.Caller, input.Tags["credprox.caller"]);
        Assert.Equal(cell.Route, output.Tags["credprox.route"]);

        var request = await cell.WaitForAsync("credprox.requests");
        Assert.Equal("2xx", request.Tags["credprox.status_class"]);
    }

    [Fact]
    public async Task UsageOptIn_Stream_CumulativeLastSeenStands()
    {
        await using var cell = StartCell(usageFormat: "anthropic");
        var response = await cell.Client.GetAsync("/api/stream");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(StreamBody, await response.Content.ReadAsStringAsync());

        var input = await cell.WaitForAsync("credprox.usage.input_tokens");
        Assert.Equal(100, input.Value);
        var output = await cell.WaitForAsync("credprox.usage.output_tokens");
        Assert.Equal(30, output.Value); // 5 then 30: the last cumulative value stands
    }

    // ── M54 ADR-0009: OpenAI-format readers through the real pipeline ──────────
    // Bodies are the Foundry Local 2.5.0 shapes measured in docs/foundry-local-notes.md.

    [Fact]
    public async Task OpenAiFormat_JsonReport_CountedWithoutDoubleCountingReasoning()
    {
        // 13 prompt / 32 completion; completion_tokens already contains reasoning 31, so
        // a reader that added the detail object would report 63. The pipeline reports 32.
        await using var cell = StartCell(usageFormat: "openai");
        var response = await cell.Client.GetAsync("/api/openai");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(OpenAiUsageJson, await response.Content.ReadAsStringAsync()); // untouched

        var input = await cell.WaitForAsync("credprox.usage.input_tokens");
        Assert.Equal(13, input.Value);
        var output = await cell.WaitForAsync("credprox.usage.output_tokens");
        Assert.Equal(32, output.Value);
    }

    [Fact]
    public async Task OpenAiFormat_RouteSpellsFormatInAnotherCase_Counted()
    {
        // The validator accepts the format name case-insensitively and its doc promises a
        // route that passes it can always be served by selection: selection
        // must compare OrdinalIgnoreCase, not Ordinal. A route spelling "OpenAI" against
        // the reader's "openai" must still count — switching the comparer in SelectReader
        // to Ordinal leaves the route silently unmetered, the exact failure ADR-0009
        // exists to remove, and this cell is what turns RED then.
        await using var cell = StartCell(usageFormat: "OpenAI");
        var response = await cell.Client.GetAsync("/api/openai");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var input = await cell.WaitForAsync("credprox.usage.input_tokens");
        Assert.Equal(13, input.Value);
        var output = await cell.WaitForAsync("credprox.usage.output_tokens");
        Assert.Equal(32, output.Value);
    }

    [Fact]
    public async Task OpenAiFormat_Stream_UsageOnlyEventCounted()
    {
        // Only the choices:[] + usage event counts; the content and finish events do not.
        await using var cell = StartCell(usageFormat: "openai");
        var response = await cell.Client.GetAsync("/api/openai-stream");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(OpenAiStreamBody, await response.Content.ReadAsStringAsync());

        var input = await cell.WaitForAsync("credprox.usage.input_tokens");
        Assert.Equal(13, input.Value);
        var output = await cell.WaitForAsync("credprox.usage.output_tokens");
        Assert.Equal(32, output.Value);
    }

    [Fact]
    public async Task OpenAiFormat_StreamWithoutUsageEvent_StaysUnmetered()
    {
        // The measured Foundry Local default: without stream_options.include_usage the
        // stream carries no usage anywhere, and metering stays silent — never guessed.
        await using var cell = StartCell(usageFormat: "openai");
        var response = await cell.Client.GetAsync("/api/openai-stream-nousage");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        await cell.WaitForAsync("credprox.requests");
        Assert.False(cell.Has("credprox.usage.input_tokens", cell.Route));
        Assert.False(cell.Has("credprox.usage.output_tokens", cell.Route));
        Assert.NotNull(cell.Find("credprox.response.bytes")); // counted, never guessed
    }

    [Fact]
    public async Task OpenAiFormat_AnthropicBody_Unmetered_FormatsDoNotCrossParse()
    {
        // RED at the old tip: "openai" sat there as a truthy opt-in and the first
        // CanRead reader — the Anthropic JSON one — parsed this body and reported 11/7.
        // Format-first selection means an openai route can only ever reach openai readers.
        await using var cell = StartCell(usageFormat: "openai");
        var response = await cell.Client.GetAsync("/api/usage");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(UsageJson, await response.Content.ReadAsStringAsync());

        await cell.WaitForAsync("credprox.requests");
        Assert.False(cell.Has("credprox.usage.input_tokens", cell.Route));
        Assert.False(cell.Has("credprox.usage.output_tokens", cell.Route));
    }

    [Fact]
    public async Task SameUsageBody_WithoutOptIn_StaysUnmeteredButStillCounted()
    {
        await using var cell = StartCell();
        var response = await cell.Client.GetAsync("/api/usage");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(UsageJson, await response.Content.ReadAsStringAsync());

        // The request settled (record fired), so the absence below is a real absence:
        await cell.WaitForAsync("credprox.requests");
        Assert.False(cell.Has("credprox.usage.input_tokens", cell.Route));
        Assert.False(cell.Has("credprox.usage.output_tokens", cell.Route));
        Assert.NotNull(cell.Find("credprox.response.bytes"));
    }

    [Fact]
    public async Task OptedInRoute_ProviderReportsNothing_NoUsageEvents()
    {
        await using var cell = StartCell(usageFormat: "anthropic");
        var response = await cell.Client.GetAsync("/api/plain");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        await cell.WaitForAsync("credprox.requests");
        Assert.False(cell.Has("credprox.usage.input_tokens", cell.Route));
        Assert.False(cell.Has("credprox.usage.output_tokens", cell.Route));
        Assert.NotNull(cell.Find("credprox.response.bytes")); // counted, never guessed
    }

    [Fact]
    public async Task TrafficShapes_NeverReachAnyTag()
    {
        await using var cell = StartCell(usageFormat: "anthropic");
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/leaky-PATHMARKER?secret=leaky-QUERYMARKER");
        request.Headers.Add("X-Me", "leaky-HEADERMARKER");
        var response = await cell.Client.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        await cell.WaitForAsync("credprox.requests");
        foreach (var m in cell.ForRoute())
        {
            foreach (var (key, value) in m.Tags)
            {
                Assert.False(
                    value is string s && (s.Contains("MARKER", StringComparison.Ordinal)),
                    $"tag {key} leaked a traffic-shaped value: {value}");
            }
        }
    }

    [Fact]
    public async Task ShortCircuitedRequest_NeverMetersAnything()
    {
        await using var cell = StartCell(withCaller: false);
        var response = await cell.Client.GetAsync("/api/thing");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        // A short circuit never reaches the forwarder, and the response leg (which owns
        // the record) never runs: nothing may be counted. Poll briefly so the absence is
        // observed, not assumed.
        var deadline = DateTime.UtcNow + TimeSpan.FromMilliseconds(500);
        while (DateTime.UtcNow < deadline)
        {
            Assert.False(cell.ForRoute().Any(), "short-circuited request produced a metering measurement");
            await Task.Delay(10);
        }
    }

    [Fact]
    public async Task UnauthenticatedMeteredRequest_TagsAnonymousCallerAndUnknownNames()
    {
        // M50 fold INFO-e: the documented contract says a request forwarded WITHOUT
        // caller authentication is tagged `anonymous`, and a route that names no
        // credential or destination tags `unknown`. The record's fallbacks ran in the
        // union coverage but no committed cell asserted the VALUES — the short-circuit
        // cell above 401s before metering, so `anonymous` had no metered witness at all.
        await using var cell = StartCell(usageFormat: "anthropic", withCaller: false, callerless: true);
        var response = await cell.Client.GetAsync("/api/thing");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var request = await cell.WaitForAsync("credprox.requests");
        Assert.Equal("anonymous", request.Tags["credprox.caller"]);
        Assert.Equal("unknown", request.Tags["credprox.credential"]);
        Assert.Equal("unknown", request.Tags["credprox.destination"]);
        Assert.Equal("2xx", request.Tags["credprox.status_class"]);
        foreach (var m in cell.ForRoute())
        {
            Assert.Equal("anonymous", m.Tags["credprox.caller"]);
        }
    }

    private sealed class SelectionFaultReader : IUsageReader
    {
        // Format must equal the fault cell's route format: selection checks Format
        // before CanRead, so this is what puts the throwing CanRead on the path.
        public string Format => "probe";

        public long? InputTokens => null;
        public long? OutputTokens => null;

        public bool CanRead(string? mediaType) =>
            mediaType == "application/vnd.credprox.probe"
                ? throw new InvalidOperationException("selection witness")
                : false;

        public void Observe(ReadOnlySpan<byte> utf8Chunk, bool endOfStream)
        {
        }
    }

    private sealed class RecordingFaultReader : IUsageReader
    {
        // Format must equal the fault cell's route format — see SelectionFaultReader.
        public string Format => "probe";

        public long? InputTokens => throw new InvalidOperationException("record witness");
        public long? OutputTokens => null;

        public bool CanRead(string? mediaType) => mediaType == "application/vnd.credprox.probe";

        public void Observe(ReadOnlySpan<byte> utf8Chunk, bool endOfStream)
        {
        }
    }

    /// <summary>
    /// A host reader with its OWN format name: on an "acme" route it is selected outright
    /// even on application/json (M54 RED witness — the old first-CanRead selection gave
    /// that media type to the built-in Anthropic JSON reader registered ahead of it), and
    /// on a built-in-format route its different Format keeps it off the path.
    /// </summary>
    private sealed class AcmeReader : IUsageReader
    {
        public string Format => "acme";
        public long? InputTokens => 333;
        public long? OutputTokens => 444;

        public bool CanRead(string? mediaType) =>
            mediaType is not null && mediaType.Contains("json", StringComparison.Ordinal);

        public void Observe(ReadOnlySpan<byte> utf8Chunk, bool endOfStream)
        {
        }
    }

    [Fact]
    public async Task HostReaderFaultInSelection_MetersWithoutUsage_BytesUntouched()
    {
        // M50 fold LOW-3 (SelectReader catch arm): a host reader that throws during
        // selection costs token usage only — the response and the byte counters stand.
        await using var cell = StartCell(usageFormat: "probe", extraServices: s =>
            s.AddTransient<IUsageReader>(_ => new SelectionFaultReader()));
        var response = await cell.Client.GetAsync("/api/custom");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(UpstreamOk, await response.Content.ReadAsStringAsync());

        var request = await cell.WaitForAsync("credprox.requests");
        Assert.Equal(1, request.Value);
        await Task.Delay(50);
        Assert.DoesNotContain(cell.ForRoute(), m => m.Instrument == "credprox.input_tokens");
    }

    [Fact]
    public async Task HostReaderFaultAtRecord_CallerGetsExactBytes_RequestStillCounted()
    {
        // M50 fold LOW-3 (OnCompleted record catch arm): a reader whose usage access
        // throws during recording changes nothing the caller can see — exact bytes, the
        // already-committed request record, and the next request unaffected.
        await using var cell = StartCell(usageFormat: "probe", extraServices: s =>
            s.AddTransient<IUsageReader>(_ => new RecordingFaultReader()));
        var response = await cell.Client.GetAsync("/api/custom");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(UpstreamOk, await response.Content.ReadAsStringAsync());

        var request = await cell.WaitForAsync("credprox.requests");
        Assert.Equal(1, request.Value);

        var second = await cell.Client.GetAsync("/api/custom");
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
    }

    // ── M54 ADR-0009: format-first selection and the fail-closed gate ──────────

    [Fact]
    public async Task HostReaderWithOwnFormat_WinsOnItsRoute_BuiltInJsonReaderNeverSelected()
    {
        // RED at the old tip: selection was first-CanRead-wins and the built-in Anthropic
        // JSON reader registered first, so this host reader never ran on a JSON response.
        // Format-first selection gives the acme route to the host reader outright.
        await using var cell = StartCell(usageFormat: "acme", extraServices: s =>
            s.AddTransient<IUsageReader>(_ => new AcmeReader()));
        var response = await cell.Client.GetAsync("/api/usage");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(UsageJson, await response.Content.ReadAsStringAsync()); // caller sees the vendor body

        var input = await cell.WaitForAsync("credprox.usage.input_tokens");
        Assert.Equal(333, input.Value);
        var output = await cell.WaitForAsync("credprox.usage.output_tokens");
        Assert.Equal(444, output.Value);
    }

    [Fact]
    public async Task BuiltInFormatRoute_IgnoresHostReader_WithADifferentFormat()
    {
        // The same host reader sits on a built-in-format route and must stay off the
        // path: its Format names acme, not anthropic, so the built-in pair keeps its route.
        await using var cell = StartCell(usageFormat: "anthropic", extraServices: s =>
            s.AddTransient<IUsageReader>(_ => new AcmeReader()));
        var response = await cell.Client.GetAsync("/api/usage");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var input = await cell.WaitForAsync("credprox.usage.input_tokens");
        Assert.Equal(11, input.Value); // the vendor's numbers, not the host reader's
        var output = await cell.WaitForAsync("credprox.usage.output_tokens");
        Assert.Equal(7, output.Value);
    }

    [Fact]
    public void LegacyBooleanTrueRoute_RefusedAtStartup_HostRefusesToStart()
    {
        // M50's "true" is gone. LoadFromMemory runs the same route validators as the
        // config-provider path, and YARP fails fast on an invalid initial load: the host
        // does not come up at all, and the thrown tree names the route id and the value.
        // (The reload half of the promise — refuse the change, keep the old config
        // serving, log the reason — is pinned in CredProxUsageFormatValidationTests.)
        var error = Assert.ThrowsAny<Exception>(() => StartCell(usageFormat: "true"));
        Assert.Contains("Route 'm50r-", error.ToString(), StringComparison.Ordinal);
        Assert.Contains("names unknown usage format 'true'", error.ToString(), StringComparison.Ordinal);
    }

    // ── Export seam (M50 live failure) ─────────────────────────────────────────
    // Every other cell here reads the static CredProx meter through a raw
    // MeterListener. That is why the offline gate stayed green while the live
    // failure hid in the CONFIGURED OpenTelemetry pipeline — the one the shipped
    // sample's console exporter attaches to. This cell drives the same metered
    // call through a real MeterProvider (AddMeter("CredProx") + a collecting
    // reader, the export shape the sample wires) and asserts the points reach an
    // exporter with the right values, tags and route attribution. The process-wide
    // bleed is handled the same way as in the listener cells: unique route ids.
    [Fact]
    public async Task ConfiguredMeterProvider_ExportsRequestAndUsagePoints_ToARealExporter()
    {
        var collected = new ConcurrentBag<CollectedPoint>();
        using var provider = Sdk.CreateMeterProviderBuilder()
            .AddMeter("CredProx")
            .AddReader(new BaseExportingMetricReader(new CollectingExporter(collected)))
            .Build();
        await using var cell = StartCell(usageFormat: "anthropic");
        var response = await cell.Client.GetAsync("/api/usage");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(UsageJson, await response.Content.ReadAsStringAsync()); // untouched
        // the listener first: it proves the record ran (OnCompleted fired); only
        // then does a flush prove the configured pipeline carries it to an exporter
        await cell.WaitForAsync("credprox.usage.input_tokens");
        Assert.True(provider.ForceFlush(10000), "the configured MeterProvider refused to flush");
        var request = Point(collected, "credprox.requests", cell.Route);
        Assert.Equal(1, request.Sum);
        Assert.Equal(cell.Caller, Tag(request, MeteringDiagnostics.CallerTag));
        Assert.Equal("2xx", Tag(request, MeteringDiagnostics.StatusClassTag));
        var input = Point(collected, "credprox.usage.input_tokens", cell.Route);
        Assert.Equal(11, input.Sum);
        var output = Point(collected, "credprox.usage.output_tokens", cell.Route);
        Assert.Equal(7, output.Sum);
    }

    /// <summary>Finds the point of <paramref name="instrument"/> carrying this route's tag.</summary>
    private static CollectedPoint Point(IEnumerable<CollectedPoint> collected, string instrument, string route)
    {
        CollectedPoint? found = null;
        var seen = new List<string>();
        foreach (var collectedPoint in collected)
        {
            seen.Add(collectedPoint.Name);
            if (!string.Equals(collectedPoint.Name, instrument, StringComparison.Ordinal))
            {
                continue;
            }

            foreach (var tag in collectedPoint.Tags)
            {
                if (tag.Key == MeteringDiagnostics.RouteTag && Equals(tag.Value, route))
                {
                    found = collectedPoint;
                    break;
                }
            }

            if (found is not null)
            {
                break;
            }
        }

        Assert.True(found is not null,
            $"{instrument} never exported a point for route {route}; exporter saw [{string.Join(", ", seen.Distinct())}].");
        return found!;
    }

    private static string? Tag(CollectedPoint point, string key)
    {
        foreach (var tag in point.Tags)
        {
            if (tag.Key == key)
            {
                return tag.Value as string;
            }
        }

        return null;
    }

    /// <summary>A metric point fully materialised INSIDE Export, as plain data. The SDK
    /// reuses the Metric object (and the storage backing its MetricPoints) the moment the
    /// export callback returns, so neither a Metric nor a MetricPoint may be stored past
    /// Export — reading one afterwards is the silent-blind-spot class that hid the M50
    /// live bug behind the console probe. Name, type, sum and tags are captured while
    /// they are still valid.</summary>
    private sealed record CollectedPoint(
        string Name,
        MetricType Type,
        long Sum,
        IReadOnlyList<KeyValuePair<string, object?>> Tags);

    private sealed class CollectingExporter(ConcurrentBag<CollectedPoint> collected) : BaseExporter<Metric>
    {
        public override ExportResult Export(in Batch<Metric> batch)
        {
            foreach (var metric in batch)
            {
                foreach (var point in metric.GetMetricPoints())
                {
                    // Materialise NOW, inside the callback: nothing below survives
                    // as a reference into Metric or MetricPoint. This harness only
                    // asserts the long counters, so the sum is read for long-sum
                    // instruments; other types (the two ObservableGauges on this
                    // meter) are still recorded with name/type/tags.
                    collected.Add(new CollectedPoint(
                        metric.Name,
                        metric.MetricType,
                        metric.MetricType == MetricType.LongSum ? point.GetSumLong() : 0L,
                        [.. point.Tags]));
                }
            }

            return ExportResult.Success;
        }

        protected override bool OnShutdown(int timeoutMilliseconds) => true;
    }
}
