using System.Net;
using System.Text;
using System.Text.Json;
using CredProx;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// §5.2 "Resilience" row: retry for idempotent methods only (POST never unless enabled,
/// streamed or over-cap bodies never), a per-attempt timeout, and a per-cluster circuit
/// breaker that opens on the failure threshold, answers 503
/// <c>credprox.upstream_unavailable</c> without reaching the upstream, and half-opens
/// after the break duration.
/// </summary>
public sealed class ResilienceHandlerTests
{
    private static ResilienceOptions Fast(Action<ResilienceOptions>? tweak = null)
    {
        var options = new ResilienceOptions
        {
            MaxRetries = 3,
            RetryBaseDelay = TimeSpan.Zero,
            AttemptTimeout = TimeSpan.FromSeconds(5),
            SamplingDuration = TimeSpan.FromMinutes(1),
            BreakDuration = TimeSpan.FromSeconds(30),

            // High enough that retry tests never trip the breaker; breaker tests lower it.
            MinimumThroughput = 100,
            FailureRatio = 1.0,
        };
        tweak?.Invoke(options);
        return options;
    }

    private static CredProxResilienceHandler MakeHandler(
        ResilienceOptions options,
        HttpMessageHandler tail,
        string clusterId = "cluster-a")
    {
        var registry = new ClusterResilienceRegistry(options);
        return new CredProxResilienceHandler(new TailHandler(tail), registry.GetOrCreate(clusterId));
    }

    private static CredProxResilienceHandler MakeHandler(
        ResilienceOptions options,
        HttpMessageHandler tail,
        ClusterResilienceRegistry registry,
        string clusterId) =>
        new(new TailHandler(tail), registry.GetOrCreate(clusterId));

    private sealed class TailHandler(HttpMessageHandler inner) : DelegatingHandler
    {
        private readonly HttpMessageInvoker _invoker = new(inner);

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            _invoker.SendAsync(request, cancellationToken);
    }

    private static async Task<string> ReadProblemCodeAsync(HttpResponseMessage response)
    {
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return document.RootElement.GetProperty("extensions").GetProperty("code").GetString()!;
    }

    // ---- retry ----

    [Fact]
    public async Task Get_TransientFailures_RetriedUntilSuccess()
    {
        var inner = new StubHttpHandler((_, index) =>
            new HttpResponseMessage(index < 2 ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK));
        using var client = new HttpClient(MakeHandler(Fast(), inner));

        var response = await client.GetAsync("https://vendor.example/api");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(3, inner.Requests.Count);
    }

    [Fact]
    public async Task Get_TransportException_RetriedUntilSuccess()
    {
        var index = 0;
        var inner = new StubHttpHandler((_, _) =>
            Interlocked.Increment(ref index) == 1
                ? throw new HttpRequestException("connection reset")
                : new HttpResponseMessage(HttpStatusCode.OK));
        using var client = new HttpClient(MakeHandler(Fast(), inner));

        var response = await client.GetAsync("https://vendor.example/api");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(2, inner.Requests.Count);
    }

    [Fact]
    public async Task Post_NotRetriedByDefault()
    {
        var inner = new StubHttpHandler(HttpStatusCode.ServiceUnavailable, "down");
        using var client = new HttpClient(MakeHandler(Fast(), inner));

        var response = await client.PostAsync("https://vendor.example/api", new StringContent("payload"));

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Single(inner.Requests);
    }

    [Fact]
    public async Task Post_WithRetryEnabled_BodyIsBufferedAndReplayed()
    {
        var inner = new StubHttpHandler((_, index) =>
            new HttpResponseMessage(index == 0 ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK));
        using var client = new HttpClient(MakeHandler(Fast(o => o.RetryNonIdempotent = true), inner));

        var response = await client.PostAsync(
            "https://vendor.example/api",
            new StringContent("payload", Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(2, inner.Requests.Count);
        Assert.Equal("payload", inner.Body(0));
        Assert.Equal("payload", inner.Body(1)); // the clone carried the buffered body
    }

    [Fact]
    public async Task StreamedBody_NeverRetried()
    {
        var inner = new StubHttpHandler(HttpStatusCode.ServiceUnavailable, "down");
        using var client = new HttpClient(MakeHandler(Fast(o => o.RetryNonIdempotent = true), inner));

        var content = new StreamContent(new ForwardOnlyStream(new MemoryStream("streamed"u8.ToArray())));
        var response = await client.PostAsync("https://vendor.example/api", content);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Single(inner.Requests); // unknown length: never buffered, never retried
    }

    [Fact]
    public async Task OverCapBody_NotRetried()
    {
        var inner = new StubHttpHandler(HttpStatusCode.ServiceUnavailable, "down");
        using var client = new HttpClient(MakeHandler(
            Fast(o =>
            {
                o.RetryNonIdempotent = true;
                o.MaxRetriedBodyBytes = 10;
            }),
            inner));

        var response = await client.PostAsync("https://vendor.example/api", new StringContent("0123456789ABCDEF"));

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Single(inner.Requests);
    }

    [Fact]
    public async Task TooManyRequests_IsNotRetried()
    {
        var inner = new StubHttpHandler(HttpStatusCode.TooManyRequests, "slow down");
        using var client = new HttpClient(MakeHandler(Fast(), inner));

        var response = await client.GetAsync("https://vendor.example/api");

        // The throttle's vendor pause owns 429; retrying it would hammer the vendor.
        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.Single(inner.Requests);
    }

    [Fact]
    public async Task CallerCancellation_IsNotRetried()
    {
        using var cts = new CancellationTokenSource();
        var inner = new StubHttpHandler((_, _) =>
        {
            cts.Cancel();
            throw new OperationCanceledException(cts.Token);
        });
        using var client = new HttpClient(MakeHandler(Fast(), inner));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => client.GetAsync("https://vendor.example/api", cts.Token));
        Assert.Single(inner.Requests);
    }

    // ---- attempt timeout ----

    [Fact]
    public async Task AttemptTimeout_ExhaustedAnswers504()
    {
        var inner = new DelayingHandler(TimeSpan.FromSeconds(2));
        using var client = new HttpClient(MakeHandler(
            Fast(o =>
            {
                o.AttemptTimeout = TimeSpan.FromMilliseconds(200);
                o.MaxRetries = 0;
            }),
            inner));

        var response = await client.GetAsync("https://vendor.example/api");

        Assert.Equal(HttpStatusCode.GatewayTimeout, response.StatusCode);
        Assert.Equal("credprox.upstream_timeout", await ReadProblemCodeAsync(response));
    }

    private sealed class DelayingHandler(TimeSpan delay) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }

    // ---- circuit breaker ----

    private static ResilienceOptions BreakerOptions(string breakDuration = "00:00:00.500") => Fast(o =>
    {
        o.MaxRetries = 0;
        o.MinimumThroughput = 2;
        o.FailureRatio = 1.0;
        o.SamplingDuration = TimeSpan.FromMinutes(1);
        o.BreakDuration = TimeSpan.Parse(breakDuration);
    });

    [Fact]
    public async Task CircuitOpens_AfterFailureThreshold_Answers503WithoutReachingUpstream()
    {
        var inner = new StubHttpHandler(HttpStatusCode.InternalServerError, "boom");
        using var client = new HttpClient(MakeHandler(BreakerOptions(breakDuration: "00:00:30"), inner));

        Assert.Equal(HttpStatusCode.InternalServerError, (await client.GetAsync("https://vendor.example/api")).StatusCode);
        Assert.Equal(HttpStatusCode.InternalServerError, (await client.GetAsync("https://vendor.example/api")).StatusCode);

        var rejected = await client.GetAsync("https://vendor.example/api");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, rejected.StatusCode);
        Assert.Equal("credprox.upstream_unavailable", await ReadProblemCodeAsync(rejected));
        Assert.Equal(2, inner.Requests.Count); // the open circuit never touched the upstream
    }

    [Fact]
    public async Task CircuitHalfOpens_ClosesAfterSuccessfulProbe()
    {
        var index = 0;
        var inner = new StubHttpHandler((_, _) =>
            new HttpResponseMessage(Interlocked.Increment(ref index) <= 2
                ? HttpStatusCode.InternalServerError
                : HttpStatusCode.OK));
        using var client = new HttpClient(MakeHandler(BreakerOptions(), inner));

        await client.GetAsync("https://vendor.example/api");
        await client.GetAsync("https://vendor.example/api");

        // Open: rejected without reaching upstream.
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await client.GetAsync("https://vendor.example/api")).StatusCode);
        Assert.Equal(2, inner.Requests.Count);

        await Task.Delay(TimeSpan.FromSeconds(1.2)); // past the 500ms break: half-open probe

        var probe = await client.GetAsync("https://vendor.example/api");
        Assert.Equal(HttpStatusCode.OK, probe.StatusCode); // the probe reached the upstream and closed the circuit

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("https://vendor.example/api")).StatusCode);
    }

    [Fact]
    public async Task Circuit_IsPerCluster()
    {
        var options = BreakerOptions(breakDuration: "00:00:30");
        var registry = new ClusterResilienceRegistry(options);

        var failing = new StubHttpHandler(HttpStatusCode.InternalServerError, "boom");
        using var clientA = new HttpClient(MakeHandler(options, failing, registry, "cluster-a"));
        using var clientB = new HttpClient(MakeHandler(
            options,
            new StubHttpHandler(HttpStatusCode.OK, "fine"),
            registry,
            "cluster-b"));

        await clientA.GetAsync("https://vendor.example/a");
        await clientA.GetAsync("https://vendor.example/a");
        Assert.Equal(
            HttpStatusCode.ServiceUnavailable,
            (await clientA.GetAsync("https://vendor.example/a")).StatusCode);

        // cluster-b's breaker is a separate state: unaffected by cluster-a's outage.
        Assert.Equal(HttpStatusCode.OK, (await clientB.GetAsync("https://vendor.example/b")).StatusCode);
    }

    [Fact]
    public async Task SuccessesDoNotOpenTheCircuit()
    {
        var inner = new StubHttpHandler(HttpStatusCode.OK, "fine");
        using var client = new HttpClient(MakeHandler(BreakerOptions(breakDuration: "00:00:30"), inner));

        for (var i = 0; i < 10; i++)
        {
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("https://vendor.example/api")).StatusCode);
        }
    }
}
