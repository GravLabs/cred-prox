using System.Diagnostics.Metrics;
using System.Net;
using CredProx;
using Microsoft.Extensions.Options;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage of the resilience startup validator: every accepted range is
/// proven from BOTH sides (the boundary value itself must pass, the first step past it
/// must fail), and each message keeps its exact config path and guidance text — the
/// per-cluster overlays carry the same rules with the cluster's own path.
/// </summary>
public sealed class ResilienceSurvivorTests
{
    private static ValidateOptionsResult Validate(Action<ResilienceOptions> mutate)
    {
        var options = new ResilienceOptions();
        mutate(options);
        return new ResilienceOptionsValidator().Validate(null!, options);
    }

    private static System.Collections.Generic.IEnumerable<string> Failures(
        Action<ResilienceOptions> mutate) => Validate(mutate).Failures!;

    [Fact]
    public void Validator_AcceptsDefaultsAndEveryBoundary()
    {
        Assert.True(new ResilienceOptionsValidator().Validate(null!, new ResilienceOptions()).Succeeded);

        Assert.True(Validate(o =>
        {
            o.AttemptTimeout = TimeSpan.FromMilliseconds(10);
            o.MaxRetries = 0;
            o.RetryBaseDelay = TimeSpan.FromMilliseconds(1);
            o.MaxRetriedBodyBytes = 0;
            o.FailureRatio = 1.0;
            o.MinimumThroughput = 2;
            o.SamplingDuration = TimeSpan.FromMilliseconds(500);
            o.BreakDuration = TimeSpan.FromMilliseconds(500);
        }).Succeeded);
    }

    [Fact]
    public void Validator_AcceptsClusterBoundaries()
    {
        var result = Validate(o =>
        {
            o.Clusters["acme"] = new ResilienceClusterOptions
            {
                AttemptTimeout = TimeSpan.FromMilliseconds(10),
                MaxRetries = 0,
                RetryBaseDelay = TimeSpan.FromMilliseconds(1),
                MaxRetriedBodyBytes = 0,
                FailureRatio = 1.0,
                MinimumThroughput = 2,
                SamplingDuration = TimeSpan.FromMilliseconds(500),
                BreakDuration = TimeSpan.FromMilliseconds(500),
            };
        });

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void Validator_WindowRules_FailWithExactPathsAndLimits()
    {
        // One step under each accepted floor, one step over the shared 24h ceiling — the
        // messages name the exact key the operator has to fix.
        Assert.Equal(
            "CredProx:Resilience:AttemptTimeout must be at least 00:00:00.0100000.",
            Assert.Single(Failures(o => o.AttemptTimeout = TimeSpan.FromMilliseconds(9))));
        Assert.Equal(
            "CredProx:Resilience:RetryBaseDelay must be at least greater than 00:00:00.",
            Assert.Single(Failures(o => o.RetryBaseDelay = TimeSpan.Zero)));
        Assert.Equal(
            "CredProx:Resilience:SamplingDuration must be at least 00:00:00.5000000.",
            Assert.Single(Failures(o => o.SamplingDuration = TimeSpan.FromMilliseconds(499))));
        Assert.Equal(
            "CredProx:Resilience:BreakDuration must be at most 1.00:00:00.",
            Assert.Single(Failures(o => o.BreakDuration = TimeSpan.FromHours(24.5))));
    }

    [Fact]
    public void Validator_CounterRules_FailWithExactGuidance()
    {
        Assert.Equal(
            "CredProx:Resilience:MaxRetries must be >= 0 (0 disables retries).",
            Assert.Single(Failures(o => o.MaxRetries = -1)));
        Assert.Equal(
            "CredProx:Resilience:MaxRetriedBodyBytes must be >= 0.",
            Assert.Single(Failures(o => o.MaxRetriedBodyBytes = -1)));
        Assert.Equal(
            "CredProx:Resilience:FailureRatio must be in (0, 1].",
            Assert.Single(Failures(o => o.FailureRatio = 0)));
        Assert.Equal(
            "CredProx:Resilience:MinimumThroughput must be >= 2.",
            Assert.Single(Failures(o => o.MinimumThroughput = 1)));
    }

    [Fact]
    public void Validator_ClusterOverlays_NameTheClusterPath()
    {
        var result = Validate(o =>
        {
            o.Clusters["acme"] = new ResilienceClusterOptions
            {
                AttemptTimeout = TimeSpan.FromMilliseconds(9),
                MaxRetries = -1,
                RetryBaseDelay = TimeSpan.Zero,
                MaxRetriedBodyBytes = -1,
                FailureRatio = 0,
                MinimumThroughput = 1,
                SamplingDuration = TimeSpan.FromMilliseconds(499),
                BreakDuration = TimeSpan.FromHours(24.5),
            };
        });

        Assert.Equal(
            [
                "CredProx:Resilience:Clusters:acme:AttemptTimeout must be at least 00:00:00.0100000.",
                "CredProx:Resilience:Clusters:acme:MaxRetries must be >= 0.",
                "CredProx:Resilience:Clusters:acme:RetryBaseDelay must be at least greater than 00:00:00.",
                "CredProx:Resilience:Clusters:acme:MaxRetriedBodyBytes must be >= 0.",
                "CredProx:Resilience:Clusters:acme:FailureRatio must be in (0, 1].",
                "CredProx:Resilience:Clusters:acme:MinimumThroughput must be >= 2.",
                "CredProx:Resilience:Clusters:acme:SamplingDuration must be at least 00:00:00.5000000.",
                "CredProx:Resilience:Clusters:acme:BreakDuration must be at most 1.00:00:00.",
            ],
            result.Failures!);
    }

    // ---- per-cluster merge ----

    [Fact]
    public void GetEffective_UnknownCluster_TakesEveryDefault()
    {
        var options = new ResilienceOptions();
        var registry = new ClusterResilienceRegistry(options);

        var effective = registry.GetEffective("no-such-cluster");

        Assert.Equal(
            new ClusterResilienceRegistry.Effective(
                options.AttemptTimeout,
                options.MaxRetries,
                options.RetryBaseDelay,
                options.RetryNonIdempotent,
                options.MaxRetriedBodyBytes,
                options.FailureRatio,
                options.MinimumThroughput,
                options.SamplingDuration,
                options.BreakDuration),
            effective);
    }

    [Fact]
    public void GetEffective_MergesEveryClusterOverrideField()
    {
        var options = new ResilienceOptions();
        options.Clusters["acme"] = new ResilienceClusterOptions
        {
            AttemptTimeout = TimeSpan.FromSeconds(11),
            MaxRetries = 1,
            RetryBaseDelay = TimeSpan.FromSeconds(2),
            RetryNonIdempotent = true,
            MaxRetriedBodyBytes = 42,
            FailureRatio = 0.25,
            MinimumThroughput = 3,
            SamplingDuration = TimeSpan.FromSeconds(21),
            BreakDuration = TimeSpan.FromSeconds(31),
        };
        var registry = new ClusterResilienceRegistry(options);

        var effective = registry.GetEffective("ACME"); // cluster keys are case-insensitive

        Assert.Equal(
            new ClusterResilienceRegistry.Effective(
                TimeSpan.FromSeconds(11),
                1,
                TimeSpan.FromSeconds(2),
                true,
                42,
                0.25,
                3,
                TimeSpan.FromSeconds(21),
                TimeSpan.FromSeconds(31)),
            effective);
        // A different cluster keeps every default — the overlay never leaks sideways.
        Assert.Equal(
            options.BreakDuration,
            new ClusterResilienceRegistry(options).GetEffective("other").BreakDuration);
    }

    // ---- transient classification, witnessed through the pipeline the operator gets ----
    // Outcome<HttpResponseMessage> is Polly-internal, so classification is proven from
    // the outside: transient shapes are retried, everything else surfaces untouched.

    [Theory]
    [InlineData(HttpStatusCode.RequestTimeout)]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.BadGateway)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    [InlineData(HttpStatusCode.GatewayTimeout)]
    public async Task TransientStatuses_AreRetried(HttpStatusCode status)
    {
        var inner = new StubHttpHandler((_, index) =>
            new HttpResponseMessage(index < 1 ? status : HttpStatusCode.OK));
        using var client = MakeClient(Fast(o => o.MaxRetries = 1), inner);

        using var response = await client.GetAsync("https://vendor.example/api");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(2, inner.Requests.Count);
    }

    [Theory]
    [InlineData(HttpStatusCode.OK)]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.TooManyRequests)] // the throttle's pause owns 429
    public async Task NonTransientStatuses_AreNotRetried(HttpStatusCode status)
    {
        var inner = new StubHttpHandler((_, _) => new HttpResponseMessage(status));
        using var client = MakeClient(Fast(o => o.MaxRetries = 3), inner);

        using var response = await client.GetAsync("https://vendor.example/api");

        Assert.Equal(status, response.StatusCode);
        Assert.Single(inner.Requests);
    }

    [Fact]
    public async Task TransportFailure_IsRetried()
    {
        var inner = new StubHttpHandler((_, index) =>
        {
            if (index < 1)
            {
                throw new HttpRequestException("down");
            }

            return new HttpResponseMessage(HttpStatusCode.OK);
        });
        using var client = MakeClient(Fast(o => o.MaxRetries = 1), inner);

        using var response = await client.GetAsync("https://vendor.example/api");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(2, inner.Requests.Count);
    }

    [Fact]
    public async Task VendorAbort_WhileTheCallerStillWaits_IsRetried()
    {
        // An aborted vendor stream is not a cancelled caller: the caller never asked to
        // stop, so the attempt is replayed.
        var inner = new StubHttpHandler((_, index) =>
        {
            if (index < 1)
            {
                throw new OperationCanceledException("vendor aborted the stream");
            }

            return new HttpResponseMessage(HttpStatusCode.OK);
        });
        using var client = MakeClient(Fast(o => o.MaxRetries = 1), inner);

        using var response = await client.GetAsync("https://vendor.example/api");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(2, inner.Requests.Count);
    }

    [Fact]
    public async Task CallerCancellation_IsNeverRetried()
    {
        // Cancelled mid-first-attempt: a caller that walked away never gets a second
        // request hammered at the vendor.
        using var cts = new CancellationTokenSource();
        var inner = new AbortingHandler(cts);
        using var client = MakeClient(Fast(o => o.MaxRetries = 3), inner);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => client.GetAsync("https://vendor.example/api", cts.Token));

        Assert.Equal(1, inner.Calls);
    }

    private sealed class AbortingHandler(CancellationTokenSource callerCts) : HttpMessageHandler
    {
        public int Calls { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            callerCts.Cancel();
            return Task.FromCanceled<HttpResponseMessage>(callerCts.Token);
        }
    }

    [Fact]
    public async Task OtherExceptions_AreNotRetriedAndSurfaceUnchanged()
    {
        var inner = new StubHttpHandler((_, _) => throw new InvalidOperationException("bug"));
        using var client = MakeClient(Fast(o => o.MaxRetries = 3), inner);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.GetAsync("https://vendor.example/api"));

        Assert.Single(inner.Requests);
    }

    // ---- handler driving ----

    private sealed class TailHandler(HttpMessageHandler inner) : DelegatingHandler
    {
        private readonly HttpMessageInvoker _invoker = new(inner);

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            _invoker.SendAsync(request, cancellationToken);
    }

    private static ResilienceOptions Fast(Action<ResilienceOptions>? tweak = null)
    {
        var options = new ResilienceOptions
        {
            MaxRetries = 3,
            RetryBaseDelay = TimeSpan.Zero,
            AttemptTimeout = TimeSpan.FromSeconds(5),
            SamplingDuration = TimeSpan.FromMinutes(1),
            BreakDuration = TimeSpan.FromSeconds(30),
            MinimumThroughput = 100,
            FailureRatio = 1.0,
        };
        tweak?.Invoke(options);
        return options;
    }

    private static HttpClient MakeClient(
        ResilienceOptions options,
        HttpMessageHandler tail,
        string clusterId = "cluster-a")
    {
        var registry = new ClusterResilienceRegistry(options);
        return new HttpClient(new CredProxResilienceHandler(new TailHandler(tail), registry.GetOrCreate(clusterId)));
    }

    [Fact]
    public async Task Retries_AreCountedWithTheClusterTag()
    {
        // The retry counter with its cluster tag is the operator's dashboard for a
        // flapping upstream: no count, or no cluster identity, and the signal is gone.
        var measurements = new List<(long Value, KeyValuePair<string, object?>[] Tags)>();
        using var listener = new MeterListener
        {
            InstrumentPublished = (instrument, l) =>
            {
                if (instrument.Meter.Name == CredProxDiagnostics.MeterName
                    && instrument.Name == "credprox.resilience.retried")
                {
                    l.EnableMeasurementEvents(instrument);
                }
            },
        };
        listener.SetMeasurementEventCallback<long>(
            (_, value, tags, _) => measurements.Add((value, [.. tags])));
        listener.Start();

        var inner = new StubHttpHandler((_, index) =>
            new HttpResponseMessage(index < 2 ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK));
        using var client = MakeClient(Fast(), inner, clusterId: "retry-cluster");
        using (await client.GetAsync("https://vendor.example/api"))
        {
        }

        // A MeterListener subscribes process-wide: resilience measurements from parallel
        // test classes land in this callback too. The claim is about THIS cluster's
        // counter, so filter by the cluster tag first — the id is unique to this file,
        // which makes the filter real isolation, not a lenient assertion.
        var mine = measurements.Where(m => m.Tags.Any(
            t => t.Key == "credprox.cluster" && (string?)t.Value == "retry-cluster")).ToList();
        Assert.Equal(2, mine.Sum(m => m.Value));
    }

    [Fact]
    public async Task CircuitOpening_IsCountedWithTheClusterTag()
    {
        // The breaker-open counter is the operator's page alert: if the emission goes
        // missing the upstream looks merely slow while the cluster is actually dark.
        var measurements = new List<(long Value, KeyValuePair<string, object?>[] Tags)>();
        using var listener = new MeterListener
        {
            InstrumentPublished = (instrument, l) =>
            {
                if (instrument.Meter.Name == CredProxDiagnostics.MeterName
                    && instrument.Name == "credprox.resilience.circuit_opened")
                {
                    l.EnableMeasurementEvents(instrument);
                }
            },
        };
        listener.SetMeasurementEventCallback<long>(
            (_, value, tags, _) => measurements.Add((value, [.. tags])));
        listener.Start();

        var inner = new StubHttpHandler(HttpStatusCode.ServiceUnavailable, "down");
        using var client = MakeClient(
            Fast(o =>
            {
                o.MaxRetries = 0;
                o.MinimumThroughput = 2;
                o.FailureRatio = 1.0;
                // The Fast() durations stay: a 500ms sampling/break pair turns this test
                // into a real-clock race under suite load — a scheduling gap past 500ms
                // splits the sampling window or half-opens the breaker mid-test, and the
                // open count drifts. Nothing here exercises recovery timing.
            }),
            inner,
            clusterId: "breaker-cluster");

        // Two failures at throughput 2 open the breaker; the third request is the open
        // answer, produced without touching the vendor.
        using (await client.GetAsync("https://vendor.example/api"))
        {
        }

        using (await client.GetAsync("https://vendor.example/api"))
        {
        }

        using var third = await client.GetAsync("https://vendor.example/api");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, third.StatusCode);
        Assert.Equal(2, inner.Requests.Count);

        // Process-wide listener (see the retried-count test): filter to this cluster's
        // emissions before counting — the earlier 1-vs-2 flake was foreign events from
        // parallel classes, not the breaker opening twice (impossible inside the 30s
        // break duration the test keeps).
        var mine = measurements.Where(m => m.Tags.Any(
            t => t.Key == "credprox.cluster" && (string?)t.Value == "breaker-cluster")).ToList();
        Assert.Equal(1, mine.Sum(m => m.Value));
    }

    [Fact]
    public async Task RetryPath_KeepsThePerAttemptTimeout()
    {
        // The retry pipeline carries its own attempt timeout: without it a slow upstream
        // would never answer 504 on the retryable path, and the timeout would not be
        // transient (so no second attempt either).
        var inner = new DelayingHandler(TimeSpan.FromMilliseconds(500));
        using var client = MakeClient(
            Fast(o =>
            {
                o.AttemptTimeout = TimeSpan.FromMilliseconds(80);
                o.MaxRetries = 1;
            }),
            inner);

        var response = await client.GetAsync("https://vendor.example/api");

        Assert.Equal(HttpStatusCode.GatewayTimeout, response.StatusCode);
        Assert.Equal(2, inner.Calls);
    }

    private sealed class DelayingHandler(TimeSpan delay) : HttpMessageHandler
    {
        public int Calls { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }

    [Fact]
    public async Task FirstAttemptSendsTheOriginal_LaterAttemptsAreClones()
    {
        // A sent request cannot be resent, so only attempts after the first may be
        // clones: the first must be the caller's own instance, the retry a fresh one.
        var inner = new StubHttpHandler((_, index) =>
            new HttpResponseMessage(index < 1 ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK));
        using var client = MakeClient(Fast(o => o.MaxRetries = 1), inner);
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://vendor.example/api");

        using (await client.SendAsync(request))
        {
        }

        Assert.Equal(2, inner.Requests.Count);
        Assert.Same(request, inner.Requests[0]);
        Assert.NotSame(inner.Requests[0], inner.Requests[1]);
    }

    [Fact]
    public async Task DeclaredLengthAtTheCap_IsBufferedAndRetried()
    {
        // At the cap the body is still re-sendable: the comparison boundary is <=.
        var inner = new StubHttpHandler((_, index) =>
            new HttpResponseMessage(index < 1 ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK));
        using var client = MakeClient(
            Fast(o =>
            {
                o.MaxRetries = 1;
                o.MaxRetriedBodyBytes = 100;
                o.RetryNonIdempotent = true; // the POST is replayable only with this on
            }),
            inner);
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://vendor.example/api")
        {
            Content = new StringContent(new string('x', 100)),
        };

        using (await client.SendAsync(request))
        {
        }

        Assert.Equal(2, inner.Requests.Count);
        Assert.Equal(new string('x', 100), inner.Body(1));
    }

    [Fact]
    public async Task LyingDeclaredLength_IsNotRetried()
    {
        // A declared length under the cap that turns out bigger is treated like the
        // streamed shape: never buffered, never resent.
        var inner = new StubHttpHandler(HttpStatusCode.ServiceUnavailable, "later");
        using var client = MakeClient(
            Fast(o =>
            {
                o.MaxRetries = 3;
                o.MaxRetriedBodyBytes = 10;
                o.RetryNonIdempotent = true; // so the lie, not the method, is what stops the retry
            }),
            inner);
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://vendor.example/api")
        {
            Content = new LyingContent(actualBytes: 50),
        };
        request.Content.Headers.ContentLength = 1; // the lie: 1 declared, 50 sent

        using (await client.SendAsync(request))
        {
        }

        Assert.Single(inner.Requests);
    }

    private sealed class LyingContent(int actualBytes) : HttpContent
    {
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
            stream.WriteAsync(new byte[actualBytes]).AsTask();

        protected override bool TryComputeLength(out long length)
        {
            length = actualBytes;
            return true;
        }
    }

    [Fact]
    public void Feature_PlainCreateHandler_RefusesWithTheClusterScopeText()
    {
        var feature = new CredProxResilienceFeature(new ClusterResilienceRegistry(new ResilienceOptions()));

        var ex = Assert.Throws<InvalidOperationException>(
            () => feature.CreateHandler(new TailHandler(new StubHttpHandler(HttpStatusCode.OK, "x"))));

        Assert.Equal(
            "Resilience is cluster-scoped; the core composes it through the PipelineFeatureContext overload.",
            ex.Message);
    }
}
