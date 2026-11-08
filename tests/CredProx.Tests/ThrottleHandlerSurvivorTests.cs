using System.Net;
using System.Net.Http.Headers;
using System.Diagnostics.Metrics;
using CredProx;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage of <see cref="ThrottleHandler"/>: the cluster tag on both throttle
/// counters, the vendor-pause condition boundaries (disabled switch, zero advertised
/// duration, wait bound exactly at <c>MaxQueueWait</c>), the post-delay re-check when the
/// pause is extended while waiting, caller-cancellation propagation through the timeout
/// catch, and the degenerate zero-wait path's <c>Retry-After</c> clamp.
/// </summary>
public sealed class ThrottleHandlerSurvivorTests
{
    // ---- counters and their cluster tag ----

    [Fact]
    public async Task ThrottleRejectionAndPauseCounters_CarryTheClusterTag()
    {
        var seen = new List<(string Instrument, string TagKey, object? TagValue, long Tag)>();
        using var listener = new MeterListener
        {
            InstrumentPublished = (instrument, l) =>
            {
                if (instrument is { Name: "credprox.throttle.rejected" or "credprox.throttle.paused" })
                {
                    l.EnableMeasurementEvents(instrument);
                }
            },
        };
        listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, _) =>
        {
            foreach (var tag in tags)
            {
                lock (seen)
                {
                    seen.Add((instrument.Name, tag.Key, tag.Value, measurement));
                }
            }
        });
        listener.Start();

        // Cluster A: a vendor 429 with Retry-After pauses it (paused counter).
        var timeA = new FakeTimeProvider();
        var (handlerA, _) = MakeHandler(
            Rate(10),
            new StubHandler(_ => VendorThrottle(TimeSpan.FromSeconds(3))),
            timeA,
            "triage-pause");
        using var clientA = new HttpClient(handlerA);
        using (var paused = await clientA.GetAsync("https://vendor.example/api"))
        {
            Assert.Equal(HttpStatusCode.TooManyRequests, paused.StatusCode); // passes through untouched
        }

        // Cluster B: full queue rejects (rejected counter).
        var timeB = new FakeTimeProvider();
        var (handlerB, _) = MakeHandler(
            Rate(1, queueLimit: 0),
            new StubHandler(_ => Ok()),
            timeB,
            "triage-reject");
        using var clientB = new HttpClient(handlerB);
        using (var first = await clientB.GetAsync("https://vendor.example/api"))
        {
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        }

        using var rejected = await clientB.GetAsync("https://vendor.example/api");
        Assert.Equal(HttpStatusCode.TooManyRequests, rejected.StatusCode);

        lock (seen)
        {
            // Predicate includes THIS test's cluster ids: MeterListener is process-wide,
            // and paused/rejected events from parallel throttle tests land in `seen` too —
            // an instrument-only Single flaked whenever another cluster emitted alongside.
            var pause = Assert.Single(
                seen, m => m.Instrument == "credprox.throttle.paused" && (string?)m.TagValue == "triage-pause");
            Assert.Equal("credprox.cluster", pause.TagKey);
            Assert.Equal(1L, pause.Tag);

            var reject = Assert.Single(
                seen, m => m.Instrument == "credprox.throttle.rejected" && (string?)m.TagValue == "triage-reject");
            Assert.Equal("credprox.cluster", reject.TagKey);
            Assert.Equal(1L, reject.Tag);
        }
    }

    // ---- vendor-pause condition boundaries ----

    [Fact]
    public async Task VendorThrottle_PauseDisabled_NoPauseRecorded()
    {
        var options = Rate(10);
        options.PauseOnVendorThrottle = false;
        var time = new FakeTimeProvider();
        var (handler, registry) = MakeHandler(options, new StubHandler(_ => VendorThrottle(TimeSpan.FromSeconds(3))), time);
        using var client = new HttpClient(handler);

        using var response = await client.GetAsync("https://vendor.example/api");

        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode); // the vendor's own 429 passes through
        Assert.Equal(TimeSpan.Zero, registry.GetOrCreate("cluster-a").PauseRemaining(time));
    }

    [Fact]
    public async Task VendorThrottle_ZeroAdvertisedDuration_NoPauseRecorded()
    {
        var time = new FakeTimeProvider();
        var (handler, registry) = MakeHandler(Rate(10), new StubHandler(_ => VendorThrottle(TimeSpan.Zero)), time);
        using var client = new HttpClient(handler);

        using var response = await client.GetAsync("https://vendor.example/api");

        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.Equal(TimeSpan.Zero, registry.GetOrCreate("cluster-a").PauseRemaining(time));
    }

    [Fact]
    public async Task PauseExactlyAtMaxQueueWait_WaitsOutThePauseAndProceeds()
    {
        // The wait bound is exclusive: a pause of exactly MaxQueueWait is waited out,
        // not rejected (the >= mutant answers 429 here; dropping the delay also rejects
        // because the pause has not elapsed when the re-check runs).
        var time = new FakeTimeProvider();
        var (handler, registry) = MakeHandler(Rate(1, maxQueueWait: "00:00:01"), new StubHandler(_ => Ok()), time);
        registry.GetOrCreate("cluster-a").PauseUntil(time.GetUtcNow() + TimeSpan.FromSeconds(1));
        using var client = new HttpClient(handler);

        var request = client.GetAsync("https://vendor.example/api");
        time.Advance(TimeSpan.FromSeconds(1));

        using var response = await request;
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task PauseExtendedWhileWaiting_RejectedWithTheRemainingPause()
    {
        // The post-delay re-check must see a pause extended mid-wait and reject with the
        // remaining duration (a skipped re-check or a negated bound proceeds upstream).
        var time = new FakeTimeProvider();
        var (handler, registry) = MakeHandler(Rate(1, maxQueueWait: "00:00:05"), new StubHandler(_ => Ok()), time);
        var state = registry.GetOrCreate("cluster-a");
        state.PauseUntil(time.GetUtcNow() + TimeSpan.FromSeconds(1));
        using var client = new HttpClient(handler);

        var request = client.GetAsync("https://vendor.example/api");
        state.PauseUntil(time.GetUtcNow() + TimeSpan.FromSeconds(3)); // extended while the wait runs
        time.Advance(TimeSpan.FromSeconds(1)); // the original wait elapses

        using var response = await request;
        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.Equal(TimeSpan.FromSeconds(2), response.Headers.RetryAfter?.Delta);
    }

    // ---- the timeout catch must not swallow the caller's own cancellation ----

    [Fact]
    public async Task CallerPreCancelled_PropagatesOperationCanceled_EvenWithLimiter()
    {
        var time = new FakeTimeProvider();
        var (handler, _) = MakeHandler(Rate(1, maxQueueWait: "00:00:05"), new StubHandler(_ => Ok()), time);
        using var invoker = new HttpMessageInvoker(handler, disposeHandler: true);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        // The only OCE source between the step boundaries is AcquireAsync's own check on
        // the linked token; the catch must rethrow because it is the caller's cancellation.
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            invoker.SendAsync(new HttpRequestMessage(HttpMethod.Get, "https://vendor.example/api"), cts.Token));
    }

    [Fact]
    public async Task DegenerateZeroQueueWait_Rejects429WithClampedRetryAfter()
    {
        // MaxQueueWait <= 0 is refused at validation, but the catch's Rejected(MaxQueueWait)
        // is the handler's own defensive floor: it must answer 429 with Retry-After: 1,
        // never 0 and never a propagated OCE.
        var time = new FakeTimeProvider();
        var (handler, _) = MakeHandler(Rate(1, maxQueueWait: "00:00:00"), new StubHandler(_ => Ok()), time);
        using var invoker = new HttpMessageInvoker(handler, disposeHandler: true);

        var send = invoker.SendAsync(new HttpRequestMessage(HttpMethod.Get, "https://vendor.example/api"), CancellationToken.None);
        Assert.True(await Task.WhenAny(send, Task.Delay(TimeSpan.FromSeconds(10))) == send, "the zero wait must resolve at once");

        using var response = await send;
        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.Equal(TimeSpan.FromSeconds(1), response.Headers.RetryAfter?.Delta);
    }

    // ---- helpers ----

    private static ThrottleOptions Rate(int permits, string maxQueueWait = "00:00:05", int queueLimit = 20) => new()
    {
        PermitsPerInterval = permits,
        Interval = TimeSpan.FromSeconds(1),
        QueueLimit = queueLimit,
        MaxQueueWait = TimeSpan.Parse(maxQueueWait),
    };

    private static (ThrottleHandler Handler, ClusterThrottleRegistry Registry) MakeHandler(
        ThrottleOptions options,
        HttpMessageHandler tail,
        TimeProvider time,
        string clusterId = "cluster-a")
    {
        var registry = new ClusterThrottleRegistry(options, time);
        var handler = new ThrottleHandler(new TailHandler(tail), registry.GetOrCreate(clusterId), clusterId, time);
        return (handler, registry);
    }

    private static HttpResponseMessage Ok() =>
        new(HttpStatusCode.OK) { Content = new StringContent("ok") };

    private static HttpResponseMessage VendorThrottle(TimeSpan retryAfter)
    {
        var response = new HttpResponseMessage(HttpStatusCode.TooManyRequests)
        {
            Content = new StringContent("vendor-slow-down"),
        };
        response.Headers.RetryAfter = new RetryConditionHeaderValue(retryAfter);
        return response;
    }

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) => Task.FromResult(respond(request));
    }

    /// <summary>DelegatingHandler tail over a raw transport (the chain's end).</summary>
    private sealed class TailHandler(HttpMessageHandler inner) : DelegatingHandler(inner)
    {
        private readonly HttpMessageInvoker _invoker = new(inner);

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            _invoker.SendAsync(request, cancellationToken);
    }

    // ---- M31 batch-2 survivors ----

    [Fact]
    public async Task VendorThrottleWithZeroRetryAfter_PausesNothing()
    {
        // "Retry-After: 0" is vendor-speak for no advertised pause: the cluster must not
        // be paused and the pause counter must stay silent — counting a zero-length pause
        // would make the operator's dashboard lie.
        var paused = new List<long>();
        using var listener = new MeterListener
        {
            InstrumentPublished = (instrument, l) =>
            {
                if (instrument is { Name: "credprox.throttle.paused" })
                {
                    l.EnableMeasurementEvents(instrument);
                }
            },
        };
        listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, _) =>
        {
            if (instrument.Name != "credprox.throttle.paused")
            {
                return;
            }

            // The zero-assert must watch THIS cluster only: MeterListener is
            // process-wide, and the parallel vendor-throttle suites pause their own
            // clusters — an instrument-only filter made this an intermittent red.
            foreach (var tag in tags)
            {
                if (tag is { Key: "credprox.cluster", Value: "triage-zero-pause" })
                {
                    lock (paused)
                    {
                        paused.Add(measurement);
                    }
                }
            }
        });
        listener.Start();

        var (handler, _) = MakeHandler(
            Rate(10),
            new StubHandler(_ => VendorThrottle(TimeSpan.Zero)),
            new FakeTimeProvider(),
            "triage-zero-pause");
        using var invoker = new HttpMessageInvoker(handler, disposeHandler: true);
        using (var response = await invoker.SendAsync(
            new HttpRequestMessage(HttpMethod.Get, "https://vendor.example/api"), CancellationToken.None))
        {
            Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode); // passes through untouched
        }

        Assert.Empty(paused);
    }

    [Fact]
    public void ThrottleFeature_NonContextualCreateHandler_NamesTheClusterScopedReason()
    {
        // The bare overload cannot compose a cluster-scoped handler: the message is the
        // diagnosis, the exception type alone is not.
        var feature = new CredProxThrottleFeature(
            new ClusterThrottleRegistry(Rate(1), new FakeTimeProvider()),
            new FakeTimeProvider());

        var error = Assert.Throws<InvalidOperationException>(
            () => feature.CreateHandler(new TailHandler(new StubHandler(_ => Ok()))));

        Assert.Contains("Throttling is cluster-scoped", error.Message, StringComparison.Ordinal);
    }
}
