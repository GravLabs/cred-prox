using System.Net;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Threading.RateLimiting;
using CredProx;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// §5.2 "Throttling" row: under burst the upstream never exceeds the configured rate or
/// concurrency; queue full or wait exceeded answers 429 with <c>Retry-After</c> and
/// <c>credprox.throttled</c>; a vendor 429 with <c>Retry-After</c> pauses the cluster and
/// recovers; limits are per cluster, never global. The rate window runs on
/// <see cref="FakeTimeProvider"/>, so the counts are exact, not statistical.
/// </summary>
public sealed class ThrottleHandlerTests
{
    private const string Cluster = "cluster-a";

    private static ThrottleOptions Rate(int permits, string interval = "00:00:01", int queueLimit = 20, string maxQueueWait = "00:00:05") =>
        new()
        {
            PermitsPerInterval = permits,
            Interval = TimeSpan.Parse(interval),
            QueueLimit = queueLimit,
            MaxQueueWait = TimeSpan.Parse(maxQueueWait),
        };

    private static (ThrottleHandler Handler, ClusterThrottleRegistry Registry) MakeHandler(
        ThrottleOptions options,
        HttpMessageHandler tail,
        TimeProvider time,
        string clusterId = Cluster)
    {
        var registry = new ClusterThrottleRegistry(options, time);
        var handler = new ThrottleHandler(new TailHandler(tail), registry.GetOrCreate(clusterId), clusterId, time);
        return (handler, registry);
    }

    private static async Task WaitUntilAsync(Func<bool> condition, string what)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(10);
        while (!condition())
        {
            Assert.True(DateTime.UtcNow < deadline, $"Timed out waiting for {what}.");
            await Task.Delay(10);
        }
    }

    private static async Task<string> ReadProblemCodeAsync(HttpResponseMessage response)
    {
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return document.RootElement.GetProperty("extensions").GetProperty("code").GetString()!;
    }

    /// <summary>DelegatingHandler tail over a raw transport (the chain's end).</summary>
    private sealed class TailHandler(HttpMessageHandler inner) : DelegatingHandler
    {
        private readonly HttpMessageInvoker _invoker = new(inner);

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            _invoker.SendAsync(request, cancellationToken);
    }

    /// <summary>Holds every request until <see cref="Release"/>, tracking in-flight peaks.</summary>
    private sealed class GatedHandler : HttpMessageHandler
    {
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _inFlight;
        private int _maxInFlight;
        private int _arrivals;

        public int Arrivals => Volatile.Read(ref _arrivals);

        public int MaxInFlight => Volatile.Read(ref _maxInFlight);

        public Func<int, HttpResponseMessage>? Responder { get; init; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var current = Interlocked.Increment(ref _inFlight);
            _ = UpdateMax(ref _maxInFlight, current);
            Interlocked.Increment(ref _arrivals);
            await _release.Task.ConfigureAwait(false);
            Interlocked.Decrement(ref _inFlight);
            return Responder?.Invoke(Volatile.Read(ref _arrivals)) ?? new HttpResponseMessage(HttpStatusCode.OK);
        }

        public void Release() => _release.TrySetResult();

        private static int UpdateMax(ref int max, int candidate)
        {
            int current;
            while (candidate > (current = Volatile.Read(ref max)))
            {
                if (Interlocked.CompareExchange(ref max, candidate, current) == current)
                {
                    break;
                }
            }

            return current;
        }
    }

    // ---- rate limiting ----

    /// <summary>Thread-safe arrival counter with immediate 200s (concurrent arrivals).</summary>
    private sealed class CountingHandler : HttpMessageHandler
    {
        private int _arrivals;

        public int Arrivals => Volatile.Read(ref _arrivals);

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _arrivals);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }

    [Fact]
    public async Task Burst_ReleasesOnlyPermitsPerWindow()
    {
        var time = new FakeTimeProvider();
        var inner = new CountingHandler();
        var (handler, registry) = MakeHandler(Rate(2), inner, time);
        using var client = new HttpClient(handler);

        var requests = Enumerable.Range(0, 4)
            .Select(_ => client.GetAsync("https://vendor.example/api"))
            .ToArray();

        // Two permits per 1s window: exactly two reach the upstream until the window rolls.
        var limiter = registry.GetOrCreate(Cluster).Limiter!;
        await WaitUntilAsync(
            () => inner.Arrivals == 2 && limiter.GetStatistics()!.CurrentQueuedCount == 2,
            "two permits granted and two queued");
        await Task.Delay(50); // let any would-be third arrival show up
        Assert.Equal(2, inner.Arrivals);

        time.Advance(TimeSpan.FromSeconds(1));
        await WaitUntilAsync(() => inner.Arrivals == 4, "the second window's permits");

        var responses = await Task.WhenAll(requests);
        Assert.All(responses, r => Assert.Equal(HttpStatusCode.OK, r.StatusCode));
        Assert.Equal(4, inner.Arrivals);
    }

    [Fact]
    public async Task QueueFull_Rejects429WithRetryAfterAndCode()
    {
        var time = new FakeTimeProvider();
        var gate = new GatedHandler();
        var (handler, _) = MakeHandler(Rate(1, queueLimit: 0), gate, time);
        using var client = new HttpClient(handler);

        var held = client.GetAsync("https://vendor.example/api");
        await WaitUntilAsync(() => gate.Arrivals == 1, "the held request");

        var rejected = await client.GetAsync("https://vendor.example/api");

        Assert.Equal(HttpStatusCode.TooManyRequests, rejected.StatusCode);
        Assert.Equal("application/problem+json", rejected.Content.Headers.ContentType?.MediaType);
        Assert.Equal("credprox.throttled", await ReadProblemCodeAsync(rejected));
        Assert.Equal(TimeSpan.FromSeconds(1), rejected.Headers.RetryAfter?.Delta);

        gate.Release();
        Assert.Equal(HttpStatusCode.OK, (await held).StatusCode);
    }

    [Fact]
    public async Task QueueWaitExceeded_Rejects429()
    {
        var time = new FakeTimeProvider();
        var inner = new StubHttpHandler(HttpStatusCode.OK, "ok");
        // One permit per 10s window; a queued request waits at most 2s.
        var (handler, registry) = MakeHandler(Rate(1, "00:00:10", queueLimit: 10, maxQueueWait: "00:00:02"), inner, time);
        using var client = new HttpClient(handler);

        var first = await client.GetAsync("https://vendor.example/api"); // takes the window's permit
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);

        var queued = client.GetAsync("https://vendor.example/api");
        await WaitUntilAsync(
            () => registry.GetOrCreate(Cluster).Limiter!.GetStatistics()!.CurrentQueuedCount == 1,
            "the queued request");

        time.Advance(TimeSpan.FromSeconds(2));

        var response = await queued;
        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.Equal("credprox.throttled", await ReadProblemCodeAsync(response));
        // 8s of the 10s window remain when the wait is abandoned.
        Assert.Equal(TimeSpan.FromSeconds(8), response.Headers.RetryAfter?.Delta);
        Assert.Single(inner.Requests);
    }

    // ---- vendor throttle pause ----

    [Fact]
    public async Task VendorThrottle_PausesClusterThenRecovers()
    {
        var time = new FakeTimeProvider();
        var index = 0;
        var inner = new StubHttpHandler((_, _) =>
        {
            var i = Interlocked.Increment(ref index);
            var response = new HttpResponseMessage(i == 1 ? HttpStatusCode.TooManyRequests : HttpStatusCode.OK)
            {
                Content = new StringContent(i == 1 ? "vendor-slow-down" : "ok"),
            };
            if (i == 1)
            {
                response.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromSeconds(3));
            }

            return response;
        });
        var options = Rate(0); // no rate limit; pause only
        options.MaxQueueWait = TimeSpan.FromSeconds(1);
        var (handler, registry) = MakeHandler(options, inner, time);
        using var client = new HttpClient(handler);

        var vendor = await client.GetAsync("https://vendor.example/api");
        Assert.Equal(HttpStatusCode.TooManyRequests, vendor.StatusCode);
        Assert.Equal("vendor-slow-down", await vendor.Content.ReadAsStringAsync()); // vendor's own 429 passes through

        // The cluster is paused for 3s; the 1s wait bound cannot cover it.
        var rejected = await client.GetAsync("https://vendor.example/api");
        Assert.Equal(HttpStatusCode.TooManyRequests, rejected.StatusCode);
        Assert.Equal("credprox.throttled", await ReadProblemCodeAsync(rejected));
        Assert.Equal(TimeSpan.FromSeconds(3), rejected.Headers.RetryAfter?.Delta);
        Assert.Single(inner.Requests); // the pause kept the upstream untouched

        time.Advance(TimeSpan.FromSeconds(3));
        var recovered = await client.GetAsync("https://vendor.example/api");
        Assert.Equal(HttpStatusCode.OK, recovered.StatusCode);
        Assert.Equal(TimeSpan.Zero, registry.GetOrCreate(Cluster).PauseRemaining(time));
    }

    [Fact]
    public async Task VendorThrottle_DateRetryAfter_PausesCluster()
    {
        var time = new FakeTimeProvider();
        var inner = new StubHttpHandler((_, index) =>
        {
            var response = new HttpResponseMessage(index == 0 ? HttpStatusCode.TooManyRequests : HttpStatusCode.OK);
            if (index == 0)
            {
                response.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(
                    time.GetUtcNow() + TimeSpan.FromSeconds(2));
            }

            return response;
        });
        var options = Rate(0);
        options.MaxQueueWait = TimeSpan.FromSeconds(1);
        var (handler, _) = MakeHandler(options, inner, time);
        using var client = new HttpClient(handler);

        Assert.Equal(HttpStatusCode.TooManyRequests, (await client.GetAsync("https://vendor.example/api")).StatusCode);

        var rejected = await client.GetAsync("https://vendor.example/api");
        Assert.Equal(HttpStatusCode.TooManyRequests, rejected.StatusCode);
        Assert.Equal("credprox.throttled", await ReadProblemCodeAsync(rejected));

        time.Advance(TimeSpan.FromSeconds(2));
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("https://vendor.example/api")).StatusCode);
    }

    [Fact]
    public async Task VendorThrottle_PauseCappedByMaxPause()
    {
        var time = new FakeTimeProvider();
        var inner = new StubHttpHandler((_, index) =>
        {
            var response = new HttpResponseMessage(index == 0 ? HttpStatusCode.TooManyRequests : HttpStatusCode.OK);
            if (index == 0)
            {
                response.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromMinutes(10));
            }

            return response;
        });
        var options = Rate(0);
        options.MaxQueueWait = TimeSpan.FromSeconds(1);
        options.MaxPause = TimeSpan.FromSeconds(5);
        var (handler, registry) = MakeHandler(options, inner, time);
        using var client = new HttpClient(handler);

        await client.GetAsync("https://vendor.example/api");

        Assert.True(registry.GetOrCreate(Cluster).PauseRemaining(time) <= TimeSpan.FromSeconds(5));
        var rejected = await client.GetAsync("https://vendor.example/api");
        Assert.Equal(TimeSpan.FromSeconds(5), rejected.Headers.RetryAfter?.Delta);
    }

    [Fact]
    public async Task VendorThrottle_WithoutRetryAfter_DoesNotPause()
    {
        var time = new FakeTimeProvider();
        var inner = new StubHttpHandler((_, index) =>
            new HttpResponseMessage(index == 0 ? HttpStatusCode.TooManyRequests : HttpStatusCode.OK));
        var (handler, registry) = MakeHandler(Rate(0), inner, time);
        using var client = new HttpClient(handler);

        Assert.Equal(HttpStatusCode.TooManyRequests, (await client.GetAsync("https://vendor.example/api")).StatusCode);
        Assert.Equal(TimeSpan.Zero, registry.GetOrCreate(Cluster).PauseRemaining(time));

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("https://vendor.example/api")).StatusCode);
    }

    [Fact]
    public void Pause_ExtendsMonotonically()
    {
        var state = new ClusterThrottleRegistry(new ThrottleOptions(), TimeProvider.System).GetOrCreate(Cluster);
        var now = DateTimeOffset.UtcNow;

        state.PauseUntil(now + TimeSpan.FromSeconds(5));
        state.PauseUntil(now + TimeSpan.FromSeconds(2)); // shorter: ignored

        Assert.True(state.PauseRemaining(TimeProvider.System) > TimeSpan.FromSeconds(3));

        state.PauseUntil(now + TimeSpan.FromSeconds(9)); // longer: extends
        Assert.True(state.PauseRemaining(TimeProvider.System) > TimeSpan.FromSeconds(7));
    }

    // ---- per-cluster scoping ----

    [Fact]
    public async Task Limits_ArePerCluster_NotGlobal()
    {
        var time = new FakeTimeProvider();
        var options = new ThrottleOptions();
        options.Clusters["cluster-a"] = new ThrottleClusterOptions
        {
            PermitsPerInterval = 1,
            Interval = TimeSpan.FromSeconds(10),
            QueueLimit = 0,
        };
        var gateA = new GatedHandler();
        var innerB = new StubHttpHandler(HttpStatusCode.OK, "ok");

        var registry = new ClusterThrottleRegistry(options, time);
        using var clientA = new HttpClient(new ThrottleHandler(new TailHandler(gateA), registry.GetOrCreate("cluster-a"), "cluster-a", time));
        using var clientB = new HttpClient(new ThrottleHandler(new TailHandler(innerB), registry.GetOrCreate("cluster-b"), "cluster-b", time));

        var held = clientA.GetAsync("https://vendor.example/a");
        await WaitUntilAsync(() => gateA.Arrivals == 1, "the held cluster-a request");

        var rejected = await clientA.GetAsync("https://vendor.example/a");
        Assert.Equal(HttpStatusCode.TooManyRequests, rejected.StatusCode);

        // cluster-b carries no limits: unaffected by cluster-a's exhaustion.
        var other = await clientB.GetAsync("https://vendor.example/b");
        Assert.Equal(HttpStatusCode.OK, other.StatusCode);

        gateA.Release();
        await held;
    }

    [Fact]
    public async Task ConcurrencyLimit_CapsInFlightUpstream()
    {
        var time = new FakeTimeProvider();
        var gate = new GatedHandler();
        var options = new ThrottleOptions { MaxConcurrency = 2, QueueLimit = 10 };
        var (handler, _) = MakeHandler(options, gate, time);
        using var client = new HttpClient(handler);

        var requests = Enumerable.Range(0, 5)
            .Select(_ => client.GetAsync("https://vendor.example/api"))
            .ToArray();

        await WaitUntilAsync(() => gate.Arrivals == 2, "the two concurrency permits");
        await Task.Delay(100); // let any would-be third arrival show up
        Assert.Equal(2, gate.Arrivals);
        Assert.Equal(2, gate.MaxInFlight);

        gate.Release();
        var responses = await Task.WhenAll(requests);
        Assert.All(responses, r => Assert.Equal(HttpStatusCode.OK, r.StatusCode));
        Assert.Equal(5, gate.Arrivals);
    }

    [Fact]
    public async Task NoLimits_PassThrough()
    {
        var time = new FakeTimeProvider();
        var inner = new StubHttpHandler(HttpStatusCode.OK, "ok");
        var (handler, registry) = MakeHandler(new ThrottleOptions(), inner, time);
        using var client = new HttpClient(handler);

        var response = await client.GetAsync("https://vendor.example/api");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Null(registry.GetOrCreate(Cluster).Limiter);
    }

    // ---- FixedWindowRateLimiter unit surface ----

    [Fact]
    public void FixedWindow_TryAcquire_GrantsWindowThenDeniesWithRetryAfter()
    {
        var time = new FakeTimeProvider();
        using var limiter = new FixedWindowRateLimiter(2, TimeSpan.FromSeconds(1), 0, time);

        Assert.True(limiter.AttemptAcquire(1).IsAcquired);
        Assert.True(limiter.AttemptAcquire(1).IsAcquired);

        using var denied = limiter.AttemptAcquire(1);
        Assert.False(denied.IsAcquired);
        Assert.True(denied.TryGetMetadata(MetadataName.RetryAfter, out TimeSpan retryAfter));
        Assert.Equal(TimeSpan.FromSeconds(1), retryAfter);

        time.Advance(TimeSpan.FromSeconds(1));
        Assert.True(limiter.AttemptAcquire(1).IsAcquired);
    }

    [Fact]
    public async Task FixedWindow_QueuedWaiters_GrantedFifoAtWindowRoll()
    {
        var time = new FakeTimeProvider();
        using var limiter = new FixedWindowRateLimiter(1, TimeSpan.FromSeconds(1), 5, time);

        Assert.True(limiter.AttemptAcquire(1).IsAcquired);
        var first = limiter.AcquireAsync(1);
        var second = limiter.AcquireAsync(1);
        Assert.False(first.IsCompleted);
        Assert.False(second.IsCompleted);

        time.Advance(TimeSpan.FromSeconds(1));
        using var grantedFirst = await first;
        Assert.True(grantedFirst.IsAcquired);

        time.Advance(TimeSpan.FromSeconds(1));
        using var grantedSecond = await second;
        Assert.True(grantedSecond.IsAcquired);

        var statistics = limiter.GetStatistics();
        Assert.Equal(3, statistics.TotalSuccessfulLeases);
        Assert.Equal(0, statistics.CurrentQueuedCount);
    }

    [Fact]
    public async Task FixedWindow_RequeuesAfterFullDrain_GrantedAtNextWindowRoll()
    {
        var time = new FakeTimeProvider();
        using var limiter = new FixedWindowRateLimiter(1, TimeSpan.FromSeconds(1), 5, time);

        // First cycle: one grant, one waiter; the queue fully drains at the window roll.
        Assert.True(limiter.AttemptAcquire(1).IsAcquired);
        var drained = limiter.AcquireAsync(1);
        time.Advance(TimeSpan.FromSeconds(1));
        using (var lease = await drained)
        {
            Assert.True(lease.IsAcquired);
        }

        // Second cycle after the drain, in a window of its own (the drained waiter's
        // grant consumed the previous window's only permit): the grant timer must be
        // re-armed for the fresh waiter. A timer that was only disarmed (never dropped)
        // would never fire again, the waiter would stall past every window, and the fast
        // path would stay blocked behind it — throughput collapsing to zero (M8 F1).
        time.Advance(TimeSpan.FromSeconds(1));
        Assert.True(limiter.AttemptAcquire(1).IsAcquired);
        var requeued = limiter.AcquireAsync(1);
        Assert.False(requeued.IsCompleted);
        time.Advance(TimeSpan.FromSeconds(1));

        Assert.True(requeued.IsCompletedSuccessfully);
        using (var lease = await requeued)
        {
            Assert.True(lease.IsAcquired);
        }
    }

    [Fact]
    public async Task FixedWindow_CancellationRemovesWaiter()
    {
        var time = new FakeTimeProvider();
        using var limiter = new FixedWindowRateLimiter(1, TimeSpan.FromSeconds(1), 5, time);

        Assert.True(limiter.AttemptAcquire(1).IsAcquired);
        using var cts = new CancellationTokenSource();
        var queued = limiter.AcquireAsync(1, cts.Token);
        cts.Cancel();

        using var lease = await queued;
        Assert.False(lease.IsAcquired);
        Assert.Equal(0, limiter.GetStatistics().CurrentQueuedCount);
    }

    [Fact]
    public async Task FixedWindow_PreCancelledToken_FailsAtOnceWithoutTakingAQueueSlot()
    {
        var time = new FakeTimeProvider();
        using var limiter = new FixedWindowRateLimiter(1, TimeSpan.FromSeconds(1), 5, time);
        Assert.True(limiter.AttemptAcquire(1).IsAcquired);

        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => limiter.AcquireAsync(1, cts.Token).AsTask());
        Assert.Equal(0, limiter.GetStatistics().CurrentQueuedCount);
    }

    // Follow-up (c) (M8 review): the caller-token registration must die with the waiter,
    // not live on the token. A live CTS roots its registrations' state, so if the
    // registration leaked, the CTS would keep the limiter (and waiter) alive — the
    // WeakReference below is the observable. GC.KeepAlive(cts) is load-bearing: without
    // it the JIT may collect the CTS itself during the collection, taking any leaked
    // registration with it and passing the test without the fix.
    [Fact]
    public async Task FixedWindow_GrantedWaiter_DoesNotOutliveItUnderALiveToken()
    {
        using var cts = new CancellationTokenSource(); // never cancelled: stays alive
        var weak = await QueueAndGrantAsync(cts);

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        Assert.False(weak.IsAlive);
        GC.KeepAlive(cts);
    }

    [Fact]
    public async Task FixedWindow_CancelledWaiter_DoesNotOutliveItUnderALiveToken()
    {
        using var cts = new CancellationTokenSource();
        var weak = await QueueAndCancelAsync(cts);

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        Assert.False(weak.IsAlive);
        GC.KeepAlive(cts);
    }

    [Fact]
    public async Task FixedWindow_DisposedLimiter_DoesNotOutliveItUnderALiveToken()
    {
        using var cts = new CancellationTokenSource();
        var weak = await QueueAndDisposeAsync(cts);

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        Assert.False(weak.IsAlive);
        GC.KeepAlive(cts);
    }

    // Each helper keeps no reference to the limiter (or its time provider) past return,
    // so the only possible root left is a leaked registration on the live token.
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static async Task<WeakReference> QueueAndGrantAsync(CancellationTokenSource cts)
    {
        var time = new FakeTimeProvider();
        var limiter = new FixedWindowRateLimiter(1, TimeSpan.FromSeconds(1), 5, time);
        Assert.True(limiter.AttemptAcquire(1).IsAcquired);
        var queued = limiter.AcquireAsync(1, cts.Token);
        time.Advance(TimeSpan.FromSeconds(1));
        using var lease = await queued;
        Assert.True(lease.IsAcquired);
        limiter.Dispose(); // the grant path alone leaves the limiter collectable
        return new WeakReference(limiter);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static async Task<WeakReference> QueueAndCancelAsync(CancellationTokenSource cts)
    {
        var limiter = new FixedWindowRateLimiter(1, TimeSpan.FromSeconds(1), 5, new FakeTimeProvider());
        Assert.True(limiter.AttemptAcquire(1).IsAcquired);
        var queued = limiter.AcquireAsync(1, cts.Token);
        cts.Cancel();
        using var lease = await queued;
        Assert.False(lease.IsAcquired);
        limiter.Dispose(); // the cancel path alone leaves the limiter collectable
        return new WeakReference(limiter);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static async Task<WeakReference> QueueAndDisposeAsync(CancellationTokenSource cts)
    {
        var limiter = new FixedWindowRateLimiter(1, TimeSpan.FromSeconds(1), 5, new FakeTimeProvider());
        Assert.True(limiter.AttemptAcquire(1).IsAcquired);
        var queued = limiter.AcquireAsync(1, cts.Token);
        limiter.Dispose();
        using var lease = await queued;
        Assert.False(lease.IsAcquired);
        return new WeakReference(limiter);
    }

    [Fact]
    public async Task FixedWindow_DisposeReleasesQueuedWaiters()
    {
        var limiter = new FixedWindowRateLimiter(1, TimeSpan.FromSeconds(1), 5, new FakeTimeProvider());
        Assert.True(limiter.AttemptAcquire(1).IsAcquired);
        var queued = limiter.AcquireAsync(1);

        limiter.Dispose();

        using var lease = await queued;
        Assert.False(lease.IsAcquired);
    }

    [Fact]
    public void FixedWindow_RejectsBadArguments()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new FixedWindowRateLimiter(0, TimeSpan.FromSeconds(1), 0, TimeProvider.System));
        Assert.Throws<ArgumentOutOfRangeException>(() => new FixedWindowRateLimiter(1, TimeSpan.Zero, 0, TimeProvider.System));
        Assert.Throws<ArgumentNullException>(() => new FixedWindowRateLimiter(1, TimeSpan.FromSeconds(1), 0, null!));
        using var limiter = new FixedWindowRateLimiter(1, TimeSpan.FromSeconds(1), 0, TimeProvider.System);
        Assert.Throws<ArgumentOutOfRangeException>(() => limiter.AttemptAcquire(2));
        Assert.Equal(TimeSpan.Zero, limiter.IdleDuration);
    }
}
