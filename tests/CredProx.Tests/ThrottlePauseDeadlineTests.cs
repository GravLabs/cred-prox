using System.Net;
using System.Text.Json;
using CredProx;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The vendor-pause wait bound: a held request may wait the pause out as long as its total
/// wait stays within <c>MaxQueueWait</c>; it is answered <c>429</c> only when the pause —
/// possibly extended while the request waited — outlasts that bound. Timer callbacks fire a
/// little before their due time here: the deterministic analogue of the whole-millisecond
/// rounding inside <see cref="Task.Delay(TimeSpan)"/>, which can wake a waiter slightly
/// before the pause actually ends.
/// </summary>
public sealed class ThrottlePauseDeadlineTests
{
    private const string Cluster = "cluster-a";

    [Fact]
    public async Task VendorPause_TimerFiresJustBeforeTheDeadline_RequestIsForwarded()
    {
        var fake = new FakeTimeProvider();
        var time = new EarlyTimerTimeProvider(fake);
        var options = PauseOnlyOptions("00:00:05");
        var (handler, registry) = MakeHandler(options, out var transport, time);
        registry.GetOrCreate(Cluster).PauseUntil(fake.GetUtcNow() + TimeSpan.FromSeconds(2));
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) }; // a stuck pause loop must unwind in seconds
        var request = client.GetAsync("https://vendor.example/api");
        await AdvanceUntilAsync(fake, request, "the held request");
        var response = await request;
        await AssertForwardedAsync(response, transport);
        Assert.True(
            time.TimerCreations <= 8,
            $"waiting the pause out took {time.TimerCreations} timer rounds; a bounded wait needs only a few.");
    }

    [Fact]
    public async Task VendorPause_OutlastingMaxQueueWait_IsRejected()
    {
        var fake = new FakeTimeProvider();
        var time = new EarlyTimerTimeProvider(fake);
        var options = PauseOnlyOptions("00:00:01");
        var (handler, registry) = MakeHandler(options, out var transport, time);
        registry.GetOrCreate(Cluster).PauseUntil(fake.GetUtcNow() + TimeSpan.FromSeconds(3));
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) }; // a stuck pause loop must unwind in seconds
        var response = await client.GetAsync("https://vendor.example/api");
        await AssertRejectedAsync(response, TimeSpan.FromSeconds(3));
        Assert.Equal(0, transport.Arrivals);
    }

    [Fact]
    public async Task VendorPause_ExtendedMidWaitWithinTheBound_IsForwarded()
    {
        var fake = new FakeTimeProvider();
        var time = new EarlyTimerTimeProvider(fake);
        var options = PauseOnlyOptions("00:00:05");
        var (handler, registry) = MakeHandler(options, out var transport, time);
        var start = fake.GetUtcNow();
        registry.GetOrCreate(Cluster).PauseUntil(start + TimeSpan.FromSeconds(1));
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) }; // a stuck pause loop must unwind in seconds
        var request = client.GetAsync("https://vendor.example/api");
        await WaitUntilAsync(() => time.TimerCreations >= 1, "the first pause delay to be scheduled");
        registry.GetOrCreate(Cluster).PauseUntil(start + TimeSpan.FromSeconds(3));
        await AdvanceUntilAsync(fake, request, "the held request");
        var response = await request;
        await AssertForwardedAsync(response, transport);
    }

    [Fact]
    public async Task VendorPause_ExtendedMidPastTheBound_IsRejected()
    {
        var fake = new FakeTimeProvider();
        var time = new EarlyTimerTimeProvider(fake);
        var options = PauseOnlyOptions("00:00:03");
        var (handler, registry) = MakeHandler(options, out var transport, time);
        var start = fake.GetUtcNow();
        registry.GetOrCreate(Cluster).PauseUntil(start + TimeSpan.FromSeconds(1));
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) }; // a stuck pause loop must unwind in seconds
        var request = client.GetAsync("https://vendor.example/api");
        await WaitUntilAsync(() => time.TimerCreations >= 1, "the first pause delay to be scheduled");
        registry.GetOrCreate(Cluster).PauseUntil(start + TimeSpan.FromSeconds(5));
        await AdvanceUntilAsync(fake, request, "the held request's decision");
        var response = await request;
        await AssertRejectedAsync(response, TimeSpan.FromSeconds(5));
        Assert.Equal(0, transport.Arrivals);
    }

    [Fact]
    public async Task VendorPause_MaxQueueWaitPastTheClockEnd_PauseIsWaitedOut()
    {
        // A one-day wait bound reaches past the end of DateTimeOffset's clock from this
        // instant: the deadline must saturate at DateTimeOffset.MaxValue, not throw
        // (entry + MaxQueueWait overflows before the clamp exists).
        var fake = new FakeTimeProvider();
        fake.SetUtcNow(DateTimeOffset.MaxValue - TimeSpan.FromMinutes(1));
        var time = new EarlyTimerTimeProvider(fake);
        var options = PauseOnlyOptions("1.00:00:00");
        var (handler, registry) = MakeHandler(options, out var transport, time);
        registry.GetOrCreate(Cluster).PauseUntil(fake.GetUtcNow() + TimeSpan.FromSeconds(5));
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) }; // a stuck pause loop must unwind in seconds
        var request = client.GetAsync("https://vendor.example/api");
        await AdvanceUntilAsync(fake, request, "the held request near the clock end");
        var response = await request;
        await AssertForwardedAsync(response, transport);
    }

    [Fact]
    public void EarlyTimerTimeProvider_RejectsSubFloorDueTimes()
    {
        // The seam's own contract: a due time below the early-fire offset would shift
        // negative, where FakeTimeProvider never fires the timer — a silent hang. The
        // guard rejects it at creation; nothing legitimate produces one (1 ms floor).
        var fake = new FakeTimeProvider();
        var time = new EarlyTimerTimeProvider(fake);
        var zero = Assert.Throws<InvalidOperationException>(
            () => time.CreateTimer(_ => { }, null, TimeSpan.Zero, Timeout.InfiniteTimeSpan));
        Assert.Contains("delay below the 1 ms floor", zero.Message);
        var subFloor = Assert.Throws<InvalidOperationException>(
            () => time.CreateTimer(_ => { }, null, TimeSpan.FromTicks(100), Timeout.InfiniteTimeSpan));
        Assert.Contains("delay below the 1 ms floor", subFloor.Message);
    }

    private static ThrottleOptions PauseOnlyOptions(string maxQueueWait) =>
        new()
        {
            PermitsPerInterval = 0,
            Interval = TimeSpan.Parse("00:00:01"),
            QueueLimit = 20,
            MaxQueueWait = TimeSpan.Parse(maxQueueWait),
        };

    private static (ThrottleHandler Handler, ClusterThrottleRegistry Registry) MakeHandler(
        ThrottleOptions options,
        out CountingTransport transport,
        TimeProvider time)
    {
        transport = new CountingTransport();
        var registry = new ClusterThrottleRegistry(options, time);
        var handler = new ThrottleHandler(new TailHandler(transport), registry.GetOrCreate(Cluster), Cluster, time);
        return (handler, registry);
    }

    private static async Task AssertForwardedAsync(HttpResponseMessage response, CountingTransport transport)
    {
        if (response.StatusCode == HttpStatusCode.TooManyRequests)
        {
            Assert.Fail(
                $"the held request was answered 429 ({await ReadProblemCodeAsync(response)}) " +
                "instead of being forwarded after the pause.");
        }

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, transport.Arrivals);
    }

    private static async Task AssertRejectedAsync(HttpResponseMessage response, TimeSpan expectedRetryAfter)
    {
        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.Equal("credprox.throttled", await ReadProblemCodeAsync(response));
        Assert.Equal(expectedRetryAfter, response.Headers.RetryAfter?.Delta);
    }

    private static async Task<string> ReadProblemCodeAsync(HttpResponseMessage response)
    {
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return document.RootElement.GetProperty("extensions").GetProperty("code").GetString()!;
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

    private static async Task AdvanceUntilAsync(FakeTimeProvider time, Task request, string what)
    {
        // Bound by FAKE time advanced, not by the wall clock: a synchronous spin inside the
        // handler freezes this loop's continuation (measured ~99.98 s of starvation behind
        // 19,995 iterations), so a wall-clock deadline is never evaluated here. A hung
        // iteration is caught by the pins' 10 s HttpClient timeout instead.
        var start = time.GetUtcNow();
        var horizon = TimeSpan.FromSeconds(30);
        while (!request.IsCompleted)
        {
            Assert.True(time.GetUtcNow() - start < horizon,
                $"gave up advancing fake time past its {horizon} horizon while waiting for {what}.");
            // Sub-millisecond steps: every test's times and the early-fire offset land on this
            // grid, so an early timer is observed at the early instant, not one tick later.
            time.Advance(TimeSpan.FromMicroseconds(100));
            await Task.Yield();
        }
    }

    /// <summary>
    /// A <see cref="TimeProvider"/> whose timers fire <see cref="EarlyBy"/> before their due
    /// time while its clock reports the firing instant — a deterministic stand-in for the
    /// sub-millisecond remainder a real timer can drop. Counts every timer it creates so a
    /// busy-waiting regression (thousands of rounds) fails a pin instead of passing quietly.
    /// </summary>
    private sealed class EarlyTimerTimeProvider(FakeTimeProvider inner) : TimeProvider
    {
        private static readonly TimeSpan EarlyBy = TimeSpan.FromTicks(5000); // 0.5 ms

        // Two ways the pause loop can stop making progress, and the soft assert (<= 8)
        // below would never see either: a runaway round count, and a sub-millisecond slice
        // that the early-fire offset pushes below zero — where FakeTimeProvider never fires
        // the timer and the request dies at the HttpClient timeout (measured 1 m 40 s) in
        // silence. Fail fast for both at this seam; the soft assert stays the statement of
        // the real round bound.
        private const int TimerCap = 64;

        private int _timerCreations;

        public int TimerCreations => Volatile.Read(ref _timerCreations);

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            // A due time below the early-fire offset lands negative after the shift, where
            // FakeTimeProvider never fires it: a hang, invisible to the cap. The product's
            // 1 ms floor makes this impossible legitimately — reject it at creation.
            if (dueTime >= TimeSpan.Zero && dueTime < EarlyBy)
            {
                throw new InvalidOperationException(
                    $"busy-spin guard: delay below the 1 ms floor ({dueTime}); the pause loop lost its millisecond floor");
            }

            var creations = Interlocked.Increment(ref _timerCreations);
            if (creations > TimerCap)
            {
                throw new InvalidOperationException(
                    $"busy-spin guard: {creations} timer rounds passed the cap of {TimerCap}; the pause loop is not making progress");
            }

            var due = dueTime >= TimeSpan.Zero ? dueTime - EarlyBy : dueTime;
            return inner.CreateTimer(callback, state, due, period);
        }

        public override DateTimeOffset GetUtcNow() => inner.GetUtcNow();
    }

    /// <summary>Immediate 200s with a thread-safe arrival count (the chain's end).</summary>
    private sealed class CountingTransport : HttpMessageHandler
    {
        private int _arrivals;

        public int Arrivals => Volatile.Read(ref _arrivals);

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _arrivals);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("ok") });
        }
    }

    /// <summary>DelegatingHandler tail over a raw transport (the chain's end).</summary>
    private sealed class TailHandler(HttpMessageHandler inner) : DelegatingHandler
    {
        private readonly HttpMessageInvoker _invoker = new(inner);

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            _invoker.SendAsync(request, cancellationToken);
    }
}
