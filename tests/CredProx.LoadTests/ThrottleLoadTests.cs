using System.Net;
using CredProx;
using Xunit;

namespace CredProx.LoadTests;

/// <summary>
/// §5.2 "Throttling" under load: a burst of concurrent callers never pushes the upstream
/// past the configured rate. Real clock, real threads — the nightly layer's job is to
/// catch what the deterministic unit tests cannot: races in the limiter under contention.
/// </summary>
[Trait("Layer", "Nightly")]
public sealed class ThrottleLoadTests
{
    [Fact]
    public async Task Burst_KeepsUpstreamAtConfiguredRate()
    {
        const int Rate = 50;
        const int Burst = 200;
        var time = TimeProvider.System;
        var start = time.GetTimestamp();
        var upstream = new TimestampingHandler(start, time);

        var registry = new ClusterThrottleRegistry(
            new ThrottleOptions
            {
                PermitsPerInterval = Rate,
                Interval = TimeSpan.FromSeconds(1),
                QueueLimit = 500,
                MaxQueueWait = TimeSpan.FromSeconds(30),
            },
            time);
        using var client = new HttpClient(
            new ThrottleHandler(new TailHandler(upstream), registry.GetOrCreate("load"), "load", time));

        var responses = await Task
            .WhenAll(Enumerable.Range(0, Burst).Select(_ => client.GetAsync("https://vendor.example/api")))
            .WaitBoundedAsync("the burst to drain");

        Assert.All(responses, r => Assert.Equal(HttpStatusCode.OK, r.StatusCode));
        Assert.Equal(Burst, upstream.Arrivals);

        // The limiter's windows are aligned to its creation (≈ start): no aligned 1s
        // window may start more than Rate permits, even with 200 callers hammering.
        var offsets = upstream.SnapshotOffsetsMs();
        for (var window = 0; window * 1000.0 <= offsets.Max(); window++)
        {
            var inWindow = offsets.Count(o => o >= window * 1000.0 && o < (window + 1) * 1000.0);
            Assert.True(
                inWindow <= Rate,
                $"Window {window} let {inWindow} requests through; the rate is {Rate}/s.");
        }

        // 200 requests at 50/s need at least four windows.
        Assert.True(
            offsets.Max() >= 3000,
            $"The burst drained in {offsets.Max():F0}ms — the rate limit did not hold.");
    }

    [Fact]
    public async Task Burst_ConcurrencyCapHoldsUnderContention()
    {
        const int MaxConcurrency = 8;
        const int Burst = 100;
        var time = TimeProvider.System;
        var upstream = new HoldingHandler();

        var registry = new ClusterThrottleRegistry(
            new ThrottleOptions
            {
                MaxConcurrency = MaxConcurrency,
                QueueLimit = 200,
                MaxQueueWait = TimeSpan.FromSeconds(30),
            },
            time);
        using var client = new HttpClient(
            new ThrottleHandler(new TailHandler(upstream), registry.GetOrCreate("load"), "load", time));

        var responses = await Task
            .WhenAll(Enumerable.Range(0, Burst).Select(_ => client.GetAsync("https://vendor.example/api")))
            .WaitBoundedAsync("the burst to drain");

        Assert.All(responses, r => Assert.Equal(HttpStatusCode.OK, r.StatusCode));
        Assert.True(
            upstream.PeakInFlight <= MaxConcurrency,
            $"Observed {upstream.PeakInFlight} concurrent upstream calls; the cap is {MaxConcurrency}.");
    }

    /// <summary>Upstream that holds each request briefly and tracks the in-flight peak.</summary>
    private sealed class HoldingHandler : HttpMessageHandler
    {
        private int _inFlight;
        private int _peak;

        public int PeakInFlight => Volatile.Read(ref _peak);

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var current = Interlocked.Increment(ref _inFlight);
            int peak;
            while (current > (peak = Volatile.Read(ref _peak)))
            {
                if (Interlocked.CompareExchange(ref _peak, current, peak) == peak)
                {
                    break;
                }
            }

            await Task.Delay(20, cancellationToken).ConfigureAwait(false);
            Interlocked.Decrement(ref _inFlight);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }
}
