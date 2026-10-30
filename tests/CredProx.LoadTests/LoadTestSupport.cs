using System.Net;

namespace CredProx.LoadTests;

/// <summary>
/// Shared plumbing for the nightly load layer (plan §5.1 "Load"): real clocks, real
/// concurrency, thread-safe counters. Deviation from the plan's "NBomber or k6": the
/// three §5.2 assertions are behavioral invariants under concurrency (rate held, breaker
/// opens/closes, single-flight kept), not throughput numbers — plain xUnit load
/// generators keep the nightly layer in one test stack with no extra tooling.
/// </summary>
internal static class LoadTestSupport
{
    /// <summary>Fail with a clear message if the task does not finish within the bound.</summary>
    public static async Task<T> WaitBoundedAsync<T>(this Task<T> task, string what, TimeSpan? bound = null)
    {
        var finished = await Task.WhenAny(task, Task.Delay(bound ?? TimeSpan.FromSeconds(60))).ConfigureAwait(false);
        if (!ReferenceEquals(finished, task))
        {
            throw new TimeoutException($"Timed out waiting for {what}.");
        }

        return await task.ConfigureAwait(false);
    }
}

/// <summary>DelegatingHandler tail over a raw transport (the chain's end).</summary>
internal sealed class TailHandler(HttpMessageHandler inner) : DelegatingHandler
{
    private readonly HttpMessageInvoker _invoker = new(inner);

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken) =>
        _invoker.SendAsync(request, cancellationToken);
}

/// <summary>
/// Thread-safe upstream: records each arrival's offset (ms) from a shared start stamp
/// and answers 200.
/// </summary>
internal sealed class TimestampingHandler(long startTimestamp, TimeProvider time) : HttpMessageHandler
{
    private readonly List<double> _arrivalOffsetsMs = [];
    private readonly object _gate = new();

    public int Arrivals
    {
        get
        {
            lock (_gate)
            {
                return _arrivalOffsetsMs.Count;
            }
        }
    }

    public double[] SnapshotOffsetsMs()
    {
        lock (_gate)
        {
            return [.. _arrivalOffsetsMs];
        }
    }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var offset = time.GetElapsedTime(startTimestamp).TotalMilliseconds;
        lock (_gate)
        {
            _arrivalOffsetsMs.Add(offset);
        }

        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
    }
}

/// <summary>Thread-safe upstream that fails (500) until switched healthy.</summary>
internal sealed class SwitchableUpstreamHandler(bool healthy = false) : HttpMessageHandler
{
    private int _arrivals;

    public bool Healthy { get; set; } = healthy;

    public int Arrivals => Volatile.Read(ref _arrivals);

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _arrivals);
        var status = Healthy ? HttpStatusCode.OK : HttpStatusCode.InternalServerError;
        return Task.FromResult(new HttpResponseMessage(status));
    }
}
