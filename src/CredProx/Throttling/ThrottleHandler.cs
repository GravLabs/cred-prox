using System.Net;
using System.Net.Http.Headers;
using System.Threading.RateLimiting;

namespace CredProx;

/// <summary>
/// Per-cluster outbound throttle as a <see cref="DelegatingHandler"/>
/// (see <c>docs/credprox-plan.md</c> §8.4, §5.2 "Throttling", §3.4): a queued request
/// waits for a permit up to <c>MaxQueueWait</c>; a full queue or an exceeded wait gets
/// <c>429</c> with <c>Retry-After</c> and the <c>credprox.throttled</c> problem code.
/// A vendor <c>429</c> carrying <c>Retry-After</c> pauses the whole cluster for that
/// duration (capped at <c>MaxPause</c>); the vendor's own 429 still passes through to
/// its caller untouched.
/// </summary>
/// <remarks>
/// The permit is held until the upstream response headers arrive — streaming the response
/// body does not hold a permit. The handler sits outside the resilience adapter, so one
/// permit covers every retry attempt of one caller request.
/// </remarks>
internal sealed class ThrottleHandler(
    DelegatingHandler inner,
    ClusterThrottleState state,
    string clusterId,
    TimeProvider time) : DelegatingHandler(inner)
{
    private readonly ClusterThrottleRegistry.Effective _effective = state.Effective;
    private readonly KeyValuePair<string, object?> _clusterTag = new("credprox.cluster", clusterId);

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        // 1. Vendor pause: wait it out within the queue-wait bound, else reject.
        var remaining = state.PauseRemaining(time);
        if (remaining > TimeSpan.Zero)
        {
            if (remaining > _effective.MaxQueueWait)
            {
                return Rejected(remaining);
            }

            await Task.Delay(remaining, time, cancellationToken).ConfigureAwait(false);
            remaining = state.PauseRemaining(time);
            if (remaining > TimeSpan.Zero)
            {
                return Rejected(remaining);
            }
        }

        // 2. Permit: the limiters' own queues are count-bounded; the wait is time-bounded
        //    here so "queue full or wait exceeded" both answer 429 (§3.4).
        RateLimitLease? lease = null;
        if (state.Limiter is { } limiter)
        {
            using var timeout = new CancellationTokenSource(_effective.MaxQueueWait, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token);
            try
            {
                lease = await limiter.AcquireAsync(1, linked.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return Rejected(_effective.MaxQueueWait);
            }
        }

        try
        {
            if (lease is not null && !lease.IsAcquired)
            {
                var retryAfter = lease.TryGetMetadata(MetadataName.RetryAfter, out TimeSpan advertised)
                    ? advertised
                    : TimeSpan.FromSeconds(1);
                return Rejected(retryAfter);
            }

            var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

            // 3. Vendor throttle: pause the cluster for the advertised duration.
            if (_effective.PauseOnVendorThrottle && response.StatusCode == HttpStatusCode.TooManyRequests)
            {
                var pause = ParseRetryAfter(response.Headers.RetryAfter, time);
                if (pause is { } duration && duration > TimeSpan.Zero)
                {
                    if (duration > _effective.MaxPause)
                    {
                        duration = _effective.MaxPause;
                    }

                    state.PauseUntil(time.GetUtcNow() + duration);
                    CredProxDiagnostics.ThrottlePauses.Add(1, _clusterTag);
                }
            }

            return response;
        }
        finally
        {
            lease?.Dispose();
        }
    }

    private HttpResponseMessage Rejected(TimeSpan retryAfter)
    {
        CredProxDiagnostics.ThrottleRejections.Add(1, _clusterTag);

        var seconds = (long)Math.Ceiling(retryAfter.TotalSeconds);
        if (seconds < 1)
        {
            seconds = 1;
        }

        var response = CredProxProblemResponses.CreateResponse(
            429,
            "credprox.throttled",
            "The outbound call to this destination is throttled. Try again later.");
        response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromSeconds(seconds));
        return response;
    }

    private static TimeSpan? ParseRetryAfter(RetryConditionHeaderValue? value, TimeProvider time)
    {
        if (value is null)
        {
            return null;
        }

        if (value.Delta is { } delta)
        {
            return delta;
        }

        if (value.Date is { } date)
        {
            var until = date - time.GetUtcNow();
            return until > TimeSpan.Zero ? until : TimeSpan.Zero;
        }

        return null;
    }
}
