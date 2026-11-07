using Polly;
using Polly.CircuitBreaker;
using Polly.Timeout;

namespace CredProx;

/// <summary>
/// Per-cluster resilience as a <see cref="DelegatingHandler"/>
/// (see <c>docs/credprox-plan.md</c> §8.4, §5.2 "Resilience"): retry for idempotent
/// methods only (POST never retried unless <c>RetryNonIdempotent</c> is enabled and the
/// body is buffered within the cap), a per-attempt timeout, and the cluster's circuit
/// breaker. An open circuit answers <c>503</c> (<c>credprox.upstream_unavailable</c>)
/// without reaching the upstream; exhausted attempt timeouts answer <c>504</c>
/// (<c>credprox.upstream_timeout</c>).
/// </summary>
/// <remarks>
/// A sent <see cref="HttpRequestMessage"/> cannot be resent, so each retry attempt sends
/// a clone (<see cref="ProxyRequestCloner"/>); the body is buffered once, before the
/// first attempt, only when it is re-sendable (known length within the cap). A streamed
/// or over-cap body is never buffered and its request is never retried — the same rule
/// as refresh-on-401.
/// </remarks>
internal sealed class CredProxResilienceHandler(
    DelegatingHandler inner,
    ClusterResilienceState state) : DelegatingHandler(inner)
{
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var effective = state.Effective;
        var retryable = effective.RetryNonIdempotent || IsIdempotent(request.Method);

        // Buffer the body once, only for the retry path and only when re-sendable.
        byte[]? body = null;
        if (retryable && request.Content is { } content)
        {
            if (content.Headers.ContentLength is { } length && length <= effective.MaxRetriedBodyBytes)
            {
                body = await content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
                if (body.LongLength > effective.MaxRetriedBodyBytes)
                {
                    // The declared length lied: too big to retry, and it is not resent.
                    retryable = false;
                    body = null;
                }
            }
            else
            {
                retryable = false; // streamed or over-cap: never buffer, never retry
            }
        }

        var pipeline = retryable ? state.RetryPipeline : state.PlainPipeline;
        var attempt = 0;

        try
        {
            return await pipeline.ExecuteAsync(
                async token =>
                {
                    var message = attempt++ == 0
                        ? request
                        : ProxyRequestCloner.Clone(request, body);
                    return await SendInnerAsync(message, token).ConfigureAwait(false);
                },
                cancellationToken).ConfigureAwait(false);
        }
        catch (BrokenCircuitException)
        {
            return CredProxProblemResponses.CreateResponse(
                503,
                "credprox.upstream_unavailable",
                "The circuit breaker for this upstream is open. Try again later.");
        }
        catch (TimeoutRejectedException)
        {
            return CredProxProblemResponses.CreateResponse(
                504,
                "credprox.upstream_timeout",
                "The upstream did not respond within the attempt timeout.");
        }
    }

    // base.SendAsync is not reachable from inside a lambda; this hop is.
    private Task<HttpResponseMessage> SendInnerAsync(HttpRequestMessage message, CancellationToken token) =>
        base.SendAsync(message, token);

    /// <summary>
    /// RFC-idempotent methods: GET/HEAD/OPTIONS/TRACE (the refresh-on-401 set) plus
    /// PUT/DELETE, whose repetition the vendor is required to absorb.
    /// </summary>
    private static bool IsIdempotent(HttpMethod method) =>
        HttpMethod.Get.Equals(method)
        || HttpMethod.Head.Equals(method)
        || HttpMethod.Options.Equals(method)
        || HttpMethod.Trace.Equals(method)
        || HttpMethod.Put.Equals(method)
        || HttpMethod.Delete.Equals(method);
}
