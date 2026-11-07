using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.Http.Resilience;
using Polly;
using Polly.CircuitBreaker;
using Polly.Timeout;

namespace CredProx;

/// <summary>
/// Per-cluster resilience state, keyed by YARP cluster id: one circuit breaker per
/// cluster, shared by a with-retry and a without-retry pipeline (an open circuit must
/// stop all traffic to the cluster, not just retryable methods). Singleton: the breaker
/// state survives cluster-client recreation. Options are bound once at startup; changing
/// them takes a restart.
/// </summary>
internal sealed class ClusterResilienceRegistry(ResilienceOptions options)
{
    private readonly ConcurrentDictionary<string, ClusterResilienceState> _states = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>The effective, merged resilience settings for one cluster.</summary>
    internal sealed record Effective(
        TimeSpan AttemptTimeout,
        int MaxRetries,
        TimeSpan RetryBaseDelay,
        bool RetryNonIdempotent,
        long MaxRetriedBodyBytes,
        double FailureRatio,
        int MinimumThroughput,
        TimeSpan SamplingDuration,
        TimeSpan BreakDuration);

    /// <summary>Gets or creates the cluster's pipelines.</summary>
    public ClusterResilienceState GetOrCreate(string clusterId) =>
        _states.GetOrAdd(clusterId, static (id, reg) => reg.CreateState(id), this);

    /// <summary>Merges the defaults with the cluster's overrides.</summary>
    internal Effective GetEffective(string clusterId)
    {
        var c = options.Clusters.TryGetValue(clusterId, out var o) ? o : null;
        return new Effective(
            c?.AttemptTimeout ?? options.AttemptTimeout,
            c?.MaxRetries ?? options.MaxRetries,
            c?.RetryBaseDelay ?? options.RetryBaseDelay,
            c?.RetryNonIdempotent ?? options.RetryNonIdempotent,
            c?.MaxRetriedBodyBytes ?? options.MaxRetriedBodyBytes,
            c?.FailureRatio ?? options.FailureRatio,
            c?.MinimumThroughput ?? options.MinimumThroughput,
            c?.SamplingDuration ?? options.SamplingDuration,
            c?.BreakDuration ?? options.BreakDuration);
    }

    private ClusterResilienceState CreateState(string clusterId)
    {
        var effective = GetEffective(clusterId);
        var clusterTag = new KeyValuePair<string, object?>("credprox.cluster", clusterId);

        // Innermost: the shared breaker. It sees raw attempt outcomes; a rejection
        // (BrokenCircuitException) is not transient, so retries never hammer an open
        // circuit and the handler answers 503 credprox.upstream_unavailable.
        var breaker = new ResiliencePipelineBuilder<HttpResponseMessage>()
            .AddCircuitBreaker(new HttpCircuitBreakerStrategyOptions
            {
                FailureRatio = effective.FailureRatio,
                MinimumThroughput = effective.MinimumThroughput,
                SamplingDuration = effective.SamplingDuration,
                BreakDuration = effective.BreakDuration,
                ShouldHandle = args =>
                    new ValueTask<bool>(IsTransient(args.Outcome, args.Context.CancellationToken)),
                OnOpened = _ =>
                {
                    CredProxDiagnostics.CircuitOpened.Add(1, clusterTag);
                    return default;
                },
            })
            .Build();

        var plainPipeline = new ResiliencePipelineBuilder<HttpResponseMessage>()
            .AddTimeout(new HttpTimeoutStrategyOptions { Timeout = effective.AttemptTimeout })
            .AddPipeline(breaker)
            .Build();

        // Retry (outermost) → per-attempt timeout → breaker. A timeout gets a fresh
        // attempt budget on each retry; exhausted timeouts surface as 504. MaxRetries=0
        // means "no retries": Polly rejects AddRetry with zero attempts, so the retry
        // pipeline is simply the plain one.
        var retryPipeline = effective.MaxRetries == 0
            ? plainPipeline
            : new ResiliencePipelineBuilder<HttpResponseMessage>()
                .AddRetry(new HttpRetryStrategyOptions
                {
                    MaxRetryAttempts = effective.MaxRetries,
                    Delay = effective.RetryBaseDelay,
                    BackoffType = DelayBackoffType.Exponential,
                    UseJitter = true,
                    ShouldHandle = args =>
                        new ValueTask<bool>(IsTransient(args.Outcome, args.Context.CancellationToken)),
                    OnRetry = _ =>
                    {
                        CredProxDiagnostics.ResilienceRetries.Add(1, clusterTag);
                        return default;
                    },
                })
                .AddTimeout(new HttpTimeoutStrategyOptions { Timeout = effective.AttemptTimeout })
                .AddPipeline(breaker)
                .Build();

        return new ClusterResilienceState(retryPipeline, plainPipeline, effective);
    }

    /// <summary>
    /// Transient for retry and breaker accounting: transport failures, attempt timeouts
    /// and 408/5xx. Caller cancellation is never transient. Vendor 429 is deliberately
    /// excluded — the throttle's cluster pause owns it; retrying it would hammer a vendor
    /// that just asked to be slowed down.
    /// </summary>
    internal static bool IsTransient(Outcome<HttpResponseMessage> outcome, CancellationToken cancellationToken) =>
        outcome.Exception switch
        {
            HttpRequestException => true,
            TimeoutRejectedException => true,
            OperationCanceledException when !cancellationToken.IsCancellationRequested => true,
            null => outcome.Result is { } response && IsTransientStatus(response.StatusCode),
            _ => false,
        };

    private static bool IsTransientStatus(HttpStatusCode status) =>
        status is HttpStatusCode.RequestTimeout
            or HttpStatusCode.InternalServerError
            or HttpStatusCode.BadGateway
            or HttpStatusCode.ServiceUnavailable
            or HttpStatusCode.GatewayTimeout;
}

/// <summary>One cluster's resilience pipelines and effective settings.</summary>
internal sealed class ClusterResilienceState(
    ResiliencePipeline<HttpResponseMessage> retryPipeline,
    ResiliencePipeline<HttpResponseMessage> plainPipeline,
    ClusterResilienceRegistry.Effective effective)
{
    /// <summary>Pipeline with retry (idempotent methods, or all when enabled).</summary>
    public ResiliencePipeline<HttpResponseMessage> RetryPipeline { get; } = retryPipeline;

    /// <summary>Pipeline without retry: timeout and breaker only.</summary>
    public ResiliencePipeline<HttpResponseMessage> PlainPipeline { get; } = plainPipeline;

    /// <summary>The cluster's effective settings.</summary>
    public ClusterResilienceRegistry.Effective Effective { get; } = effective;
}
