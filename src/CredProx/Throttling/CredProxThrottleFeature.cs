using CredProx.Abstractions;

namespace CredProx;

/// <summary>
/// The built-in outbound throttling pipeline feature (§8.4): composes a
/// <see cref="ThrottleHandler"/> per cluster over the cluster's per-cluster limiter state.
/// Registered by <c>AddCredProxThrottling</c>; inert otherwise.
/// </summary>
internal sealed class CredProxThrottleFeature(
    ClusterThrottleRegistry registry,
    TimeProvider time) : IPipelineFeature
{
    /// <inheritdoc />
    public Stage Stage => Stage.Pipeline;

    /// <inheritdoc />
    /// <remarks>Outermost of the built-in pipeline features: one permit covers retries.</remarks>
    public int Order => 10;

    /// <inheritdoc />
    public DelegatingHandler CreateHandler(DelegatingHandler innerHandler) =>
        throw new InvalidOperationException(
            "Throttling is cluster-scoped; the core composes it through the PipelineFeatureContext overload.");

    /// <inheritdoc />
    public DelegatingHandler CreateHandler(DelegatingHandler innerHandler, PipelineFeatureContext context) =>
        new ThrottleHandler(innerHandler, registry.GetOrCreate(context.ClusterId), context.ClusterId, time);
}
