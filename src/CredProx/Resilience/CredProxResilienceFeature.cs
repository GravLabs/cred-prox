using CredProx.Abstractions;

namespace CredProx;

/// <summary>
/// The built-in resilience pipeline feature (§8.4): composes a
/// <see cref="CredProxResilienceHandler"/> per cluster over the cluster's shared
/// circuit-breaker pipelines. Registered by <c>AddCredProxResilience</c>; inert otherwise.
/// </summary>
internal sealed class CredProxResilienceFeature(ClusterResilienceRegistry registry) : IPipelineFeature
{
    /// <inheritdoc />
    public Stage Stage => Stage.Pipeline;

    /// <inheritdoc />
    /// <remarks>Innermost built-in: its retries run inside one throttle permit.</remarks>
    public int Order => 0;

    /// <inheritdoc />
    public DelegatingHandler CreateHandler(DelegatingHandler innerHandler) =>
        throw new InvalidOperationException(
            "Resilience is cluster-scoped; the core composes it through the PipelineFeatureContext overload.");

    /// <inheritdoc />
    public DelegatingHandler CreateHandler(DelegatingHandler innerHandler, PipelineFeatureContext context) =>
        new CredProxResilienceHandler(innerHandler, registry.GetOrCreate(context.ClusterId));
}
