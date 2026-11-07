using System.Diagnostics.CodeAnalysis;

namespace CredProx.Abstractions;

/// <summary>
/// The cluster-scoped context a pipeline feature is composed for. The outbound handler
/// chain is built per cluster (<c>ForwarderHttpClientFactory.WrapHandler</c>), so a
/// feature that keeps per-cluster state — a rate limiter or a circuit breaker keyed to
/// one upstream — uses <see cref="ClusterId"/> as its state key.
/// </summary>
/// <param name="ClusterId">The YARP cluster id this handler chain belongs to.</param>
[Experimental("CREDPROX001")]
public sealed record PipelineFeatureContext(string ClusterId);
