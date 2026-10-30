using System.Diagnostics.CodeAnalysis;
using System.Net.Http;

namespace CredProx.Abstractions;

/// <summary>
/// A feature that wraps the outbound request pipeline of a cluster as a
/// <see cref="DelegatingHandler"/>. Applied in
/// <c>ForwarderHttpClientFactory.WrapHandler</c>, in stage order
/// (for example throttling, resilience or audit).
/// </summary>
[Experimental("CREDPROX001")]
public interface IPipelineFeature
{
    /// <summary>
    /// The stage this feature runs in; pipeline features normally declare
    /// <see cref="Abstractions.Stage.Pipeline"/>. The core composes the handlers in
    /// stage order, independently of registration order.
    /// </summary>
    Stage Stage { get; }

    /// <summary>
    /// Orders features that share a <see cref="Stage"/>: lower runs innermost (closer to
    /// the transport), higher runs outermost. The built-ins use 0 for resilience and 10
    /// for throttling so the throttle permit covers every resilience retry regardless of
    /// registration order. Default 0.
    /// </summary>
    int Order => 0;

    /// <summary>
    /// Creates a handler that wraps <paramref name="innerHandler"/>.
    /// </summary>
    /// <param name="innerHandler">The next handler toward the upstream connection.</param>
    DelegatingHandler CreateHandler(DelegatingHandler innerHandler);

    /// <summary>
    /// Creates a handler that wraps <paramref name="innerHandler"/> for one cluster.
    /// The core calls this overload; the default delegates to
    /// <see cref="CreateHandler(DelegatingHandler)"/>, so features with no per-cluster
    /// state need not implement it.
    /// </summary>
    /// <param name="innerHandler">The next handler toward the upstream connection.</param>
    /// <param name="context">The cluster this handler chain is built for.</param>
    DelegatingHandler CreateHandler(DelegatingHandler innerHandler, PipelineFeatureContext context) =>
        CreateHandler(innerHandler);
}
