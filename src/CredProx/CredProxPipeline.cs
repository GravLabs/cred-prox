using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;

namespace CredProx;

/// <summary>
/// Orders the registered features by their declared <see cref="Stage"/>, independently of
/// the order they were registered in, and runs request features in that order
/// (see <c>docs/credprox-plan.md</c> §3.5 rule 3). Features that declare the same stage
/// keep their registration order.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class CredProxPipeline
{
    private readonly IRequestFeature[] _requestFeatures;
    private readonly IPipelineFeature[] _pipelineFeatures;
    private readonly IResponseFeature[] _responseFeatures;

    /// <summary>
    /// Creates the pipeline from the registered features. The order of the input
    /// sequences is irrelevant; the declared <see cref="Stage"/> of each feature decides.
    /// </summary>
    /// <param name="requestFeatures">The registered request features.</param>
    /// <param name="pipelineFeatures">The registered outbound pipeline features.</param>
    public CredProxPipeline(
        IEnumerable<IRequestFeature> requestFeatures,
        IEnumerable<IPipelineFeature> pipelineFeatures)
        : this(requestFeatures, pipelineFeatures, [])
    {
    }

    /// <summary>
    /// Creates the pipeline from the registered features, including the response
    /// features of M20 (plan §8.2). The order of the input sequences is irrelevant; the
    /// declared <see cref="Stage"/> of each feature decides.
    /// </summary>
    /// <param name="requestFeatures">The registered request features.</param>
    /// <param name="pipelineFeatures">The registered outbound pipeline features.</param>
    /// <param name="responseFeatures">The registered response features.</param>
    public CredProxPipeline(
        IEnumerable<IRequestFeature> requestFeatures,
        IEnumerable<IPipelineFeature> pipelineFeatures,
        IEnumerable<IResponseFeature> responseFeatures)
    {
        ArgumentNullException.ThrowIfNull(requestFeatures);
        ArgumentNullException.ThrowIfNull(pipelineFeatures);
        ArgumentNullException.ThrowIfNull(responseFeatures);

        // OrderBy is a stable sort, so features with the same stage keep registration order.
        _requestFeatures = requestFeatures.OrderBy(feature => feature.Stage).ToArray();
        _pipelineFeatures = pipelineFeatures.OrderBy(feature => feature.Stage).ToArray();
        _responseFeatures = responseFeatures.OrderBy(feature => feature.Stage).ToArray();
    }

    /// <summary>The registered request features, in stage order.</summary>
    public IReadOnlyList<IRequestFeature> RequestFeatures => _requestFeatures;

    /// <summary>The registered outbound pipeline features, in stage order.</summary>
    public IReadOnlyList<IPipelineFeature> PipelineFeatures => _pipelineFeatures;

    /// <summary>The registered response features, in stage order (M20, plan §8.2).</summary>
    public IReadOnlyList<IResponseFeature> ResponseFeatures => _responseFeatures;

    /// <summary>
    /// Runs the request features in stage order against <paramref name="context"/>.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> of the request being proxied.</param>
    /// <param name="cancellationToken">Cancels the run.</param>
    public async ValueTask ApplyRequestAsync(HttpContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        foreach (var feature in _requestFeatures)
        {
            await feature.ApplyAsync(context, cancellationToken).ConfigureAwait(false);

            // A feature that short-circuited the request (CredProxRequestState.AbortAsync)
            // stops the pipeline; later stages — credential attachment above all — must not
            // run for a request that will not be forwarded (§3.4).
            if (context.Features.Get<CredProxRequestState>()?.IsAborted == true)
            {
                break;
            }
        }
    }

    /// <summary>
    /// Runs the response features in stage order against <paramref name="context"/>
    /// (M20, plan §8.2), while the upstream response is still pre-copy: features can
    /// reshape headers and wrap the body stream before any byte reaches the caller.
    /// Unlike the request direction there is no short-circuit — the response is
    /// fail-closed: a feature failure propagates and the raw upstream bytes are never
    /// forwarded over it.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> of the request being answered.</param>
    /// <param name="cancellationToken">Cancels the run.</param>
    public async ValueTask ApplyResponseAsync(HttpContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        foreach (var feature in _responseFeatures)
        {
            await feature.ApplyAsync(context, cancellationToken).ConfigureAwait(false);
        }
    }
}
