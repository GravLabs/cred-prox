using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Yarp.ReverseProxy.Transforms;
using Yarp.ReverseProxy.Transforms.Builder;

namespace CredProx;

/// <summary>
/// The single YARP transform adapter for the CredProx request pipeline
/// (see <c>docs/credprox-plan.md</c> §3.1: <see cref="Abstractions.IRequestFeature"/>
/// "maps to a YARP request transform"). One transform is added per route: it publishes
/// the <see cref="CredProxRequestState"/>, runs the stage-ordered pipeline against it,
/// and — unless a feature short-circuited — applies the resolved destination override.
/// </summary>
/// <remarks>
/// Short-circuiting relies on YARP's documented behavior that a transform which sets the
/// response makes the forwarder skip the proxy call (the plan §3.4 flagged this for a
/// test; the M4 integration tests assert it against YARP 2.3: no forward, no token call).
/// The response direction is deliberately not a YARP response transform: by the time
/// those run, YARP has already copied the upstream headers to the caller. The state this
/// transform publishes travels on the outbound message so the response dispatcher in
/// <see cref="CredProxForwarderHttpClientFactory"/> runs the features pre-copy (M20, §8.2).
/// </remarks>
[Experimental("CREDPROX001")]
public sealed class CredProxTransformProvider : ITransformProvider
{
    private readonly CredProxPipeline _pipeline;
    private readonly ILogger<CredProxTransformProvider> _logger;
    private readonly CredProxAuditRecorder _audit;

    /// <summary>Creates the provider over the stage-ordered pipeline.</summary>
    /// <param name="pipeline">The registered request pipeline.</param>
    /// <param name="logger">Logs unexpected feature failures.</param>
    /// <param name="audit">
    /// The audit recorder; started before the pipeline so every processed request —
    /// including one a feature short-circuits — gets its record (M7, §4 "Audit log").
    /// </param>
    public CredProxTransformProvider(
        CredProxPipeline pipeline,
        ILogger<CredProxTransformProvider> logger,
        CredProxAuditRecorder audit)
    {
        _pipeline = pipeline ?? throw new ArgumentNullException(nameof(pipeline));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
    }

    /// <inheritdoc />
    public void ValidateRoute(Yarp.ReverseProxy.Transforms.Builder.TransformRouteValidationContext context)
    {
        // Route-level validation is the startup validator's job (registry cross-checks);
        // the transform itself adds nothing route-shape-specific.
    }

    /// <inheritdoc />
    public void ValidateCluster(Yarp.ReverseProxy.Transforms.Builder.TransformClusterValidationContext context)
    {
        // As above, for clusters.
    }

    /// <inheritdoc />
    public void Apply(TransformBuilderContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        context.AddRequestTransform(async transformContext =>
        {
            var httpContext = transformContext.HttpContext;
            var state = new CredProxRequestState(httpContext, transformContext.ProxyRequest);
            httpContext.Features.Set(state);

            // The response direction runs at the end of the outbound pipeline (M20,
            // §8.2): carry the state on the outbound message (the same channel as the
            // refresh targets) so the dispatcher there reaches this request's features.
            transformContext.ProxyRequest.Options.Set(CredProxRequestOptions.RequestState, state);

            // Route-level transforms (path rewrites, query transforms) have already run —
            // global providers are appended after them — but YARP assembles RequestUri only
            // after every transform completes. Carry the final path/query on the state so
            // the Sign stage signs the request as the vendor will receive it (§5.2: the
            // signing stage sees the final request).
            state.OutboundPath = transformContext.Path.HasValue ? transformContext.Path.Value : "/";
            state.OutboundQuery = transformContext.Query.QueryString.HasValue
                ? transformContext.Query.QueryString.Value
                : null;
            _audit.Begin(httpContext);

            try
            {
                await _pipeline.ApplyRequestAsync(httpContext, transformContext.CancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex) when (!state.IsAborted)
            {
                // A feature failed unexpectedly; the caller gets a static problem
                // response, the detail goes to the log (messages are value-free by
                // construction, and this is the last net).
                _logger.LogError(ex, "The CredProx request pipeline failed for this request.");
                await state
                    .AbortAsync(StatusCodes.Status500InternalServerError, "credprox.internal_error",
                        "The proxy failed to process the request.")
                    .ConfigureAwait(false);
            }

            if (state.IsAborted)
            {
                return; // response set: the forwarder skips the proxy call
            }

            if (state.DestinationPrefix is { } prefix)
            {
                transformContext.DestinationPrefix = prefix;
            }
        });
    }
}
