using System.Net.Http;
using Microsoft.Extensions.Logging;

namespace CredProx;

/// <summary>
/// Runs the stage-ordered response features (M20, plan §8.2) on the upstream response at
/// the end of the outbound pipeline: after refresh-on-401 has settled on one response,
/// and before YARP has received — let alone copied — anything. That position is what the
/// contract promises: a response feature reshapes the response <em>before the caller
/// sees any of it</em>. (A YARP response transform cannot make that promise: by the time
/// transforms run, YARP has already copied the upstream headers to the caller's
/// response, so changes to <c>ProxyResponse</c> there are invisible.)
/// </summary>
/// <remarks>
/// Requests with no CredProx state (routes the pipeline never processed) pass through
/// untouched. A failing feature is fail-closed: the exception propagates, the response
/// never reaches the caller, and no partially-scrubbed bytes flow over it.
/// </remarks>
internal sealed class ResponseDispatchHandler : DelegatingHandler
{
    private readonly CredProxPipeline _pipeline;
    private readonly ILogger<ResponseDispatchHandler> _logger;

    public ResponseDispatchHandler(
        HttpMessageHandler innerHandler,
        CredProxPipeline pipeline,
        ILogger<ResponseDispatchHandler> logger)
    {
        InnerHandler = innerHandler ?? throw new ArgumentNullException(nameof(innerHandler));
        _pipeline = pipeline ?? throw new ArgumentNullException(nameof(pipeline));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

        if (!request.Options.TryGetValue(CredProxRequestOptions.RequestState, out var state)
            || state is null)
        {
            return response;
        }

        state.ProxyResponse = response;

        try
        {
            await _pipeline.ApplyResponseAsync(state.HttpContext, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // The settled response is discarded either way — dispose it so the
            // connection goes back now, not at finalization (the refresh handler
            // disposes its discarded responses for the same reason).
            response.Dispose();
            throw;
        }
        catch (Exception ex)
        {
            response.Dispose();
            // Fail-closed: throwing here means YARP never starts the copy; the caller
            // gets the proxy error, never the raw upstream bytes. The detail goes to
            // the log (messages are value-free by construction, §3.5).
            _logger.LogError(ex, "The CredProx response pipeline failed for this request.");
            throw;
        }

        return response;
    }
}
