using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Http;

namespace CredProx.Abstractions;

/// <summary>
/// A feature that inspects or modifies the upstream response before the caller sees
/// any of it.
/// </summary>
/// <remarks>
/// <para>
/// The core runs response features in <see cref="Stage"/> order (defaulting to
/// <see cref="Stage.ShapeResponse"/>, M20) at the end of the outbound pipeline: after
/// the upstream response has arrived (and any refresh-on-401 retry has settled on one
/// response) and before the proxy has copied a single header or body byte to the
/// caller. The upstream response — headers and body stream both — is reachable through
/// the request state feature (<c>CredProxRequestState.ProxyResponse</c>); a feature
/// that replaces or wraps the body stream takes ownership of it.
/// </para>
/// <para>
/// A failing response feature ends the response (fail-closed): the raw upstream bytes
/// are never forwarded over a feature's failure.
/// </para>
/// </remarks>
[Experimental("CREDPROX001")]
public interface IResponseFeature
{
    /// <summary>
    /// The stage this feature runs in. The core orders response features by this value,
    /// independently of the order they were registered in; <see cref="Stage.ShapeResponse"/>
    /// suits anything that shapes the caller-visible response.
    /// </summary>
    Stage Stage => Stage.ShapeResponse;

    /// <summary>
    /// Applies the feature to the response received from upstream.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> whose response is being written.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    ValueTask ApplyAsync(HttpContext context, CancellationToken cancellationToken);
}
