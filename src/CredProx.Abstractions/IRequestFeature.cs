using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Http;

namespace CredProx.Abstractions;

/// <summary>
/// A feature that modifies the request being proxied. Maps to a YARP request transform
/// (<c>ITransformProvider</c> → <c>AddRequestTransform</c>) and is bound to a route.
/// </summary>
/// <remarks>
/// While features run, the outbound request's <c>RequestUri</c> is still <see langword="null"/>:
/// YARP assembles it only after every transform completes. The final path and query are the
/// supported read surface on <c>CredProxRequestState</c> (<c>OutboundPath</c> /
/// <c>OutboundQuery</c>); a <c>RequestUri</c> assigned during a feature survives to the wire
/// exactly as set.
/// </remarks>
[Experimental("CREDPROX001")]
public interface IRequestFeature
{
    /// <summary>
    /// The stage this feature runs in. The core orders request features by this value,
    /// independently of the order they were registered in.
    /// </summary>
    Stage Stage { get; }

    /// <summary>
    /// Applies the feature to the request being proxied.
    /// </summary>
    /// <param name="context">
    /// The <see cref="HttpContext"/> of the inbound request. The outbound request is built
    /// from it; route metadata and the caller identity are available through its features.
    /// </param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    ValueTask ApplyAsync(HttpContext context, CancellationToken cancellationToken);
}
