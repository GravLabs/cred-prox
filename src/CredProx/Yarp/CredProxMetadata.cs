using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Http;
using Yarp.ReverseProxy.Model;

namespace CredProx;

/// <summary>
/// The YARP metadata keys that reference CredProx configuration by name
/// (see <c>docs/credprox-plan.md</c> §3.2): route metadata <c>CredProx.Credential</c> and
/// <c>CredProx.Destination</c>, cluster metadata <c>CredProx.Connection</c>. Metadata is
/// flat, so it only references the structured <c>CredProx</c> sections; every reference
/// must resolve at startup (§3.3).
/// </summary>
[Experimental("CREDPROX001")]
public static class CredProxMetadata
{
    /// <summary>Route metadata naming the <c>CredProx:Credentials</c> entry to attach.</summary>
    public const string Credential = "CredProx.Credential";

    /// <summary>Route metadata naming the <c>CredProx:Destinations</c> entry to resolve.</summary>
    public const string Destination = "CredProx.Destination";

    /// <summary>Cluster metadata naming the <c>CredProx:Connections</c> entry for the outbound connection.</summary>
    public const string Connection = "CredProx.Connection";

    /// <summary>
    /// Route metadata controlling caller authentication for the route. Once caller
    /// authentication is registered every proxied route requires an authenticated caller;
    /// a route opts out with the value <c>"anonymous"</c>
    /// (see <see cref="CallerAuthenticationFeature.AnonymousValue"/>).
    /// </summary>
    public const string Caller = "CredProx.Caller";

    /// <summary>
    /// Route metadata opting the route out of vendor error normalisation (M24, §8.5):
    /// with the value <c>"off"</c> (case-insensitive) the route's vendor error bodies
    /// flow to the caller byte-identical, exactly as the vendor writes them. Any other
    /// value — including a misspelling — normalises like every other route; check the
    /// spelling against <see cref="ErrorNormalisationFeature.OptOutValue"/>.
    /// </summary>
    public const string ErrorNormalisation = "CredProx.ErrorNormalisation";

    /// <summary>
    /// The route's metadata from the proxy pipeline features, or <see langword="null"/>
    /// outside a proxied request.
    /// </summary>
    /// <param name="context">The inbound request.</param>
    public static IReadOnlyDictionary<string, string>? GetRouteMetadata(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return context.Features.Get<IReverseProxyFeature>()?.Route?.Config?.Metadata;
    }

    /// <summary>
    /// The cluster's metadata from the proxy pipeline features, or <see langword="null"/>
    /// outside a proxied request.
    /// </summary>
    /// <param name="context">The inbound request.</param>
    public static IReadOnlyDictionary<string, string>? GetClusterMetadata(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return context.Features.Get<IReverseProxyFeature>()?.Cluster?.Config?.Metadata;
    }
}
