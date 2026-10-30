using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// The fixed names of the CredProx caller-authentication surface.
/// </summary>
[Experimental("CREDPROX001")]
public static class CredProxAuth
{
    /// <summary>
    /// The ASP.NET Core authentication scheme of the CredProx caller API-key handler
    /// (registered by <c>AddCredProxCallerAuthentication</c>). Hosts that enforce caller
    /// authentication through middleware set this scheme's authorization policy on their
    /// YARP routes; the in-pipeline enforcement works with or without it.
    /// </summary>
    public const string CallerKeyScheme = "CredProxCallerKey";

    /// <summary>
    /// The authorization policy requiring an authenticated CredProx caller, for hosts that
    /// prefer per-route <c>AuthorizationPolicy</c> over the built-in pipeline enforcement.
    /// </summary>
    public const string CallerPolicy = "CredProx.Caller";
}
