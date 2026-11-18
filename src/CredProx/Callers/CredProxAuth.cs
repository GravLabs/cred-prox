using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// The fixed names of the CredProx caller-authentication surface.
/// </summary>
[Experimental("CREDPROX001")]
public static class CredProxAuth
{
    /// <summary>
    /// The ASP.NET Core authentication scheme of the CredProx caller API-key handler.
    /// Internal: the key layer itself lives in the CredProx.CallerKeys add-on, whose
    /// <c>CallerKeyOptions.Scheme</c> is the public name of the same constant (the
    /// analogue of <see cref="CallerTokenScheme"/>); the core keeps only the name it must
    /// match in the policy.
    /// </summary>
    internal const string CallerKeyScheme = "CredProxCallerKey";

    /// <summary>
    /// The ASP.NET Core authentication scheme of the caller-token validation (ADR-0004) —
    /// the scheme name the caller policy accepts for a caller token alongside
    /// <see cref="CallerKeyScheme"/>. Internal: the token layer itself lives in the
    /// CredProx.CallerTokens add-on, whose <c>CallerTokenOptions.Scheme</c> is the public
    /// name of the same constant; the core keeps only the name it must match in the policy.
    /// </summary>
    internal const string CallerTokenScheme = "CredProxCallerToken";

    /// <summary>
    /// The authorization policy requiring an authenticated CredProx caller, for hosts that
    /// prefer per-route <c>AuthorizationPolicy</c> over the built-in pipeline enforcement.
    /// It names both caller schemes; an unregistered scheme authenticates as no-result, so
    /// a caller key or — once registered — a caller token satisfies it.
    /// </summary>
    public const string CallerPolicy = "CredProx.Caller";
}
