using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// The RFC 6265 cookie-name rule shared by cookie credential placement: a
/// placement named outside the token characters fails at startup rather than at the first
/// request. Credential add-ons that offer cookie placement validate against this same
/// rule, so the validator and the attacher never drift apart.
/// </summary>
[Experimental("CREDPROX001")]
public static class CredProxCookieNames
{
    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is a valid RFC 6265
    /// cookie name.
    /// </summary>
    /// <param name="name">The candidate cookie name.</param>
    /// <returns>Whether the name may be used for cookie placement.</returns>
    public static bool IsValid(string name) => CredentialAttacher.IsValidCookieName(name);
}
