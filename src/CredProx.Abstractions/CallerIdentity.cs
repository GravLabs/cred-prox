using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;

namespace CredProx.Abstractions;

/// <summary>
/// The authenticated caller of a proxied request (see <c>docs/credprox-plan.md</c> §4
/// Phase B): who presented a valid inbound API key, and which of that caller's keys did
/// it (callers keep multiple active keys for rotation). Carries no key material.
/// </summary>
/// <param name="CallerId">The configured caller identifier.</param>
/// <param name="KeyId">The identifier of the key that authenticated.</param>
[Experimental("CREDPROX001")]
public sealed record CallerIdentity(string CallerId, string KeyId)
{
    /// <summary>The claim carrying the caller id on an authenticated principal.</summary>
    public const string CallerClaimType = "credprox.caller";

    /// <summary>The claim carrying the authenticating key id on an authenticated principal.</summary>
    public const string KeyIdClaimType = "credprox.keyid";

    /// <summary>
    /// Reads the caller identity from an authenticated principal, or <see langword="null"/>
    /// when the principal carries no CredProx caller claim.
    /// </summary>
    /// <param name="principal">The principal to read.</param>
    public static CallerIdentity? FromPrincipal(ClaimsPrincipal? principal)
    {
        var caller = principal?.FindFirst(CallerClaimType)?.Value;
        if (string.IsNullOrEmpty(caller))
        {
            return null;
        }

        return new CallerIdentity(caller, principal!.FindFirst(KeyIdClaimType)?.Value ?? string.Empty);
    }
}
