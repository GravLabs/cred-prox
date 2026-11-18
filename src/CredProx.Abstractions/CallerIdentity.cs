using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;

namespace CredProx.Abstractions;

/// <summary>
/// The authenticated caller of a proxied request: who presented a valid inbound API key,
/// and which of that caller's keys did
/// it (callers keep multiple active keys for rotation). Carries no key material.
/// </summary>
/// <param name="CallerId">The configured caller identifier.</param>
/// <param name="KeyId">The identifier of the key that authenticated.</param>
/// <param name="ClientId">For a caller token (ADR-0004), the application (client)
/// id the token was issued to — the <c>azp</c>/<c>appid</c> the mapper matched;
/// <see langword="null"/> on the caller-key path. Part of record equality.</param>
[Experimental("CREDPROX001")]
public sealed record CallerIdentity(string CallerId, string KeyId, string? ClientId = null)
{
    /// <summary>The claim carrying the caller id on an authenticated principal.</summary>
    public const string CallerClaimType = "credprox.caller";

    /// <summary>The claim carrying the authenticating key id on an authenticated principal.</summary>
    public const string KeyIdClaimType = "credprox.keyid";

    /// <summary>
    /// The claim carrying the application (client) id of an authenticating caller token;
    /// absent on the caller-key path.
    /// </summary>
    public const string ClientIdClaimType = "credprox.clientid";

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

        return new CallerIdentity(
            caller,
            principal!.FindFirst(KeyIdClaimType)?.Value ?? string.Empty,
            principal.FindFirst(ClientIdClaimType)?.Value);
    }
}
