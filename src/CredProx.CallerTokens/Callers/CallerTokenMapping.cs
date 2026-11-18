using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using CredProx.Abstractions;

namespace CredProx;

/// <summary>
/// The validated-principal-to-caller mapping layer of caller-token authentication
/// (ADR-0004): after the stock JWT bearer handler has checked signature, issuer,
/// audience and expiry, this decides <em>which configured caller</em> a token
/// belongs to — or none. Swapping the scheme for another handler (multi-tenant
/// Entra, introspection) changes nothing above this interface; swapping this
/// mapping (a different claim layout, a different caller directory) changes
/// nothing below validation.
/// </summary>
[Experimental("CREDPROX001")]
public interface ICallerTokenMapper
{
    /// <summary>
    /// Maps an authenticated token principal to a caller, or returns
    /// <see langword="null"/> when the token names no configured caller. A
    /// <see langword="null"/> result is a failed caller authentication (401) even
    /// for a cryptographically valid token — validity is not authorization.
    /// </summary>
    /// <param name="principal">The principal produced by the caller-token scheme.</param>
    CallerTokenMapping? MapToken(ClaimsPrincipal principal);
}

/// <summary>
/// What a mapped caller token grants: the caller identity to publish (its key id
/// names the token id, never token material) and the scopes the token carries.
/// Scopes only ever <em>narrow</em> what the caller may do — they never widen its
/// operation rules, and on the caller-token path an empty set admits nothing: a
/// token gets exactly the operations its roles name (ADR-0004).
/// </summary>
/// <param name="Identity">The caller identity the token authenticates.</param>
/// <param name="Scopes">The token's scopes; never <see langword="null"/>, empty when the token carries none.</param>
[Experimental("CREDPROX001")]
public sealed record CallerTokenMapping(CallerIdentity Identity, IReadOnlySet<string> Scopes);
