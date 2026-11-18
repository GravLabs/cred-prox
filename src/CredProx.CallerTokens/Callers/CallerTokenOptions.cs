using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Authentication;

namespace CredProx;

/// <summary>
/// Options for caller-token authentication (ADR-0004), bound from <c>CredProx:CallerToken</c>.
/// Validation itself is the stock JWT bearer handler — these are the CredProx-side knobs:
/// what to validate against, how old a token may be, and which claims carry the client id
/// and the scopes.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class CallerTokenOptions : AuthenticationSchemeOptions
{
    /// <summary>
    /// The ASP.NET Core authentication scheme of the caller-token validation — the stock
    /// JWT bearer handler configured by <c>AddCredProxCallerTokenAuthentication</c>
    /// (ADR-0004). The core caller policy accepts this scheme alongside the caller
    /// API-key scheme.
    /// </summary>
    public const string Scheme = "CredProxCallerToken";

    /// <summary>
    /// The OIDC authority that issues caller tokens — for Entra,
    /// <c>https://login.microsoftonline.com/&lt;tenant-id&gt;/v2.0</c>. Required: its
    /// published metadata and JWKS are what validate signatures and issuer.
    /// </summary>
    public string? Authority { get; set; }

    /// <summary>
    /// The audience a caller token must carry — the CredProx API's app ID URI or client id.
    /// Required: without it a token minted for any API in the tenant would pass.
    /// </summary>
    public string? Audience { get; set; }

    /// <summary>
    /// Whether the authority's OIDC metadata must be fetched over https — <c>true</c> by
    /// default, the real-world setting: Entra and every production issuer publish over https,
    /// and a caller token path that accepts http metadata accepts a forged key set. Set it to
    /// <c>false</c> only in an offline environment whose local issuer stub serves plain-http
    /// metadata (see a sample's <c>appsettings.Development.json</c>) — and that is enforced,
    /// not advised: <c>false</c> with any Authority that is not http on a loopback host
    /// (localhost, 127.0.0.1, ::1) refuses startup naming both keys, so a copied dev setting
    /// cannot quietly disable https metadata in production. It reaches the stock handler
    /// only: with the <c>registerScheme</c> swap the host's handler owns transport
    /// trust the same way it owns Authority and Audience.
    /// </summary>
    public bool RequireHttpsMetadata { get; set; } = true;

    /// <summary>
    /// Optional maximum token age, measured from <c>iat</c>. Rejects a token the issuer
    /// still considers valid but the operator considers stale — a window shorter than
    /// Entra's own lifetime policies. Write it as <c>d.HH:mm:ss</c>; a bare number is read
    /// as days, so 15 minutes is <c>00:15:00</c> and <c>15</c> is fifteen days. The value
    /// must be greater than zero and less than 24 h — anything else refuses startup rather
    /// than silently widening or locking the bound. It is enforced by the caller-
    /// authentication stage <em>before</em> any <see cref="ICallerTokenMapper"/> runs, so
    /// replacing the mapper cannot drop it, and it is read once at startup: changing it
    /// requires a restart. The comparison permits the five-minute clock skew the JWT bearer
    /// handler allows by default, in both directions — a future <c>iat</c> beyond the skew
    /// is not freshness either. With a limit set, a token carrying no parsable <c>iat</c>
    /// is rejected (unprovable freshness). Rejection is a plain
    /// <c>401 caller_unauthenticated</c>. Unset means the issuer's lifetime is the bound.
    /// </summary>
    public TimeSpan? MaxTokenAge { get; set; }

    /// <summary>
    /// Claim names carrying the client (application) id, checked in order: <c>azp</c> for
    /// v2 tokens, <c>appid</c> for v1. Another OIDC issuer that names the claim differently
    /// is met by configuration, not code.
    /// </summary>
    public string[] ClientClaimNames { get; set; } = ["azp", "appid"];

    /// <summary>
    /// Claim names carrying the token's scopes, checked in order: <c>roles</c> (app roles,
    /// the client-credentials shape) and <c>scp</c> (delegated user tokens). The raw names
    /// arrive because the caller-token scheme turns the stock JWT bearer handler's inbound
    /// claim mapping off (<c>MapInboundClaims = false</c>) — nothing renames them to the
    /// long claim types, and another issuer's claim naming is met by configuration here,
    /// not by code. Caller tokens require named rules: a token gets exactly the operations
    /// its roles name; a caller without named rules admits no token.
    /// </summary>
    public string[] ScopeClaimNames { get; set; } = ["roles", "scp"];
}
