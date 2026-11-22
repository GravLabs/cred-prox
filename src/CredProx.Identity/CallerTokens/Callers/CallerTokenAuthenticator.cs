using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Claims;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace CredProx;

/// <summary>
/// The built-in caller-token authenticator (ADR-0004; seam per ADR-0005): admits a
/// validated caller token whose client id a caller declares. A token can carry scopes, so a
/// success reports the mapper's scope set too — even when empty, which locks out the
/// caller's named rules (the fail-closed reading of "scope only narrows"). Before any
/// <see cref="ICallerTokenMapper"/> runs this authenticator enforces
/// <c>CredProx:CallerToken:MaxTokenAge</c> against the raw <c>iat</c>, so the bound cannot be
/// dropped by a replaced mapper; it is read once at startup, so changing it requires a
/// restart. A refused token is logged server-side with its reason (stale / unlisted), never
/// in the response body. On success the credential's own <c>Authorization</c> header is
/// reported as the presented credential, so header hygiene strips it from the outbound
/// request before the vendor's credential is attached.
/// </summary>
[Experimental("CREDPROX001")]
internal sealed class CallerTokenAuthenticator : ICallerAuthenticator
{
    /// <inheritdoc />
    public string CredentialRequirementHint => "caller token";

    /// <inheritdoc />
    public async ValueTask<CallerAuthenticationResult> AuthenticateAsync(
        HttpContext context,
        CancellationToken cancellationToken)
    {
        // The scheme registration — not the mapper — is what makes a token admissible:
        // authenticating a scheme nobody registered throws inside the feature, and a mapper
        // without the scheme could never authenticate anything. A validated principal that
        // maps to no configured caller is a refusal, not a 500.
        var schemes = context.RequestServices.GetService<IAuthenticationSchemeProvider>();
        if (schemes is null
            || await schemes.GetSchemeAsync(CallerTokenOptions.Scheme).ConfigureAwait(false) is null)
        {
            return CallerAuthenticationResult.NoCredential();
        }

        var mapper = context.RequestServices.GetService<ICallerTokenMapper>();
        if (mapper is null)
        {
            return CallerAuthenticationResult.NoCredential();
        }

        var tokenResult = await context
            .AuthenticateAsync(CallerTokenOptions.Scheme)
            .ConfigureAwait(false);
        if (!tokenResult.Succeeded || tokenResult.Principal is not { } tokenPrincipal)
        {
            return CallerAuthenticationResult.NoCredential();
        }

        // M39 (ADR-0004): MaxTokenAge is CredProx's bound, not the mapper's — this check
        // runs before any mapper, so a host-registered ICallerTokenMapper cannot drop it.
        // The limit comes from the CredProx-side options singleton (the scheme's
        // AddJwtBearer copy receives only Authority/Audience) and is read at startup;
        // changing it requires a restart.
        // Fail closed: AddCredProx always registers these options when the token
        // path is on, so a missing registration is a broken container — it must
        // abort the request, not admit tokens with no age bound (M39).
        var options = context.RequestServices.GetRequiredService<CallerTokenOptions>();
        var refusal = options.MaxTokenAge is { } maxAge && !IsFresh(tokenPrincipal, maxAge)
            ? "stale"
            : null;
        var mapping = refusal is null ? mapper.MapToken(tokenPrincipal) : null;
        if (refusal is null && mapping is null)
        {
            refusal = "unlisted";
        }

        if (mapping is not null)
        {
            // The scope set flows even when empty (ADR-0004 clause 3), the bearer header is
            // named as the presented credential so hygiene strips it upstream, and the raw
            // token principal is handed over so the host still sees the issuer's raw claim
            // names and role membership (M39).
            return CallerAuthenticationResult.Authenticated(
                mapping.Identity, mapping.Scopes, "Authorization", tokenPrincipal);
        }

        // Diagnosability (M39): name the refusal server-side; the problem+json
        // body stays the generic 401 detail.
        context.RequestServices
            .GetService<ILogger<CallerTokenAuthenticator>>()?
            .LogWarning(
                "Caller token refused ({Reason}); client id '{ClientId}'.",
                refusal,
                FirstClaimValue(tokenPrincipal, options.ClientClaimNames));
        return CallerAuthenticationResult.Refused();
    }

    private const string IssuedAtClaim = "iat";

    // The JWT bearer handler's own default ClockSkew: rejecting a token this check
    // still considers fresh while the handler accepts it would be its own surprise (M39/D).
    private static readonly TimeSpan JwtBearerDefaultClockSkew = TimeSpan.FromMinutes(5);

    // Raw "iat" in whole seconds — the caller-token scheme turns inbound claim mapping
    // off, so the name and the value arrive exactly as the issuer wrote them. No parsable
    // iat is no established freshness: fail closed while a limit is configured.
    private static bool IsFresh(ClaimsPrincipal principal, TimeSpan maxAge)
    {
        var raw = principal.FindFirst(IssuedAtClaim)?.Value;
        if (raw is null
            || !long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var issuedAtSeconds))
        {
            return false;
        }

        var age = DateTimeOffset.UtcNow - DateTimeOffset.FromUnixTimeSeconds(issuedAtSeconds);
        // M39 (ADR-0004): a future iat is not freshness either — a negative age is inside
        // every upper bound, so the skew gates both directions of the clock.
        return age >= -JwtBearerDefaultClockSkew && age <= maxAge + JwtBearerDefaultClockSkew;
    }

    // Client ids are log-safe (audit records them); the token itself is never read here.
    private static string? FirstClaimValue(ClaimsPrincipal principal, IReadOnlyList<string> claimNames)
    {
        foreach (var name in claimNames)
        {
            var value = principal.FindFirst(name)?.Value;
            if (!string.IsNullOrEmpty(value))
            {
                return value;
            }
        }

        return null;
    }
}
