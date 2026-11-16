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
/// The built-in <see cref="Stage.AuthenticateCaller"/> feature (§3.5 rule 3, §4 Phase B):
/// once caller authentication is registered, every proxied route requires an authenticated
/// caller unless the route opts out with <c>"Metadata": { "CredProx.Caller": "anonymous" }</c>.
/// A missing, unknown, expired or revoked key answers
/// <c>401 credprox.caller_unauthenticated</c> before destination resolution, header shaping
/// and credential attachment run — so a rejected request never reaches a token endpoint or
/// the upstream (§3.4). Where the caller-token layer is registered (M39, ADR-0004) a
/// validated caller token whose client id a caller declares is admitted the same way, after
/// the key check. Before any <see cref="ICallerTokenMapper"/> runs this stage enforces
/// <c>CredProx:CallerToken:MaxTokenAge</c> against the raw <c>iat</c> (M39, ADR-0004) — the
/// bound cannot be dropped by a replaced mapper, and it is read once at startup, so
/// changing it requires a restart. A refused token is logged server-side with its reason
/// (stale / unlisted), never in the response body. On success the caller identity is published as an
/// <see cref="HttpContext"/> feature (for the operation allow-list and the <c>caller:</c>
/// partition source) and as <see cref="HttpContext.User"/> (for hosts that also enforce
/// the <see cref="CredProxAuth.CallerPolicy"/> through middleware).
/// </summary>
[Experimental("CREDPROX001")]
public sealed class CallerAuthenticationFeature : IRequestFeature
{
    /// <summary>The route metadata value opting a route out of caller authentication.</summary>
    public const string AnonymousValue = "anonymous";

    /// <inheritdoc />
    public Stage Stage => Stage.AuthenticateCaller;

    /// <inheritdoc />
    public async ValueTask ApplyAsync(HttpContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.Features.Get<CredProxRequestState>() is not { } state)
        {
            return; // not running inside the CredProx transform
        }

        var metadata = CredProxMetadata.GetRouteMetadata(context);
        if (metadata is not null
            && metadata.TryGetValue(CredProxMetadata.Caller, out var requirement)
            && string.Equals(requirement, AnonymousValue, StringComparison.OrdinalIgnoreCase))
        {
            return; // route opted out
        }

        var result = await context.AuthenticateAsync(CredProxAuth.CallerKeyScheme).ConfigureAwait(false);
        if (result.Succeeded && result.Principal is { } keyPrincipal)
        {
            if (CallerIdentity.FromPrincipal(keyPrincipal) is not { } identity)
            {
                // A principal from this scheme without the caller claim is a contract break;
                // fail closed rather than serve an unidentified caller.
                await state
                    .AbortAsync(StatusCodes.Status401Unauthorized, "credprox.caller_unauthenticated",
                        "A valid caller API key is required.")
                    .ConfigureAwait(false);
                return;
            }

            context.User = keyPrincipal;
            context.Features.Set(identity);
            return;
        }

        // No key (or the key failed): a caller token is admitted wherever the token
        // SCHEME is registered and a mapper can turn the principal into a caller (M39,
        // ADR-0004). The scheme registration — not the mapper — is what makes a
        // token admissible: authenticating a scheme nobody registered throws inside the
        // feature, and a mapper without the scheme could never authenticate anything.
        // A validated principal that maps to no configured caller is a failed
        // authentication, not a 500.
        var schemes = context.RequestServices.GetService<IAuthenticationSchemeProvider>();
        var tokenSchemeRegistered = schemes is not null
            && await schemes.GetSchemeAsync(CredProxAuth.CallerTokenScheme).ConfigureAwait(false) is not null;
        var mapper = tokenSchemeRegistered
            ? context.RequestServices.GetService<ICallerTokenMapper>()
            : null;
        if (mapper is not null)
        {
            var tokenResult = await context.AuthenticateAsync(CredProxAuth.CallerTokenScheme)
                .ConfigureAwait(false);
            if (tokenResult.Succeeded && tokenResult.Principal is { } tokenPrincipal)
            {
                // M39 (ADR-0004): MaxTokenAge is CredProx's bound, not the mapper's —
                // this stage is not replaceable and the check runs before any mapper,
                // so a host-registered ICallerTokenMapper cannot drop it. The limit
                // comes from the CredProx-side options singleton (the scheme's
                // AddJwtBearer copy receives only Authority/Audience) and is read at
                // startup; changing it requires a restart.
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
                    // Publish the caller identity exactly like the key handler does, so
                    // the allow-list, the caller: partition and the policy all read one
                    // shape whichever scheme won — plus, M39 (ADR-0004), the client id
                    // (for audit) and the per-request scope set the allow-list stage
                    // intersects with. The scope set is set even when empty: a token
                    // carrying no roles locks out the caller's named rules, which is the
                    // fail-closed reading of "scope only narrows".
                    var clientId = mapping.Identity.ClientId;
                    tokenPrincipal.AddIdentity(new ClaimsIdentity(
                        [
                            new Claim(CallerIdentity.CallerClaimType, mapping.Identity.CallerId),
                            new Claim(CallerIdentity.KeyIdClaimType, mapping.Identity.KeyId),
                            .. clientId is not null
                                ? new[] { new Claim(CallerIdentity.ClientIdClaimType, clientId) }
                                : [],
                        ],
                        authenticationType: CredProxAuth.CallerTokenScheme,
                        nameType: CallerIdentity.CallerClaimType,
                        roleType: null));
                    context.User = tokenPrincipal;
                    context.Features.Set(mapping.Identity);
                    context.Features.Set(new CallerRequestScopes(mapping.Scopes));
                    context.Features.Set(new CallerTokenRequestMarker());
                    return;
                }
                // Diagnosability (M39): name the refusal server-side; the problem+json
                // body stays the generic 401 detail.
                context.RequestServices
                    .GetService<ILogger<CallerAuthenticationFeature>>()?
                    .LogWarning(
                        "Caller token refused ({Reason}); client id '{ClientId}'.",
                        refusal,
                        FirstClaimValue(tokenPrincipal, options.ClientClaimNames));
            }
        }

        await state
            .AbortAsync(StatusCodes.Status401Unauthorized, "credprox.caller_unauthenticated",
                tokenSchemeRegistered
                    ? "A valid caller API key or caller token is required."
                    : "A valid caller API key is required.")
            .ConfigureAwait(false);
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
