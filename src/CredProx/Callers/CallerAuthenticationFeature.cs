using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace CredProx;

/// <summary>
/// The built-in <see cref="Stage.AuthenticateCaller"/> feature (§3.5 rule 3, §4 Phase B):
/// once caller authentication is registered, every proxied route requires an authenticated
/// caller unless the route opts out with <c>"Metadata": { "CredProx.Caller": "anonymous" }</c>.
/// A missing, unknown, expired or revoked key answers
/// <c>401 credprox.caller_unauthenticated</c> before destination resolution, header shaping
/// and credential attachment run — so a rejected request never reaches a token endpoint or
/// the upstream (§3.4). On success the caller identity is published as an
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
        if (!result.Succeeded || result.Principal is not { } principal)
        {
            await state
                .AbortAsync(StatusCodes.Status401Unauthorized, "credprox.caller_unauthenticated",
                    "A valid caller API key is required.")
                .ConfigureAwait(false);
            return;
        }

        if (CallerIdentity.FromPrincipal(principal) is not { } identity)
        {
            // A principal from this scheme without the caller claim is a contract break;
            // fail closed rather than serve an unidentified caller.
            await state
                .AbortAsync(StatusCodes.Status401Unauthorized, "credprox.caller_unauthenticated",
                    "A valid caller API key is required.")
                .ConfigureAwait(false);
            return;
        }

        context.User = principal;
        context.Features.Set(identity);
    }
}
