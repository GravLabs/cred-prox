using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace CredProx;

/// <summary>
/// The built-in <see cref="Stage.AuthenticateCaller"/> feature:
/// once caller authentication is registered, every proxied route requires an authenticated
/// caller unless the route opts out with <c>"Metadata": { "CredProx.Caller": "anonymous" }</c>.
/// A missing or refused credential answers <c>401 credprox.caller_unauthenticated</c> before
/// destination resolution, header shaping and credential attachment run — so a rejected
/// request never reaches a token endpoint or the upstream.
/// </summary>
/// <remarks>
/// <para>
/// The stage consults every registered <see cref="ICallerAuthenticator"/> in registration
/// order (ADR-0005); the first <see cref="CallerAuthenticationOutcome.Authenticated"/> or
/// <see cref="CallerAuthenticationOutcome.Refused"/> outcome wins, and when all answer
/// <see cref="CallerAuthenticationOutcome.NoCredential"/> the request ends unauthenticated.
/// What the credential is — an API key, a caller token, anything a host registers — is the
/// authenticators' business; the stage names no credential type. Its 401 detail is composed
/// from their <see cref="ICallerAuthenticator.CredentialRequirementHint"/> values.
/// </para>
/// <para>
/// On success the stage publishes the winner's identity exactly once, in one shape: as an
/// <see cref="HttpContext"/> feature (for the operation allow-list and the <c>caller:</c>
/// partition source) and as <see cref="HttpContext.User"/> (for hosts that also enforce the
/// <see cref="CredProxAuth.CallerPolicy"/> through middleware) — plus the scope set and the
/// presented-credential marker when the winner reported them. An identity that the
/// configured caller registry does not know never gets published: it answers the same 401
/// an unknown credential holder does.
/// </para>
/// </remarks>
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

        // Registration order decides which authenticator sees the request first; the first
        // authenticated-or-refused outcome wins (ADR-0005). Exceptions from an
        // authenticator propagate untouched — a broken authenticator is a host bug, not
        // an unauthenticated request.
        CallerAuthenticationResult? won = null;
        foreach (var authenticator in context.RequestServices.GetServices<ICallerAuthenticator>())
        {
            var outcome = await authenticator
                .AuthenticateAsync(context, cancellationToken)
                .ConfigureAwait(false);
            if (outcome.Outcome != CallerAuthenticationOutcome.NoCredential)
            {
                won = outcome;
                break;
            }
        }

        if (won is { Outcome: CallerAuthenticationOutcome.Authenticated, Identity: { } identity })
        {
            // Fail closed on the identity itself: an authenticated caller the configured
            // registry does not know answers the same generic 401 an unknown key holder
            // gets — no authenticator can mint callers the configuration never declared.
            // (ADR-0004/ADR-0005: registering an authenticator brings the caller policy.)
            if (context.RequestServices.GetService<CallerRegistryProvider>() is { } registryProvider
                && !registryProvider.Current.TryGet(identity.CallerId, out _))
            {
                await state
                    .AbortAsync(StatusCodes.Status401Unauthorized, "credprox.caller_unauthenticated",
                        RequirementText(context))
                    .ConfigureAwait(false);
                return;
            }

            // Publish the caller identity in one shape whichever authenticator won, so the
            // allow-list, the caller: partition and the policy all read the same record: a
            // fresh principal carrying exactly the caller claims (the winning credential
            // itself stays out of it — see PresentedCredentialHeader), the identity feature,
            // the scope set when the credential type carries one, and the presented-header
            // marker when the credential arrived in a request header.
            if (won.Principal is { } carried)
            {
                // The credential's own principal stays visible so host middleware keeps
                // seeing its raw claims (M39); the caller identity is added as one more
                // identity, in the same shape the synthesized principal uses.
                carried.AddIdentity(BuildCallerIdentity(identity));
                context.User = carried;
            }
            else
            {
                context.User = new ClaimsPrincipal(BuildCallerIdentity(identity));
            }
            context.Features.Set(identity);
            if (won.Scopes is { } scopes)
            {
                // Set even when empty: a credential carrying no scopes locks out the
                // caller's named rules (ADR-0004 clause 3, fail closed).
                context.Features.Set(new CallerRequestScopes(scopes));
            }

            if (won.PresentedCredentialHeader is { } header)
            {
                context.Features.Set(new PresentedCredential(header));
            }

            return;
        }

        // Refused, or every authenticator saw no credential: the generic 401 (a refusal's
        // reason is logged server-side by its authenticator, never in the response body).
        await state
            .AbortAsync(StatusCodes.Status401Unauthorized, "credprox.caller_unauthenticated",
                RequirementText(context))
            .ConfigureAwait(false);
    }

    // The caller-claims identity, published in one shape whichever authenticator won, so
    // the caller policy's RequireClaim and the caller-name binding hold for every path.
    // Its authentication type says CredProx authenticated this caller — which credential
    // type won is the authenticators' business, not host middleware's.
    private static ClaimsIdentity BuildCallerIdentity(CallerIdentity identity)
    {
        var clientId = identity.ClientId;
        return new ClaimsIdentity(
            [
                new Claim(CallerIdentity.CallerClaimType, identity.CallerId),
                new Claim(CallerIdentity.KeyIdClaimType, identity.KeyId),
                .. clientId is not null
                    ? new[] { new Claim(CallerIdentity.ClientIdClaimType, clientId) }
                    : [],
            ],
            authenticationType: CredProxCallerAuthenticationType,
            nameType: CallerIdentity.CallerClaimType,
            roleType: null);
    }

    private const string CredProxCallerAuthenticationType = "CredProxCaller";

    // "A valid caller API key or caller token is required." — composed over every
    // registered authenticator's hint, in registration order, so the stage names what the
    // host accepts without naming any credential type itself (ADR-0005).
    private static string RequirementText(HttpContext context)
    {
        string? composed = null;
        foreach (var authenticator in context.RequestServices.GetServices<ICallerAuthenticator>())
        {
            composed = composed is null
                ? authenticator.CredentialRequirementHint
                : composed + " or " + authenticator.CredentialRequirementHint;
        }

        return composed is null
            ? "A valid caller credential is required."
            : "A valid " + composed + " is required.";
    }
}
