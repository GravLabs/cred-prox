using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Yarp.ReverseProxy.Model;

namespace CredProx;

/// <summary>
/// The built-in <see cref="Stage.AuthorizeOperation"/> feature: for an authenticated
/// caller that declares an operation
/// allow-list, the request's route, method and path must match at least one entry, or the
/// request answers <c>403 credprox.operation_not_allowed</c> before destination resolution
/// and credential attachment — nothing reaches the token endpoint or the upstream. When
/// the request carries a <see cref="CallerRequestScopes"/> feature (the caller-token
/// path, ADR-0004) only entries NAMED in the token's scope set apply: a token gets
/// exactly the operations its roles name, an unnamed entry admits no token, and a caller
/// that declares no operations is denied for tokens too (fail closed). On the caller-key
/// path the feature is absent: an empty allow-list is opt-out and matching is
/// byte-for-byte as it has always been.
/// </summary>
/// <remarks>
/// Path safety comes first: a path carrying dot segments,
/// backslashes, control characters, or percent-escapes of <c>/</c>, <c>\</c>, <c>.</c> or
/// <c>%</c> in the raw target is refused before any pattern is consulted; matching on the
/// decoded path is ordinal and case-sensitive.
/// </remarks>
[Experimental("CREDPROX001")]
public sealed class OperationAllowListFeature(CallerRegistryProvider registryProvider) : IRequestFeature
{
    private readonly CallerRegistryProvider _registryProvider =
        registryProvider ?? throw new ArgumentNullException(nameof(registryProvider));

    /// <inheritdoc />
    public Stage Stage => Stage.AuthorizeOperation;

    /// <inheritdoc />
    public ValueTask ApplyAsync(HttpContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.Features.Get<CredProxRequestState>() is not { } state)
        {
            return ValueTask.CompletedTask; // not running inside the CredProx transform
        }

        if (context.Features.Get<CallerIdentity>() is not { } identity)
        {
            return ValueTask.CompletedTask; // anonymous route or caller auth not registered
        }

        if (!_registryProvider.Current.TryGet(identity.CallerId, out var caller))
        {
            // Authenticated against a caller the live registry no longer has (revoked
            // between authentication and authorization on this same request is impossible
            // in one pass; this is the fail-closed net for a rebind race).
            return AbortAsync(state);
        }

        // M39 (ADR-0004): the scope feature is published ONLY by the
        // caller-token path — an empty set is still present — so its presence, not
        // its content, is the discriminator. It is read before anything else.
        var scopes = context.Features.Get<CallerRequestScopes>()?.Scopes;
        if (caller.Operations.Count == 0)
        {
            // Key path: an empty allow-list is opt-out (unrestricted). Token path:
            // the caller declares no named rule the token could match, so nothing
            // is admitted — a scoped or role-less token gets 403 here too.
            if (scopes is null)
            {
                return ValueTask.CompletedTask;
            }

            LogTokenRefusal(context, identity, "the caller declares no named operations");
            return AbortAsync(state);
        }

        var routeId = context.Features.Get<IReverseProxyFeature>()?.Route?.Config?.RouteId;
        var rawPath = context.Features.Get<IHttpRequestFeature>()?.Path;
        var decodedPath = DecodedPathWithoutBase(context);

        if (!PathPatterns.IsSafePath(rawPath, decodedPath))
        {
            return AbortAsync(state);
        }

        // Scope only narrows, and on the token path it narrows to named matches:
        // an entry runs for a token only when it is NAMED and its name is among the
        // token's scopes. Unnamed entries and non-matching names are removed —
        // the intersection only ever removes, and a token gets exactly the
        // operations its roles name.
        var rules = scopes is null
            ? caller.Operations
            : caller.Operations.Where(rule => rule.Name is not null && scopes.Contains(rule.Name));

        var method = context.Request.Method;
        if (!rules.Any(rule => rule.Matches(routeId, method, decodedPath)))
        {
            if (scopes is not null)
            {
                LogTokenRefusal(context, identity, "no named operation rule matched");
            }

            return AbortAsync(state);
        }

        return ValueTask.CompletedTask;
    }

    // Diagnosability (M39): a refused caller token names its reason
    // server-side; the problem+json body stays the generic 403 detail. Client ids are
    // log-safe (audit records them); the token itself is never read here.
    private static void LogTokenRefusal(HttpContext context, CallerIdentity identity, string reason) =>
        context.RequestServices?
            .GetService<ILogger<OperationAllowListFeature>>()?
            .LogWarning(
                "Caller token refused ({Reason}); caller '{CallerId}', client id '{ClientId}'.",
                reason,
                identity.CallerId,
                identity.ClientId);

    private static string DecodedPathWithoutBase(HttpContext context)
    {
        var path = context.Request.Path;
        var pathBase = context.Request.PathBase;

        var remaining = pathBase.HasValue && path.StartsWithSegments(pathBase)
            ? path.Value![pathBase.Value!.Length..]
            : path.Value;

        return string.IsNullOrEmpty(remaining) ? "/" : remaining;
    }

    private static ValueTask AbortAsync(CredProxRequestState state) => state.AbortAsync(
        StatusCodes.Status403Forbidden, "credprox.operation_not_allowed",
        "The caller is not allowed this operation.");
}
