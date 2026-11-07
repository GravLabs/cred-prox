using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Yarp.ReverseProxy.Model;

namespace CredProx;

/// <summary>
/// The built-in <see cref="Stage.AuthorizeOperation"/> feature (§4 Phase B, §5.2
/// "Operation allow-lists"): for an authenticated caller that declares an operation
/// allow-list, the request's route, method and path must match at least one entry, or the
/// request answers <c>403 credprox.operation_not_allowed</c> before destination resolution
/// and credential attachment — nothing reaches the token endpoint or the upstream. A
/// caller with no declared operations is unrestricted.
/// </summary>
/// <remarks>
/// Path safety comes first (§5.2 traversal variants): a path carrying dot segments,
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

        if (caller.Operations.Count == 0)
        {
            return ValueTask.CompletedTask; // caller declares no allow-list: unrestricted
        }

        var routeId = context.Features.Get<IReverseProxyFeature>()?.Route?.Config?.RouteId;
        var rawPath = context.Features.Get<IHttpRequestFeature>()?.Path;
        var decodedPath = DecodedPathWithoutBase(context);

        if (!PathPatterns.IsSafePath(rawPath, decodedPath))
        {
            return AbortAsync(state);
        }

        var method = context.Request.Method;
        if (!caller.Operations.Any(rule => rule.Matches(routeId, method, decodedPath)))
        {
            return AbortAsync(state);
        }

        return ValueTask.CompletedTask;
    }

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
