using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
using Yarp.ReverseProxy.Model;

namespace CredProx;

/// <summary>
/// The built-in <see cref="Stage.ApplyCallerBudget"/> feature (M15, plan §3.7): an
/// authenticated caller that declares a <c>Limits</c> budget gets at most
/// <c>PermitsPerInterval</c> requests per window per cluster; beyond it the request answers
/// <c>429 credprox.caller_throttled</c> with <c>Retry-After</c> (time to the window reset)
/// — before header shaping and credential attachment, so a rejected request never touches a
/// token endpoint or the upstream (§3.4). Unlike the cluster throttle there is no queueing:
/// the budget protects the other callers from this one, so waiting would hold the shared
/// resource it exists to protect.
/// </summary>
/// <remarks>
/// The budget is per caller app: the key id never enters the budget key (rotation must not
/// reset it) and neither does any end-user or partition value (post-M14 per-user tokens
/// share the app's budget, §3.7). Runs after <see cref="Stage.AuthorizeOperation"/> (a
/// blocked operation never consumes budget) and after
/// <see cref="Stage.ResolveDestination"/> (per-cluster overrides key on the resolved
/// cluster). Single-instance, in-memory scope.
/// </remarks>
internal sealed class CallerBudgetFeature(CallerRegistryProvider registryProvider, CallerBudgetRegistry budgets) : IRequestFeature
{
    private readonly CallerRegistryProvider _registryProvider =
        registryProvider ?? throw new ArgumentNullException(nameof(registryProvider));
    private readonly CallerBudgetRegistry _budgets =
        budgets ?? throw new ArgumentNullException(nameof(budgets));

    /// <inheritdoc />
    public Stage Stage => Stage.ApplyCallerBudget;

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

        if (!_registryProvider.Current.TryGet(identity.CallerId, out var caller) || caller.Limits is not { } limits)
        {
            // Gone from the live registry: the allow-list stage already failed closed on
            // the same snapshot; the budget adds no auth. No Limits: unlimited (§3.7).
            return ValueTask.CompletedTask;
        }

        var clusterId = context.Features.Get<IReverseProxyFeature>()?.Cluster?.Config?.ClusterId
            ?? context.Features.Get<IReverseProxyFeature>()?.Route?.Config?.ClusterId;

        var (permits, interval) = Effective(limits, clusterId);
        if (permits <= 0)
        {
            return ValueTask.CompletedTask; // disabled for this cluster (0 disables, §3.7)
        }

        var clusterKey = clusterId ?? CallerBudgetRegistry.DefaultClusterKey;
        if (_budgets.TryAcquire(identity.CallerId, clusterKey, permits, interval, out var retryAfter))
        {
            return ValueTask.CompletedTask;
        }

        CredProxDiagnostics.CallerBudgetRejections.Add(
            1,
            new KeyValuePair<string, object?>("credprox.caller", identity.CallerId),
            new KeyValuePair<string, object?>("credprox.cluster", clusterKey));

        return state.AbortAsync(
            StatusCodes.Status429TooManyRequests,
            "credprox.caller_throttled",
            "The caller exceeded its request budget for this destination. Try again later.",
            retryAfter);
    }

    // Per-cluster override replaces the caller default field by field (null inherits —
    // the ThrottleClusterOptions idiom); 0 permits disables for that cluster (§3.7).
    internal static (int Permits, TimeSpan Interval) Effective(CallerLimits limits, string? clusterId)
    {
        if (clusterId is not null && limits.Clusters.TryGetValue(clusterId, out var cluster))
        {
            return (cluster.PermitsPerInterval ?? limits.PermitsPerInterval, cluster.Interval ?? limits.Interval);
        }

        return (limits.PermitsPerInterval, limits.Interval);
    }
}
