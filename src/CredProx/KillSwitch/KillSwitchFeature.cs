using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
using Yarp.ReverseProxy.Model;

namespace CredProx;

/// <summary>
/// The built-in <see cref="Stage.ApplyKillSwitch"/> feature (M18, plan §8.4): a cluster or
/// a caller listed under <c>CredProx:KillSwitch</c> is out of service — the request answers
/// <c>503 credprox.vendor_disabled</c> or <c>503 credprox.caller_disabled</c> and is never
/// forwarded, no partition is resolved and no token endpoint is called (§3.4). The flip
/// lives in configuration and takes effect on reload, so taking a vendor out of service is
/// a config push, not a redeploy.
/// </summary>
/// <remarks>
/// A disabled caller is answered only after its key authenticated — the switch removes a
/// caller from service, it never becomes an anonymous bypass around caller auth. The caller
/// check runs before the cluster check: with both disabled the caller-facing code is the
/// more specific answer. An anonymous route (no <see cref="CallerIdentity"/>) is still
/// guarded by the cluster check.
/// </remarks>
internal sealed class KillSwitchFeature(KillSwitchRegistryProvider switches) : IRequestFeature
{
    private readonly KillSwitchRegistryProvider _switches =
        switches ?? throw new ArgumentNullException(nameof(switches));

    /// <inheritdoc />
    public Stage Stage => Stage.ApplyKillSwitch;

    /// <inheritdoc />
    public ValueTask ApplyAsync(HttpContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.Features.Get<CredProxRequestState>() is not { } state)
        {
            return ValueTask.CompletedTask; // not running inside the CredProx transform
        }

        var registry = _switches.Current;

        if (context.Features.Get<CallerIdentity>() is { } identity
            && registry.IsCallerDisabled(identity.CallerId))
        {
            CredProxDiagnostics.KillSwitchRejections.Add(
                1,
                new KeyValuePair<string, object?>("credprox.kind", "caller"),
                new KeyValuePair<string, object?>("credprox.caller", identity.CallerId));

            return state.AbortAsync(
                StatusCodes.Status503ServiceUnavailable,
                "credprox.caller_disabled",
                "The caller is temporarily out of service.");
        }

        var proxyFeature = context.Features.Get<IReverseProxyFeature>();
        var clusterId = proxyFeature?.Cluster?.Config?.ClusterId ?? proxyFeature?.Route?.Config?.ClusterId;
        if (clusterId is not null && registry.IsClusterDisabled(clusterId))
        {
            CredProxDiagnostics.KillSwitchRejections.Add(
                1,
                new KeyValuePair<string, object?>("credprox.kind", "cluster"),
                new KeyValuePair<string, object?>("credprox.cluster", clusterId));

            return state.AbortAsync(
                StatusCodes.Status503ServiceUnavailable,
                "credprox.vendor_disabled",
                "The destination is temporarily out of service.");
        }

        return ValueTask.CompletedTask;
    }
}
