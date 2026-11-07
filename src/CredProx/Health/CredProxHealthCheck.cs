using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace CredProx;

/// <summary>
/// The ASP.NET Core health check over the latest probe round (§4 "Credential health"):
/// any Unhealthy probe makes the check Unhealthy, else any Degraded makes it Degraded,
/// else Healthy. The failure descriptions ride along as check data — names and failure
/// kinds, never secret values.
/// </summary>
[Experimental("CREDPROX001")]
internal sealed class CredProxHealthCheck(CredentialHealthSnapshot snapshot) : IHealthCheck
{
    /// <inheritdoc />
    public Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        var results = snapshot.Results;
        var failing = results.Where(r => r.Severity > 0).ToArray();

        if (failing.Length == 0)
        {
            return Task.FromResult(HealthCheckResult.Healthy(
                results.Length == 0 ? "No CredProx health probes have run yet." : null));
        }

        var description = string.Join("; ", failing.Select(r => $"{r.Name}: {r.Description}"));
        var data = failing.ToDictionary(r => r.Name, r => (object)r.Description!);

        return Task.FromResult(failing.Max(r => r.Severity) == 2
            ? HealthCheckResult.Unhealthy(description, data: data)
            : HealthCheckResult.Degraded(description, data: data));
    }
}
