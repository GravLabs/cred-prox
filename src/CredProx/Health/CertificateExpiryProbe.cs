using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;

namespace CredProx;

/// <summary>
/// The built-in certificate-expiry probe (§4 "Credential health", §5.2 "Credential
/// health"): reads each connection's loaded client certificate and reports
/// <c>Degraded</c> while one expires within <see cref="CredProxHealthOptions.CertWarningDays"/>
/// days and <c>Unhealthy</c> once one has expired (or a connection has no usable
/// certificate). The days-to-expiry gauge is recorded every round whatever the status,
/// so the warning window is visible in dashboards before health changes.
/// </summary>
[Experimental("CREDPROX001")]
internal sealed class CertificateExpiryProbe(
    ConnectionRegistryProvider registryProvider,
    CredProxHealthOptions options,
    TimeProvider time) : ICredentialHealthProbe
{
    /// <inheritdoc />
    public string Name => "credprox.certificates";

    /// <inheritdoc />
    public ValueTask<CredProxHealthResult?> CheckAsync(CancellationToken cancellationToken)
    {
        var registry = registryProvider.Current;
        var now = time.GetUtcNow();
        var warningWindow = now + TimeSpan.FromDays(options.CertWarningDays);

        var problems = new List<string>();
        var anyUnhealthy = false;

        foreach (var name in registry.Names)
        {
            DateTimeOffset notAfter;
            try
            {
                notAfter = registry.Get(name).Certificate.NotAfter;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                problems.Add($"connection '{name}' has no usable client certificate ({ex.Message})");
                anyUnhealthy = true;
                CredProxDiagnostics.RecordHealthStatus("connection", name, 2);
                continue;
            }

            CredProxDiagnostics.RecordCertificateDaysToExpiry(name, (notAfter - now).TotalDays);

            if (notAfter <= now)
            {
                problems.Add($"connection '{name}' client certificate expired {notAfter:u}");
                anyUnhealthy = true;
                CredProxDiagnostics.RecordHealthStatus("connection", name, 2);
            }
            else if (notAfter <= warningWindow)
            {
                problems.Add(
                    $"connection '{name}' client certificate expires {notAfter:u} (within {options.CertWarningDays} days)");
                CredProxDiagnostics.RecordHealthStatus("connection", name, 1);
            }
            else
            {
                CredProxDiagnostics.RecordHealthStatus("connection", name, 0);
            }
        }

        if (problems.Count == 0)
        {
            return ValueTask.FromResult<CredProxHealthResult?>(null);
        }

        var description = string.Join("; ", problems);
        return ValueTask.FromResult<CredProxHealthResult?>(new CredProxHealthResult(
            anyUnhealthy ? CredProxHealthSeverity.Unhealthy : CredProxHealthSeverity.Degraded,
            description));
    }
}
