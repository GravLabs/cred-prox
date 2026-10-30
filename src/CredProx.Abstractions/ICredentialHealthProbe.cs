using System.Diagnostics.CodeAnalysis;

namespace CredProx.Abstractions;

/// <summary>
/// A background probe that checks a credential or certificate is still usable — for
/// example that a token can still be obtained, or that a client certificate is not near
/// expiry. The core exposes probes through ASP.NET Core health checks, metrics and
/// warnings.
/// </summary>
[Experimental("CREDPROX001")]
public interface ICredentialHealthProbe
{
    /// <summary>The probe name, used in health reports and metrics.</summary>
    string Name { get; }

    /// <summary>
    /// Runs the probe.
    /// </summary>
    /// <returns>
    /// <see langword="null"/> when healthy, otherwise a result carrying the failure's
    /// severity and a short human-readable description. The description must never
    /// contain a secret value.
    /// </returns>
    /// <param name="cancellationToken">Cancels the probe.</param>
    ValueTask<CredProxHealthResult?> CheckAsync(CancellationToken cancellationToken);
}
