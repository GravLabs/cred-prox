using System.Diagnostics.CodeAnalysis;

namespace CredProx.Abstractions;

/// <summary>
/// The failure a health probe found. Severity is per-result, not per-probe: the built-in
/// certificate probe reports <see cref="CredProxHealthSeverity.Degraded"/> while a
/// certificate is merely near expiry and <see cref="CredProxHealthSeverity.Unhealthy"/>
/// once it has expired.
/// </summary>
/// <param name="Severity">How bad the failure is.</param>
/// <param name="Description">
/// A short human-readable description for health reports and warnings. It must never
/// contain a secret value.
/// </param>
[Experimental("CREDPROX001")]
public sealed record CredProxHealthResult(CredProxHealthSeverity Severity, string Description);
