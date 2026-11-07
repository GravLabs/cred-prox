using System.Diagnostics.CodeAnalysis;

namespace CredProx.Abstractions;

/// <summary>
/// How bad a failed health probe is. The core maps these onto the ASP.NET Core health
/// check statuses of the same name (<c>Degraded</c>, <c>Unhealthy</c>) when reporting.
/// </summary>
[Experimental("CREDPROX001")]
public enum CredProxHealthSeverity
{
    /// <summary>
    /// The credential or certificate still works but is near a problem — for example a
    /// client certificate expiring within the configured warning window.
    /// </summary>
    Degraded = 1,

    /// <summary>
    /// The credential or certificate does not work — for example a token that cannot be
    /// obtained or a certificate that has already expired.
    /// </summary>
    Unhealthy = 2,
}
