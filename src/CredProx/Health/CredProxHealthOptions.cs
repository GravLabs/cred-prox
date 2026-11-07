using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// Credential-health options bound from <c>CredProx:Health</c> (see
/// <c>docs/credprox-plan.md</c> §4 "Credential health", §5.2 "Credential health").
/// </summary>
[Experimental("CREDPROX001")]
public sealed class CredProxHealthOptions
{
    private TimeSpan _probeInterval = TimeSpan.FromMinutes(5);
    private int _certWarningDays = 30;

    /// <summary>Whether the background probe loop runs. Default <see langword="true"/>.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// How often the probes run. Default 5 minutes; must be positive. The first round
    /// runs at startup, so health is meaningful before the first interval elapses.
    /// </summary>
    public TimeSpan ProbeInterval
    {
        get => _probeInterval;
        set
        {
            if (value <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(value), "The health probe interval must be positive.");
            }

            _probeInterval = value;
        }
    }

    /// <summary>
    /// How far before expiry a client certificate turns health <c>Degraded</c> and logs
    /// the warning. Default 30 days; must not be negative. A certificate that has already
    /// expired is <c>Unhealthy</c> regardless.
    /// </summary>
    public int CertWarningDays
    {
        get => _certWarningDays;
        set
        {
            if (value < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(value), "The certificate warning window cannot be negative.");
            }

            _certWarningDays = value;
        }
    }
}
