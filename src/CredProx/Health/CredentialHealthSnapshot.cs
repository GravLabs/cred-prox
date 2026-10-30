using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>One probe's outcome from the latest completed round.</summary>
/// <param name="Name">The probe name.</param>
/// <param name="Severity">0 healthy, 1 degraded, 2 unhealthy.</param>
/// <param name="Description">The failure description; <see langword="null"/> when healthy.</param>
/// <param name="CheckedAt">When the round ran.</param>
internal sealed record HealthProbeResult(string Name, int Severity, string? Description, DateTimeOffset CheckedAt);

/// <summary>
/// The latest health-probe round, swapped atomically by the probe loop and read by the
/// ASP.NET Core health check. Readers never see a torn round.
/// </summary>
[Experimental("CREDPROX001")]
internal sealed class CredentialHealthSnapshot
{
    private volatile HealthProbeResult[] _results = [];

    /// <summary>The latest round's per-probe results (empty before the first round).</summary>
    public HealthProbeResult[] Results => _results;

    /// <summary>Replaces the whole round.</summary>
    /// <param name="results">The completed round's results.</param>
    public void Update(IEnumerable<HealthProbeResult> results)
    {
        ArgumentNullException.ThrowIfNull(results);
        _results = [.. results];
    }
}
