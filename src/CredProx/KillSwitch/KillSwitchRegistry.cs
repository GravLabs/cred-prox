namespace CredProx;

/// <summary>
/// The live kill-switch state (M18, plan §8.4): which clusters and which callers are
/// currently out of service. Ids match case-insensitively, like every other CredProx id;
/// entries that name nothing existing are harmless (the id may arrive with a later
/// reload), so nothing cross-checks them against the other registries.
/// </summary>
internal sealed class KillSwitchRegistry
{
    /// <summary>The state with nothing disabled — every request passes.</summary>
    public static readonly KillSwitchRegistry Empty = new([], []);

    private readonly HashSet<string> _clusters;
    private readonly HashSet<string> _callers;

    public KillSwitchRegistry(IEnumerable<string> clusters, IEnumerable<string> callers)
    {
        _clusters = new HashSet<string>(clusters, StringComparer.OrdinalIgnoreCase);
        _callers = new HashSet<string>(callers, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>How many clusters are out of service (for the rebind log).</summary>
    public int DisabledClusterCount => _clusters.Count;

    /// <summary>How many callers are out of service (for the rebind log).</summary>
    public int DisabledCallerCount => _callers.Count;

    public bool IsClusterDisabled(string clusterId) => _clusters.Contains(clusterId);

    public bool IsCallerDisabled(string callerId) => _callers.Contains(callerId);
}
