using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// The bound set of callers (§4 Phase B), keyed by caller id case-insensitively — the
/// config key is the identity. Resolved per request through the live provider, so a
/// reload that adds or revokes a caller takes effect without a restart.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class CallerRegistry
{
    private readonly Dictionary<string, CallerDefinition> _callers;

    /// <summary>Creates the registry.</summary>
    /// <param name="callers">The bound callers, keyed by caller id.</param>
    public CallerRegistry(IReadOnlyDictionary<string, CallerDefinition> callers)
    {
        ArgumentNullException.ThrowIfNull(callers);
        _callers = new Dictionary<string, CallerDefinition>(callers, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>The number of configured callers.</summary>
    public int Count => _callers.Count;

    /// <summary>The configured caller ids.</summary>
    public IEnumerable<string> CallerIds => _callers.Keys;

    /// <summary>Looks up a caller by id.</summary>
    /// <param name="callerId">The caller id to find.</param>
    /// <param name="definition">The caller when found.</param>
    /// <returns><see langword="true"/> when the caller is configured.</returns>
    public bool TryGet(string callerId, [NotNullWhen(true)] out CallerDefinition? definition) =>
        _callers.TryGetValue(callerId, out definition);

    /// <summary>Looks up a caller by id.</summary>
    /// <param name="callerId">The caller id to find.</param>
    /// <exception cref="KeyNotFoundException">The caller is not configured.</exception>
    public CallerDefinition Get(string callerId) => _callers[callerId];
}
