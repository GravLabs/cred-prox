using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// One <c>CredProx:Destinations:&lt;name&gt;</c> entry, bound at startup
/// (see <c>docs/credprox-plan.md</c> §3.2): the address template, the bound partition
/// source with its allow-list, and whether the partition header is stripped before
/// forwarding.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class DestinationEntry
{
    internal DestinationEntry(string name, DestinationDefinition definition, PartitionSourceBinding? partition)
    {
        Name = name;
        Definition = definition;
        Partition = partition;
    }

    /// <summary>The destination name from configuration.</summary>
    public string Name { get; }

    /// <summary>The configured definition.</summary>
    public DestinationDefinition Definition { get; }

    /// <summary>The bound partition source, or <see langword="null"/> for a static destination.</summary>
    public PartitionSourceBinding? Partition { get; }

    /// <summary>
    /// Expands the address template for an <em>already admitted</em> partition value.
    /// Callers must resolve through <see cref="Partition"/> first — this method performs
    /// no validation of its own.
    /// </summary>
    /// <param name="partition">The partition value that passed the allow-list.</param>
    /// <returns>The outbound destination prefix.</returns>
    public string ResolvePrefix(string partition)
    {
        ArgumentNullException.ThrowIfNull(partition);

        return Definition.Template!.Replace("{partition}", partition, StringComparison.Ordinal);
    }
}

/// <summary>
/// The bound <c>CredProx:Destinations</c> section, keyed by name. Built once by
/// <see cref="DestinationBinder"/> at startup; the request pipeline looks entries up by
/// the route metadata reference <c>CredProx.Destination</c>.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class DestinationRegistry
{
    private readonly Dictionary<string, DestinationEntry> _entries;

    internal DestinationRegistry(Dictionary<string, DestinationEntry> entries)
    {
        _entries = entries;
    }

    /// <summary>The configured destination names.</summary>
    public IEnumerable<string> Names => _entries.Keys.Order(StringComparer.OrdinalIgnoreCase);

    /// <summary>Looks up a destination by name (case-insensitive, like configuration keys).</summary>
    /// <param name="name">The destination name from route metadata.</param>
    /// <param name="entry">The entry when found.</param>
    /// <returns><see langword="true"/> when the name is configured.</returns>
    public bool TryGet(string name, [NotNullWhen(true)] out DestinationEntry? entry) =>
        _entries.TryGetValue(name, out entry);

    /// <summary>
    /// Looks up a destination, failing with a clear message when the name is not configured
    /// (a metadata reference that survived startup validation).
    /// </summary>
    /// <param name="name">The destination name from route metadata.</param>
    /// <exception cref="InvalidOperationException">No destination has that name.</exception>
    public DestinationEntry Get(string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        return TryGet(name, out var entry)
            ? entry
            : throw new InvalidOperationException(
                $"The destination '{name}' is not configured under CredProx:Destinations.");
    }
}
