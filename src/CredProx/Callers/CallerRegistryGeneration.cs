using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// One committed unit of caller state: an accepted <see cref="CallerRegistry"/> and the
/// data every <see cref="ICallerRegistryContributor"/> built against it, bound together by
/// the bind that accepted them. The provider swaps the live generation atomically, so
/// readers take the registry and all contributed data as one snapshot — derived data can
/// never drift from the registry it was built against. Every accepted configuration change
/// commits a new generation (even when the core registry part is unchanged, the
/// contributors rebuild against the new registry instance); a refused change commits
/// nothing and the previous generation keeps serving in full.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class CallerRegistryGeneration
{
    private readonly Dictionary<Type, object> _contributed;

    internal CallerRegistryGeneration(
        CallerRegistry registry,
        Dictionary<Type, object> contributed)
    {
        Registry = registry;
        _contributed = contributed;
    }

    /// <summary>The registry this generation committed.</summary>
    public CallerRegistry Registry { get; }

    /// <summary>
    /// Gets the data the contributor of type <typeparamref name="TContributor"/> committed
    /// with this generation.
    /// </summary>
    /// <typeparam name="TContributor">The contributor whose data to read.</typeparam>
    /// <param name="data">The committed data, when this generation has it.</param>
    /// <returns><see langword="true"/> when the contributor ran in the bind that produced this generation.</returns>
    public bool TryGetContributed<TContributor>([NotNullWhen(true)] out object? data)
        where TContributor : ICallerRegistryContributor =>
        _contributed.TryGetValue(typeof(TContributor), out data);
}
