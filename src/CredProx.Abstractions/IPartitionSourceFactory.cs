using System.Diagnostics.CodeAnalysis;

namespace CredProx.Abstractions;

/// <summary>
/// Creates <see cref="IPartitionSource"/> instances for one partition-spec scheme
/// (see <c>docs/credprox-plan.md</c> §3.2: <c>"Partition": "header:X-API-Env"</c>).
/// The core binds a destination's or credential's <c>Partition</c> value by splitting it
/// at the first <c>:</c> into a scheme and an argument, then asks the factory registered
/// for that scheme to create the source. Built-ins in 0.3: <c>header:</c> (M4);
/// <c>claim:</c>, <c>caller:</c> and <c>route:</c> arrive with caller identity (M6).
/// </summary>
/// <remarks>
/// Factories are registered explicitly in DI (§3.5 rule 6). A configuration value naming
/// an unregistered scheme fails startup — there is no fallback source.
/// </remarks>
[Experimental("CREDPROX001")]
public interface IPartitionSourceFactory
{
    /// <summary>
    /// The scheme this factory handles — the part before the first <c>:</c> in a partition
    /// spec, for example <c>header</c>. Compared case-insensitively.
    /// </summary>
    string Scheme { get; }

    /// <summary>
    /// Creates the source for one spec's argument (for <c>header:X-API-Env</c> the
    /// argument is <c>X-API-Env</c>).
    /// </summary>
    /// <param name="argument">The part after the first <c>:</c>; never <see langword="null"/>, may be empty.</param>
    /// <returns>The source to resolve partitions with.</returns>
    IPartitionSource CreateSource(string argument);
}
