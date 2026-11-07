using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;

namespace CredProx;

/// <summary>
/// Creates <see cref="ScopedSecretAccessor"/> instances whose allowed reference set is
/// extracted from a plugin's own configuration section, enforcing the secret scoping rule
/// (see <c>docs/credprox-plan.md</c> §3.5 rule 4).
/// </summary>
[Experimental("CREDPROX001")]
public sealed class SecretAccessorFactory
{
    private readonly ISecretSource _source;

    /// <summary>
    /// Creates the factory over the given secret source.
    /// </summary>
    /// <param name="source">The secret source the created accessors resolve through.</param>
    public SecretAccessorFactory(ISecretSource source)
    {
        _source = source ?? throw new ArgumentNullException(nameof(source));
    }

    /// <summary>
    /// Creates an accessor scoped to the <c>secret:</c> references used under
    /// <paramref name="pluginSection"/>. A reference declared with <c>{placeholder}</c>
    /// segments scopes to its declared shape (see <see cref="ScopedSecretAccessor"/>).
    /// </summary>
    /// <param name="pluginSection">The plugin's own configuration section.</param>
    /// <returns>An accessor scoped to that section's references.</returns>
    /// <remarks>
    /// The extracted allow-list is a snapshot of the section as it stands now; recreate the
    /// accessor after a configuration reload that changes the section's references.
    /// </remarks>
    public ScopedSecretAccessor CreateAccessor(IConfigurationSection pluginSection)
    {
        ArgumentNullException.ThrowIfNull(pluginSection);

        return new ScopedSecretAccessor(_source, SecretReferences.FindInSection(pluginSection));
    }
}
