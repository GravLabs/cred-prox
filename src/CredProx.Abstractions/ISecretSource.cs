using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Primitives;

namespace CredProx.Abstractions;

/// <summary>
/// Resolves secret references (for example <c>secret:name</c>) to their values.
/// A plugin never sees a source directly; it receives an <see cref="ISecretAccessor"/>
/// scoped to its own configuration.
/// </summary>
[Experimental("CREDPROX001")]
public interface ISecretSource
{
    /// <summary>
    /// The reference scheme this source handles, for example <c>secret</c> for
    /// <c>secret:name</c> references.
    /// </summary>
    string Scheme { get; }

    /// <summary>
    /// Resolves <paramref name="name"/> to its secret value, or returns <see langword="null"/>
    /// when this source does not define that name.
    /// </summary>
    /// <param name="name">The reference name, without the scheme prefix.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    ValueTask<string?> GetSecretAsync(string name, CancellationToken cancellationToken);

    /// <summary>
    /// A token that fires when any secret resolved by this source changes, so consumers
    /// (for example a client certificate held by a connection feature) can be rebuilt.
    /// </summary>
    IChangeToken GetChangeToken();
}
