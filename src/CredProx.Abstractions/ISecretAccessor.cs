using System.Diagnostics.CodeAnalysis;

namespace CredProx.Abstractions;

/// <summary>
/// A secret accessor scoped to a single plugin instance: it resolves only the
/// <c>secret:</c> references named in that plugin's own configuration
/// (see <c>docs/credprox-plan.md</c> §3.5 rule 4). A buggy or malicious plugin cannot
/// read other integrations' secrets through it.
/// </summary>
[Experimental("CREDPROX001")]
public interface ISecretAccessor
{
    /// <summary>
    /// Resolves a secret reference to its value.
    /// </summary>
    /// <param name="name">The reference name, for example <c>secret:adp-client-secret</c>.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <exception cref="InvalidOperationException">
    /// <paramref name="name"/> is outside the configuration of the plugin this accessor was
    /// created for, or it does not resolve. The message names the reference, never a value.
    /// </exception>
    ValueTask<string> GetSecretAsync(string name, CancellationToken cancellationToken);
}
