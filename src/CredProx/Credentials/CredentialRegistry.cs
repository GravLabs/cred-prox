using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// The startup-bound set of credentials, keyed by configuration name. Built once by
/// <see cref="CredentialBinder"/>; lookups are the request path's only access to providers.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class CredentialRegistry
{
    private readonly Dictionary<string, CredentialBinding> _bindings;

    internal CredentialRegistry(Dictionary<string, CredentialBinding> bindings)
    {
        _bindings = bindings;
    }

    /// <summary>The configured credential names.</summary>
    public IEnumerable<string> Names => _bindings.Keys.Order(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Looks up a credential binding by name (case-insensitive, like configuration keys).
    /// </summary>
    /// <param name="name">The credential name from route metadata.</param>
    /// <param name="binding">The binding when found.</param>
    /// <returns><see langword="true"/> when the name is configured.</returns>
    public bool TryGet(string name, [NotNullWhen(true)] out CredentialBinding? binding) =>
        _bindings.TryGetValue(name, out binding);

    /// <summary>
    /// Looks up a credential binding, failing with a clear message when the name is not
    /// configured (a metadata reference that survived startup validation).
    /// </summary>
    /// <param name="name">The credential name from route metadata.</param>
    /// <exception cref="InvalidOperationException">No credential has that name.</exception>
    public CredentialBinding Get(string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        return TryGet(name, out var binding)
            ? binding
            : throw new InvalidOperationException(
                $"The credential '{name}' is not configured under CredProx:Credentials.");
    }
}
