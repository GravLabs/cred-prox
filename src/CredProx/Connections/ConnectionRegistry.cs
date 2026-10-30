using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// The startup-bound <c>CredProx:Connections</c> section, keyed by name. Built by
/// <see cref="ConnectionBinder"/>; referenced by cluster metadata
/// <c>CredProx.Connection</c> and by a credential's <c>Connection</c> option (§3.2).
/// </summary>
[Experimental("CREDPROX001")]
public sealed class ConnectionRegistry
{
    private readonly Dictionary<string, ClientCertificateConnection> _connections;

    internal ConnectionRegistry(Dictionary<string, ClientCertificateConnection> connections)
    {
        _connections = connections;
    }

    /// <summary>The configured connection names.</summary>
    public IEnumerable<string> Names => _connections.Keys.Order(StringComparer.OrdinalIgnoreCase);

    /// <summary>Looks up a connection by name (case-insensitive, like configuration keys).</summary>
    /// <param name="name">The connection name.</param>
    /// <param name="connection">The connection when found.</param>
    /// <returns><see langword="true"/> when the name is configured.</returns>
    public bool TryGet(string name, [NotNullWhen(true)] out ClientCertificateConnection? connection) =>
        _connections.TryGetValue(name, out connection);

    /// <summary>
    /// Looks up a connection, failing with a clear message when the name is not configured
    /// (a reference that survived startup validation).
    /// </summary>
    /// <param name="name">The connection name.</param>
    /// <exception cref="InvalidOperationException">No connection has that name.</exception>
    public ClientCertificateConnection Get(string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        return TryGet(name, out var connection)
            ? connection
            : throw new InvalidOperationException(
                $"The connection '{name}' is not configured under CredProx:Connections.");
    }
}
