using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// Names of the named <see cref="IHttpClientFactory"/> clients CredProx registers and
/// providers use for token/login calls (see <c>docs/credprox-plan.md</c> §3.2: a
/// credential's <c>Connection</c> makes the token call present that connection's client
/// certificate). A credential with a connection gets the per-connection client, whose
/// primary handler carries the certificate; custom credential types can use this helper
/// with their own <c>Connection</c> option.
/// </summary>
[Experimental("CREDPROX001")]
public static class CredProxHttpClientNames
{
    /// <summary>The client used when a credential declares no <c>Connection</c>.</summary>
    public const string TokenClient = "credprox-token";

    /// <summary>The suffix marking a per-connection token client.</summary>
    public const string ConnectionPrefix = "credprox-token:";

    /// <summary>
    /// The token/login client name for a credential: the plain one when
    /// <paramref name="connection"/> is null or empty, the connection's otherwise.
    /// </summary>
    /// <param name="connection">The credential's <c>Connection</c> option value.</param>
    /// <returns>The registered client name.</returns>
    public static string ForConnection(string? connection) =>
        string.IsNullOrEmpty(connection) ? TokenClient : ConnectionPrefix + connection;
}
