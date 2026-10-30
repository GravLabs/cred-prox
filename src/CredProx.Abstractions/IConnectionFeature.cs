using System.Diagnostics.CodeAnalysis;
using System.Net.Http;

namespace CredProx.Abstractions;

/// <summary>
/// A feature that configures the outbound HTTP connection for a cluster. Applied in
/// <c>ForwarderHttpClientFactory.ConfigureHandler</c> and bound to a cluster
/// (for example a client certificate for mTLS).
/// </summary>
[Experimental("CREDPROX001")]
public interface IConnectionFeature
{
    /// <summary>
    /// Configures the cluster's outbound <see cref="SocketsHttpHandler"/>. Called when the
    /// client is created or rebuilt (for example after a client-certificate secret rotates).
    /// </summary>
    /// <param name="handler">The handler to configure.</param>
    void ConfigureHandler(SocketsHttpHandler handler);
}
