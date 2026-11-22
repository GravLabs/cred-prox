using System.Diagnostics.CodeAnalysis;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;

namespace CredProx;

/// <summary>
/// Gives every <c>credprox-token:&lt;name&gt;</c> named client (see
/// <see cref="CredProxHttpClientNames"/>) a primary handler carrying that connection's
/// client certificate: a credential's
/// <c>Connection</c> makes the token call present that connection's certificate.
/// </summary>
/// <remarks>
/// <para>
/// The handler is built from the <em>live</em> connection registry at handler-creation
/// time, not from a registration-time snapshot: a connection added by a configuration
/// reload gets its certificate-carrying client without a restart.
/// <see cref="IHttpClientFactory"/> recreates primary handlers on their expiry, so a
/// rotated certificate is picked up the same way.
/// </para>
/// <para>
/// The filter owns the <c>credprox-token:</c> name space for the primary handler and
/// sets it after the client's own configuration, so a per-connection client always
/// presents the connection's certificate. A name whose connection is not (or no longer)
/// configured fails when its handler is built — the token call surfaces the failure
/// rather than silently presenting no certificate.
/// </para>
/// <para>
/// It also owns the default User-Agent for the whole <c>credprox-token</c> name space —
/// the plain client and every <c>credprox-token:&lt;name&gt;</c> client alike (product
/// bug 2026-11-22: GitHub answers a UA-less token exchange 403 at its administrative
/// edge, before any credential is read). The stamp is appended after the client's own
/// configuration and stamps only when the request carries no User-Agent, so a host's
/// explicit value always wins; the plain client's primary handler stays whatever the
/// client's own registration configured.
/// </para>
/// </remarks>
[Experimental("CREDPROX001")]
public sealed class CredProxTokenClientFilter : IHttpMessageHandlerBuilderFilter
{
    /// <inheritdoc />
    public Action<HttpMessageHandlerBuilder> Configure(Action<HttpMessageHandlerBuilder> next)
    {
        ArgumentNullException.ThrowIfNull(next);

        return builder =>
        {
            ArgumentNullException.ThrowIfNull(builder);

            next(builder);

            if (builder.Name is not { } clientName)
            {
                return;
            }

            if (!clientName.StartsWith(CredProxHttpClientNames.ConnectionPrefix, StringComparison.Ordinal))
            {
                // The plain token client gets the default User-Agent and nothing else —
                // its primary handler stays exactly what its own registration configured.
                if (string.Equals(clientName, CredProxHttpClientNames.TokenClient, StringComparison.Ordinal))
                {
                    builder.AdditionalHandlers.Add(new CredProxUserAgentHandler());
                }

                return;
            }

            var connectionName = clientName[CredProxHttpClientNames.ConnectionPrefix.Length..];
            var registry = builder.Services?.GetService<ConnectionRegistry>()
                ?? throw new InvalidOperationException(
                    "The CredProx connection registry is not registered; call AddCredProx(configuration) "
                    + $"to serve the token client for connection '{connectionName}'.");

            var connection = registry.Get(connectionName);
            connection.Refresh();
            builder.PrimaryHandler = new SocketsHttpHandler
            {
                // Credential acquisition never follows redirects (M45 security finding F-1):
                // a 3xx from a token/metadata endpoint must reach the provider as a refusal,
                // not as some other host's response.
                AllowAutoRedirect = false,
                SslOptions = { ClientCertificates = new X509Certificate2Collection(connection.Certificate) },
            };
            builder.AdditionalHandlers.Add(new CredProxRedirectGuard());
            builder.AdditionalHandlers.Add(new CredProxUserAgentHandler());
        };
    }
}
