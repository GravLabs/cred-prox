using System.Diagnostics.CodeAnalysis;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;

namespace CredProx;

/// <summary>
/// Gives every <c>credprox-token:&lt;name&gt;</c> named client (see
/// <see cref="CredProxHttpClientNames"/>) a primary handler carrying that connection's
/// client certificate (see <c>docs/credprox-plan.md</c> §3.2: a credential's
/// <c>Connection</c> makes the token call present that connection's certificate).
/// </summary>
/// <remarks>
/// <para>
/// The handler is built from the <em>live</em> connection registry at handler-creation
/// time, not from a registration-time snapshot: a connection added by a configuration
/// reload gets its certificate-carrying client without a restart (M5 note N2).
/// <see cref="IHttpClientFactory"/> recreates primary handlers on their expiry, so a
/// rotated certificate is picked up the same way.
/// </para>
/// <para>
/// The filter owns the <c>credprox-token:</c> name space and sets the primary handler
/// after the client's own configuration, so a per-connection client always presents the
/// connection's certificate. A name whose connection is not (or no longer) configured
/// fails when its handler is built — the token call surfaces the failure rather than
/// silently presenting no certificate.
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

            if (builder.Name is not { } clientName
                || !clientName.StartsWith(CredProxHttpClientNames.ConnectionPrefix, StringComparison.Ordinal))
            {
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
                SslOptions = { ClientCertificates = new X509Certificate2Collection(connection.Certificate) },
            };
        };
    }
}
