using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Configuration;
using Yarp.ReverseProxy.Configuration;

namespace CredProx;

/// <summary>
/// The CredProx <see cref="IConfigValidator"/> (the config-reload story, M5, note N1):
/// YARP runs every registered validator when it loads the proxy configuration — at startup
/// and on every reload — and rejects a load whose validation fails, keeping the previously
/// applied configuration serving. This closes the gap where the startup gate was one-shot:
/// a reload introducing an unknown <c>CredProx.Credential</c>, <c>CredProx.Destination</c>
/// or <c>CredProx.Connection</c> reference is refused with the same clear messages as
/// startup (§5.2 "Validation"), instead of failing per request afterwards.
/// </summary>
/// <remarks>
/// <para>
/// Checks run against the <em>live</em> registries (the reload-aware providers), so a
/// reload that adds a connection and a route referencing it in the same change validates.
/// A reference the registry does not (yet) have is accepted when the current configuration
/// declares it: the registry rebind and YARP's configuration load are both triggered by the
/// same reload, and the validator must not reject a load over a rebind that has not landed
/// this instant. A reference missing from both is refused.
/// </para>
/// <para>
/// Messages name references, never values.
/// </para>
/// </remarks>
[Experimental("CREDPROX001")]
public sealed class CredProxConfigValidator : IConfigValidator
{
    private readonly CredentialRegistryProvider _credentials;
    private readonly DestinationRegistryProvider _destinations;
    private readonly ConnectionRegistryProvider _connections;
    private readonly IConfiguration _configuration;

    /// <summary>Creates the validator over the live registries and the live configuration.</summary>
    /// <param name="credentials">The reload-aware credential registry.</param>
    /// <param name="destinations">The reload-aware destination registry.</param>
    /// <param name="connections">The reload-aware connection registry.</param>
    /// <param name="configuration">The application configuration root.</param>
    public CredProxConfigValidator(
        CredentialRegistryProvider credentials,
        DestinationRegistryProvider destinations,
        ConnectionRegistryProvider connections,
        IConfiguration configuration)
    {
        _credentials = credentials ?? throw new ArgumentNullException(nameof(credentials));
        _destinations = destinations ?? throw new ArgumentNullException(nameof(destinations));
        _connections = connections ?? throw new ArgumentNullException(nameof(connections));
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
    }

    /// <inheritdoc />
    public ValueTask<IList<Exception>> ValidateRouteAsync(RouteConfig route)
    {
        ArgumentNullException.ThrowIfNull(route);

        var errors = new List<Exception>();
        var metadata = route.Metadata;
        if (metadata is not null)
        {
            if (metadata.TryGetValue(CredProxMetadata.Credential, out var credentialName)
                && !string.IsNullOrEmpty(credentialName))
            {
                var binding = _credentials.Current.TryGet(credentialName, out var found) ? found : null;
                var declaredInConfig = _configuration
                    .GetSection("CredProx:Credentials").GetSection(credentialName).GetChildren().Any();

                if (binding is null && !declaredInConfig)
                {
                    errors.Add(new InvalidOperationException(
                        $"Route '{route.RouteId}' references unknown credential '{credentialName}' in {CredProxMetadata.Credential}."));
                }
                else
                {
                    // The Connection reference comes from the bound credential when it is
                    // live, else straight from the configuration the load is built on.
                    var connectionName = binding?.ConnectionName
                        ?? _configuration[$"CredProx:Credentials:{credentialName}:Connection"];
                    if (!string.IsNullOrEmpty(connectionName) && !ConnectionExists(connectionName))
                    {
                        errors.Add(new InvalidOperationException(
                            $"The credential '{credentialName}' references unknown connection '{connectionName}' in its Connection option."));
                    }
                }
            }

            if (metadata.TryGetValue(CredProxMetadata.Destination, out var destinationName)
                && !string.IsNullOrEmpty(destinationName)
                && !_destinations.Current.TryGet(destinationName, out _)
                && !_configuration.GetSection("CredProx:Destinations").GetSection(destinationName).GetChildren().Any())
            {
                errors.Add(new InvalidOperationException(
                    $"Route '{route.RouteId}' references unknown destination '{destinationName}' in {CredProxMetadata.Destination}."));
            }
        }

        return new ValueTask<IList<Exception>>(errors);
    }

    /// <inheritdoc />
    public ValueTask<IList<Exception>> ValidateClusterAsync(ClusterConfig cluster)
    {
        ArgumentNullException.ThrowIfNull(cluster);

        var errors = new List<Exception>();
        if (cluster.Metadata is { } metadata
            && metadata.TryGetValue(CredProxMetadata.Connection, out var connectionName)
            && !string.IsNullOrEmpty(connectionName)
            && !ConnectionExists(connectionName))
        {
            errors.Add(new InvalidOperationException(
                $"Cluster '{cluster.ClusterId}' references unknown connection '{connectionName}' in {CredProxMetadata.Connection}."));
        }

        return new ValueTask<IList<Exception>>(errors);
    }

    private bool ConnectionExists(string connectionName) =>
        _connections.Current.TryGet(connectionName, out _)
        || _configuration.GetSection("CredProx:Connections").GetSection(connectionName).GetChildren().Any();
}
