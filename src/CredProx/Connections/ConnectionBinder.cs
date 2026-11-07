using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CredProx;

/// <summary>
/// Binds every <c>CredProx:Connections:&lt;name&gt;</c> section at startup into a
/// <see cref="ConnectionRegistry"/> (see <c>docs/credprox-plan.md</c> §3.2/§5.2): the
/// client certificate secret is resolved and loaded immediately, so a missing secret or a
/// wrong password fails startup with one clear <see cref="OptionsValidationException"/>
/// naming the connection and reference — never the value or the password. Keys other than
/// <c>ClientCertificate</c> and <c>ClientCertificatePassword</c> are rejected too (M17,
/// §3.3), at startup and on rebind.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class ConnectionBinder
{
    private readonly IConfiguration _configuration;
    private readonly SecretAccessorFactory _accessorFactory;
    private readonly ILoggerFactory _loggerFactory;

    /// <summary>Creates the binder.</summary>
    /// <param name="configuration">The application configuration root.</param>
    /// <param name="accessorFactory">Scopes each connection to its own secret references.</param>
    /// <param name="loggerFactory">Loggers for post-startup rotation failures.</param>
    public ConnectionBinder(
        IConfiguration configuration,
        SecretAccessorFactory accessorFactory,
        ILoggerFactory loggerFactory)
    {
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        _accessorFactory = accessorFactory ?? throw new ArgumentNullException(nameof(accessorFactory));
        _loggerFactory = loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory));
    }

    /// <summary>
    /// Binds and loads every configured connection.
    /// </summary>
    /// <exception cref="OptionsValidationException">
    /// A connection declares no certificate, or its certificate cannot be resolved or
    /// loaded (including a wrong password).
    /// </exception>
    public ConnectionRegistry Bind()
    {
        var errors = new List<string>();
        var connections = new Dictionary<string, ClientCertificateConnection>(StringComparer.OrdinalIgnoreCase);

        foreach (var section in _configuration.GetSection("CredProx:Connections").GetChildren())
        {
            if (!RejectUnknownKeys(section, errors))
            {
                continue;
            }

            if (TryBindOne(section, errors, out var connection))
            {
                connections[section.Key] = connection;
            }
        }

        if (errors.Count > 0)
        {
            throw new OptionsValidationException("CredProx", typeof(object), errors);
        }

        return new ConnectionRegistry(connections);
    }

    /// <summary>
    /// Rebinds after a configuration change (the config-reload story, M5): new and changed
    /// connections bind fresh (loaded eagerly, so a bad new certificate fails the rebind),
    /// removed ones drop out, and a connection whose <c>ClientCertificate</c> and
    /// <c>ClientCertificatePassword</c> references are unchanged keeps its existing object —
    /// its <see cref="ClientCertificateConnection.Version"/> stays monotonic for the client
    /// factory's reuse stamp, and a rotated secret value is picked up by
    /// <see cref="ClientCertificateConnection.Refresh"/> on that same object.
    /// </summary>
    /// <param name="previous">The registry the provider is serving.</param>
    /// <exception cref="OptionsValidationException">
    /// A new or changed connection fails to bind; the caller keeps the previous registry.
    /// </exception>
    public ConnectionRegistry Rebind(ConnectionRegistry previous)
    {
        ArgumentNullException.ThrowIfNull(previous);

        var errors = new List<string>();
        var connections = new Dictionary<string, ClientCertificateConnection>(StringComparer.OrdinalIgnoreCase);

        foreach (var section in _configuration.GetSection("CredProx:Connections").GetChildren())
        {
            // M17: rejected before the reuse path — a typo arriving in a reload fails the
            // rebind even when the certificate references are unchanged (the reuse path
            // would otherwise never inspect the section's keys).
            if (!RejectUnknownKeys(section, errors))
            {
                continue;
            }

            var certificateReference = section["ClientCertificate"];
            if (!string.IsNullOrWhiteSpace(certificateReference)
                && previous.TryGet(section.Key, out var existing)
                && string.Equals(existing.CertificateReference, certificateReference, StringComparison.Ordinal)
                && existing.PasswordReference == section["ClientCertificatePassword"])
            {
                connections[section.Key] = existing;
                continue;
            }

            if (TryBindOne(section, errors, out var connection))
            {
                connections[section.Key] = connection;
            }
        }

        if (errors.Count > 0)
        {
            throw new OptionsValidationException("CredProx", typeof(object), errors);
        }

        return new ConnectionRegistry(connections);
    }

    // The only keys the binder consumes (M17, §3.3): both are read as single values, so a
    // block nested under one is rejected like under any other scalar.
    private static readonly IReadOnlyDictionary<string, Type?> AllowedKeys =
        new Dictionary<string, Type?>(StringComparer.OrdinalIgnoreCase)
        {
            ["ClientCertificate"] = null,
            ["ClientCertificatePassword"] = null,
        };

    // M17 (§3.3): the binder reads exactly the two keys above; anything else under the
    // section is dropped in silence — rejected at startup and on rebind (the provider keeps
    // the previous registry on a failed rebind). Returns false when problems were appended.
    private static bool RejectUnknownKeys(IConfigurationSection section, List<string> errors)
    {
        var before = errors.Count;
        ConfigKeyValidator.RejectUnknownKeys(
            section, AllowedKeys, $"connection '{section.Key}'", $"CredProx:Connections:{section.Key}", errors);
        return errors.Count == before;
    }

    private bool TryBindOne(IConfigurationSection section, List<string> errors, out ClientCertificateConnection connection)
    {
        var name = section.Key;
        var certificateReference = section["ClientCertificate"];
        if (string.IsNullOrWhiteSpace(certificateReference))
        {
            errors.Add($"The connection '{name}' has no ClientCertificate.");
            connection = null!;
            return false;
        }

        var secrets = _accessorFactory.CreateAccessor(section);
        connection = new ClientCertificateConnection(
            name,
            secrets,
            certificateReference,
            section["ClientCertificatePassword"],
            _loggerFactory.CreateLogger<ClientCertificateConnection>());

        try
        {
            // Load now: a wrong password or missing secret is a startup failure (§5.2
            // "Connections"), not a surprise on first connection.
            connection.LoadAsync(CancellationToken.None).AsTask().GetAwaiter().GetResult();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            errors.Add($"The connection '{name}' could not load its ClientCertificate: {ex.Message}");
            return false;
        }

        return true;
    }
}
