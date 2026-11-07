using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

namespace CredProx;

/// <summary>
/// Holds the live <see cref="ConnectionRegistry"/> and rebinds it when the secret source's
/// change token fires (the config-reload story, M5): a reload that adds a connection makes
/// it resolvable without a restart, and one that removes a connection takes it out.
/// Rebinding is incremental — a connection whose <c>ClientCertificate</c> and
/// <c>ClientCertificatePassword</c> references are unchanged keeps its existing
/// <see cref="ClientCertificateConnection"/> object, so its <see cref="ClientCertificateConnection.Version"/>
/// stays monotonic (the client factory's reuse stamp depends on it) and a rotated secret
/// value is picked up by <see cref="ClientCertificateConnection.Refresh"/> on the same
/// object. A rebind that fails keeps the previous registry and logs: a bad reload must not
/// take down a running proxy.
/// </summary>
/// <remarks>
/// The initial bind happens in the constructor — the startup validator resolves this
/// service, so connection configuration is fully validated before the proxy serves
/// traffic.
/// </remarks>
[Experimental("CREDPROX001")]
public sealed class ConnectionRegistryProvider
{
    private readonly ConnectionBinder _binder;
    private readonly ILogger<ConnectionRegistryProvider> _logger;
    private volatile ConnectionRegistry _current;

    /// <summary>Creates the provider and performs the initial bind.</summary>
    /// <param name="binder">The connection binder.</param>
    /// <param name="secretSource">The source whose change token triggers a rebind.</param>
    /// <param name="logger">Logs rebind outcomes; messages name references, never values.</param>
    /// <exception cref="Microsoft.Extensions.Options.OptionsValidationException">
    /// The initial bind fails — startup fails.
    /// </exception>
    public ConnectionRegistryProvider(
        ConnectionBinder binder,
        ISecretSource secretSource,
        ILogger<ConnectionRegistryProvider> logger)
    {
        ArgumentNullException.ThrowIfNull(binder);
        ArgumentNullException.ThrowIfNull(secretSource);
        ArgumentNullException.ThrowIfNull(logger);

        _binder = binder;
        _logger = logger;
        _current = binder.Bind();

        // ChangeToken.OnChange re-arms, so this keeps firing across reloads; the
        // registration lives as long as this singleton.
        ChangeToken.OnChange(secretSource.GetChangeToken, Rebind);
    }

    /// <summary>The registry to serve requests from; swapped atomically on rebind.</summary>
    public ConnectionRegistry Current => _current;

    private void Rebind()
    {
        try
        {
            _current = _binder.Rebind(_current);
            _logger.LogInformation("CredProx connections rebound after a configuration change.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(
                ex,
                "CredProx connections failed to rebind after a configuration change; keeping the previous registry.");
        }
    }
}
