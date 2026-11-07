using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

namespace CredProx;

/// <summary>
/// Holds the live <see cref="DestinationRegistry"/> and rebinds it when the secret source's
/// change token fires (the config-reload story, M5): a reload that adds a destination
/// makes it resolvable without a restart, and one that removes a destination takes it out.
/// Destination entries are plain data, so a rebind replaces the whole registry. A rebind
/// that fails keeps the previous registry and logs: a bad reload must not take down a
/// running proxy.
/// </summary>
/// <remarks>
/// The initial bind happens in the constructor — the startup validator resolves this
/// service, so destination configuration is fully validated before the proxy serves
/// traffic. The change signal is <see cref="ISecretSource.GetChangeToken"/>, the same
/// reload signal the credential and connection registries follow.
/// </remarks>
[Experimental("CREDPROX001")]
public sealed class DestinationRegistryProvider
{
    private readonly DestinationBinder _binder;
    private readonly ILogger<DestinationRegistryProvider> _logger;
    private volatile DestinationRegistry _current;

    /// <summary>Creates the provider and performs the initial bind.</summary>
    /// <param name="binder">The destination binder.</param>
    /// <param name="secretSource">The source whose change token triggers a rebind.</param>
    /// <param name="logger">Logs rebind outcomes.</param>
    /// <exception cref="Microsoft.Extensions.Options.OptionsValidationException">
    /// The initial bind fails — startup fails.
    /// </exception>
    public DestinationRegistryProvider(
        DestinationBinder binder,
        ISecretSource secretSource,
        ILogger<DestinationRegistryProvider> logger)
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
    public DestinationRegistry Current => _current;

    private void Rebind()
    {
        try
        {
            _current = _binder.Bind();
            _logger.LogInformation("CredProx destinations rebound after a configuration change.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(
                ex,
                "CredProx destinations failed to rebind after a configuration change; keeping the previous registry.");
        }
    }
}
