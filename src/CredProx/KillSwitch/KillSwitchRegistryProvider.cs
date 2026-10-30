using CredProx.Abstractions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

namespace CredProx;

/// <summary>
/// Holds the live <see cref="KillSwitchRegistry"/> (M18, plan §8.4) and rebinds it when the
/// secret source's change token fires — the same config-reload story as the other
/// registries, because flipping a switch is exactly a configuration change. A rebind that
/// fails keeps the previous switch state and logs: a typo introduced by a reload must not
/// silently re-enable a vendor the operator had taken out of service, and must not drop
/// the whole switch either — the last known-good state keeps guarding.
/// </summary>
internal sealed class KillSwitchRegistryProvider
{
    private readonly KillSwitchBinder _binder;
    private readonly ILogger<KillSwitchRegistryProvider> _logger;
    private volatile KillSwitchRegistry _current;

    /// <summary>Creates the provider and performs the initial bind.</summary>
    /// <param name="binder">The kill-switch binder.</param>
    /// <param name="secretSource">The source whose change token triggers a rebind.</param>
    /// <param name="logger">Logs rebind outcomes; messages count ids, never carry values.</param>
    /// <exception cref="Microsoft.Extensions.Options.OptionsValidationException">
    /// The initial bind fails — startup fails.
    /// </exception>
    public KillSwitchRegistryProvider(
        KillSwitchBinder binder,
        ISecretSource secretSource,
        ILogger<KillSwitchRegistryProvider> logger)
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

    /// <summary>The switch state to serve requests from; swapped atomically on rebind.</summary>
    public KillSwitchRegistry Current => _current;

    private void Rebind()
    {
        try
        {
            _current = _binder.Bind();
            _logger.LogInformation(
                "CredProx kill switch rebound: {Clusters} cluster(s) and {Callers} caller(s) out of service.",
                _current.DisabledClusterCount,
                _current.DisabledCallerCount);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(
                ex,
                "CredProx kill switch failed to rebind after a configuration change; keeping the previous switch state.");
        }
    }
}
