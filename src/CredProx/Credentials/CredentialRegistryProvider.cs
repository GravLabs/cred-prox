using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

namespace CredProx;

/// <summary>
/// Holds the live <see cref="CredentialRegistry"/> and rebinds it when the secret source's
/// change token fires (see <c>docs/credprox-plan.md</c> §3.3: config reload). Rebinding
/// recreates each credential's scoped <see cref="ISecretAccessor"/>, so a reload that adds
/// a <c>secret:</c> reference to a credential's section takes effect without a restart —
/// the accessor allow-lists are snapshots by design (M2 review carry). A rebind that fails
/// keeps the previous registry and logs: a bad reload must not take down a running proxy.
/// </summary>
/// <remarks>
/// The initial bind happens in the constructor — the startup validator resolves this
/// service, so credential configuration is fully validated before the proxy serves
/// traffic (M3 review carry: no lazy first-request binding).
/// </remarks>
[Experimental("CREDPROX001")]
public sealed class CredentialRegistryProvider
{
    private volatile CredentialRegistry _current;

    /// <summary>Creates the provider and performs the initial bind.</summary>
    /// <param name="binder">The credential binder.</param>
    /// <param name="secretSource">The source whose change token triggers a rebind.</param>
    /// <param name="logger">Logs rebind outcomes; messages name references, never values.</param>
    /// <exception cref="Microsoft.Extensions.Options.OptionsValidationException">
    /// The initial bind fails — startup fails.
    /// </exception>
    public CredentialRegistryProvider(
        CredentialBinder binder,
        ISecretSource secretSource,
        ILogger<CredentialRegistryProvider> logger)
    {
        ArgumentNullException.ThrowIfNull(binder);
        ArgumentNullException.ThrowIfNull(secretSource);
        ArgumentNullException.ThrowIfNull(logger);

        _current = binder.Bind();

        // ChangeToken.OnChange re-arms, so this keeps firing across reloads; the
        // registration lives as long as this singleton.
        ChangeToken.OnChange(secretSource.GetChangeToken, () =>
        {
            try
            {
                _current = binder.Bind();
                logger.LogInformation("CredProx credentials rebound after a configuration change.");
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(
                    ex,
                    "CredProx credentials failed to rebind after a configuration change; keeping the previous registry.");
            }
        });
    }

    /// <summary>The registry to serve requests from; swapped atomically on rebind.</summary>
    public CredentialRegistry Current => _current;
}
