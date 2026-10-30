using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

namespace CredProx;

/// <summary>
/// Holds the live <see cref="CallerRegistry"/> and rebinds it when the secret source's
/// change token fires (the config-reload story applied to M6): adding a caller, rotating a
/// key (add the new key, then remove the old one) or revoking a key all take effect
/// without a restart. A rebind that fails keeps the previous registry and logs — a bad
/// reload must not turn a running proxy into one that authenticates nobody.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class CallerRegistryProvider
{
    private readonly CallerBinder _binder;
    private readonly ILogger<CallerRegistryProvider> _logger;
    private volatile CallerRegistry _current;

    /// <summary>Creates the provider and performs the initial bind.</summary>
    /// <param name="binder">The caller binder.</param>
    /// <param name="secretSource">The source whose change token triggers a rebind.</param>
    /// <param name="logger">Logs rebind outcomes; messages name ids, never key material.</param>
    /// <exception cref="Microsoft.Extensions.Options.OptionsValidationException">
    /// The initial bind fails — startup fails.
    /// </exception>
    public CallerRegistryProvider(CallerBinder binder, ISecretSource secretSource, ILogger<CallerRegistryProvider> logger)
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
    public CallerRegistry Current => _current;

    private void Rebind()
    {
        try
        {
            _current = _binder.Rebind(_current);
            _logger.LogInformation("CredProx callers rebound after a configuration change.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(
                ex,
                "CredProx callers failed to rebind after a configuration change; keeping the previous registry.");
        }
    }
}
