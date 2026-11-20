using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;
using Microsoft.Extensions.Logging;

namespace CredProx;

/// <summary>
/// The built-in token-obtainable probe:
/// resolves every configured credential through the normal attach path — which always
/// goes through <see cref="ITokenCache"/> — so a valid cached token means no vendor call
/// ("probes respect the token cache"). A credential with a partition source is probed
/// once per <em>allowed</em> partition value: those are admitted by construction, so the
/// probe never invents a partition. Any failure is <c>Unhealthy</c>; the next round that
/// succeeds recovers it.
/// </summary>
/// <remarks>
/// Failure descriptions name the credential and the exception type. A provider's own
/// message is never relayed: a third-party provider's catch-all reports the type, not
/// the text (M45 security finding F-5).
/// </remarks>
[Experimental("CREDPROX001")]
internal sealed class TokenObtainableProbe(
    CredentialRegistryProvider registryProvider,
    ILogger<TokenObtainableProbe> logger) : ICredentialHealthProbe
{
    /// <inheritdoc />
    public string Name => "credprox.tokens";

    /// <inheritdoc />
    public async ValueTask<CredProxHealthResult?> CheckAsync(CancellationToken cancellationToken)
    {
        var registry = registryProvider.Current;
        var failures = new List<string>();
        var failedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var name in registry.Names)
        {
            var binding = registry.Get(name);
            string?[] partitions = binding.PartitionSource is { } partitionSource
                ? [.. partitionSource.Allowed]
                : [null];

            foreach (var partition in partitions)
            {
                try
                {
                    await binding.GetCredential(
                        new CredentialRequestContext { CredentialName = name, Partition = partition },
                        cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    // M45 security finding F-5: the provider here may be a third party,
                    // and its message is its own — the health report names the exception
                    // type, never the text.
                    var target = partition is null ? $"'{name}'" : $"'{name}' (partition '{partition}')";
                    failures.Add($"credential {target} could not be obtained ({ex.GetType().Name})");
                    failedNames.Add(name);
                }
            }

            // Worst partition decides the credential's gauge for this round.
            OperationsDiagnostics.RecordHealthStatus("credential", name, failedNames.Contains(name) ? 2 : 0);
        }

        if (failures.Count > 0)
        {
            logger.LogWarning(
                "The CredProx token health probe found {Count} credential(s) that could not be obtained.",
                failures.Count);
            return new CredProxHealthResult(
                CredProxHealthSeverity.Unhealthy, string.Join("; ", failures));
        }

        return null;
    }
}
