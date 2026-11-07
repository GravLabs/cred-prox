using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Primitives;

namespace CredProx;

/// <summary>
/// The built-in <see cref="ISecretSource"/>: resolves <c>secret:&lt;name&gt;</c> references
/// from the <c>CredProx:Secrets</c> configuration section, which covers environment variables
/// (<c>CredProx__Secrets__&lt;name&gt;</c>), user-secrets and Key Vault pulled in through a
/// configuration provider (see <c>docs/credprox-plan.md</c> §3.3). Values are read from
/// <see cref="IConfiguration"/> on every lookup, so a configuration reload updates resolved
/// values; <see cref="GetChangeToken"/> fires on each reload.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class ConfigurationSecretSource : ISecretSource
{
    /// <summary>The configuration section that holds secret values, keyed by reference name.</summary>
    public const string SecretsSection = "CredProx:Secrets";

    private readonly IConfiguration _configuration;
    private CancellationTokenSource _reloadCts = new();

    /// <summary>
    /// Creates the source over the given configuration root.
    /// </summary>
    /// <param name="configuration">The application configuration.</param>
    public ConfigurationSecretSource(IConfiguration configuration)
    {
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));

        // ChangeToken.OnChange re-arms itself, so this keeps firing across reloads. The
        // registration lives as long as this singleton source.
        _ = ChangeToken.OnChange(_configuration.GetReloadToken, RaiseChanged);
    }

    /// <inheritdoc />
    public string Scheme => SecretReferences.Prefix[..^1];

    /// <inheritdoc />
    public ValueTask<string?> GetSecretAsync(string name, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(name);

        // IConfiguration is live: this reads the value as currently configured, so a reload
        // updates resolved values without recreating the source.
        return new ValueTask<string?>(_configuration[$"{SecretsSection}:{name}"]);
    }

    /// <inheritdoc />
    public IChangeToken GetChangeToken() => new CancellationChangeToken(Volatile.Read(ref _reloadCts).Token);

    private void RaiseChanged()
    {
        // The previous source is intentionally not disposed: a consumer may be constructing
        // a CancellationChangeToken from its token right now, and registering a callback on
        // a disposed source would throw. Reloads are rare, so the leak is bounded.
        Interlocked.Exchange(ref _reloadCts, new CancellationTokenSource()).Cancel();
    }
}
