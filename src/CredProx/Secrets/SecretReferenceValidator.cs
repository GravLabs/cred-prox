using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace CredProx;

/// <summary>
/// Startup validation for secret references (see <c>docs/credprox-plan.md</c> §3.3):
/// every <c>secret:</c> reference used under the <c>CredProx</c> configuration section must
/// resolve through the registered <see cref="ISecretSource"/>. A reference that does not
/// resolve produces one <see cref="OptionsValidationException"/> naming the references —
/// never a secret value.
/// </summary>
/// <remarks>
/// References whose name contains a template placeholder (for example
/// <c>{secret:cayuse-{partition}-tenantid}</c>) cannot be resolved at startup because the
/// partition value is per-request; they are validated lazily on first use: the plugin's
/// <see cref="ScopedSecretAccessor"/> admits only names matching the declared shape and
/// reports a name that does not resolve when it is requested.
/// </remarks>
[Experimental("CREDPROX001")]
public sealed class SecretReferenceValidator
{
    private readonly ISecretSource _source;

    /// <summary>
    /// Creates the validator over the given secret source.
    /// </summary>
    /// <param name="source">The secret source references are resolved against.</param>
    public SecretReferenceValidator(ISecretSource source)
    {
        _source = source ?? throw new ArgumentNullException(nameof(source));
    }

    /// <summary>
    /// Resolves every literal <c>secret:</c> reference under <paramref name="credProxSection"/>
    /// and throws when any of them does not resolve.
    /// </summary>
    /// <param name="credProxSection">The <c>CredProx</c> configuration section.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <exception cref="OptionsValidationException">
    /// One or more references do not resolve. The errors name the references, not values.
    /// </exception>
    public async ValueTask ValidateAsync(IConfigurationSection credProxSection, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(credProxSection);

        var errors = new List<string>();
        foreach (var name in SecretReferences.FindInSection(credProxSection).Order(StringComparer.Ordinal))
        {
            // Templated names ({partition} and friends) resolve per-request, not at startup.
            if (name.Contains('{') || name.Contains('}'))
            {
                continue;
            }

            var value = await _source.GetSecretAsync(name, cancellationToken).ConfigureAwait(false);
            if (value is null)
            {
                errors.Add($"The secret reference '{SecretReferences.Prefix}{name}' does not resolve.");
            }
        }

        if (errors.Count > 0)
        {
            throw new OptionsValidationException("CredProx", typeof(object), errors);
        }
    }
}
