using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace CredProx;

/// <summary>
/// Binds every <c>CredProx:Destinations:&lt;name&gt;</c> section at startup into a
/// <see cref="DestinationRegistry"/> (see <c>docs/credprox-plan.md</c> §3.2/§3.3): the
/// template must be an absolute HTTP(S) address, and a destination that resolves a
/// partition must declare a registered partition source and a non-empty allow-list —
/// each problem is one clear <see cref="OptionsValidationException"/>, never a value.
/// Unknown keys under a destination are rejected too (M17, §3.3): the same rule at
/// startup and on rebind, where a failed rebind keeps the previous registry.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class DestinationBinder
{
    private const string PartitionPlaceholder = "{partition}";

    private readonly IConfiguration _configuration;
    private readonly IReadOnlyList<IPartitionSourceFactory> _factories;

    /// <summary>Creates the binder.</summary>
    /// <param name="configuration">The application configuration root.</param>
    /// <param name="factories">The registered partition source factories.</param>
    public DestinationBinder(IConfiguration configuration, IEnumerable<IPartitionSourceFactory> factories)
    {
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        _factories = (factories ?? throw new ArgumentNullException(nameof(factories))).ToList();
    }

    /// <summary>
    /// Binds every configured destination into a <see cref="DestinationRegistry"/>.
    /// </summary>
    /// <exception cref="OptionsValidationException">
    /// A destination has no template, a template that is not an absolute HTTP(S) address,
    /// a <c>{partition}</c> template without a partition source, or a partition without a
    /// non-empty allow-list.
    /// </exception>
    public DestinationRegistry Bind()
    {
        var errors = new List<string>();
        var entries = new Dictionary<string, DestinationEntry>(StringComparer.OrdinalIgnoreCase);

        foreach (var section in _configuration.GetSection("CredProx:Destinations").GetChildren())
        {
            var name = section.Key;

            // M17 (§3.3): keys DestinationDefinition does not expose are silently dropped by
            // section.Bind, so a misspelled field (e.g. "StripHeaderr") would configure nothing —
            // rejected at startup and on rebind (the provider keeps the previous registry on a
            // failed rebind), with the allowed keys derived from the definition by reflection.
            var before = errors.Count;
            ConfigKeyValidator.RejectUnknownKeys(
                section, typeof(DestinationDefinition), $"destination '{name}'",
                $"CredProx:Destinations:{name}", errors);
            if (errors.Count > before)
            {
                continue;
            }

            var definition = new DestinationDefinition();
            section.Bind(definition);

            if (string.IsNullOrWhiteSpace(definition.Template))
            {
                errors.Add($"The destination '{name}' has no Template.");
                continue;
            }

            if (!IsAbsoluteHttpAddress(definition.Template))
            {
                errors.Add($"The destination '{name}' Template '{definition.Template}' is not an absolute http(s) address.");
                continue;
            }

            if (definition.Template.Contains(PartitionPlaceholder, StringComparison.Ordinal)
                && string.IsNullOrWhiteSpace(definition.Partition))
            {
                errors.Add($"The destination '{name}' uses {{partition}} but declares no Partition source.");
                continue;
            }

            if (!PartitionBinder.TryBind(
                    definition.Partition, definition.Allowed, _factories, $"destination '{name}'",
                    out var partition, out var error))
            {
                errors.Add(error!);
                continue;
            }

            entries[name] = new DestinationEntry(name, definition, partition);
        }

        if (errors.Count > 0)
        {
            throw new OptionsValidationException("CredProx", typeof(object), errors);
        }

        return new DestinationRegistry(entries);
    }

    /// <summary>
    /// Validates the template's shape with the placeholder replaced by a fixed token, so
    /// the check is about the configured address, not about any request value.
    /// </summary>
    private static bool IsAbsoluteHttpAddress(string template)
    {
        var probe = template.Replace(PartitionPlaceholder, "p", StringComparison.Ordinal);
        return Uri.TryCreate(probe, UriKind.Absolute, out var uri)
            && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);
    }
}
