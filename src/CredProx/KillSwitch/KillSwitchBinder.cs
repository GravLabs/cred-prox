using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace CredProx;

/// <summary>
/// Binds <c>CredProx:KillSwitch</c> (M18, plan §8.4) into a <see cref="KillSwitchRegistry"/>.
/// The section takes exactly two list keys — <c>Clusters</c> and <c>Callers</c>, each a list
/// of ids — and the M17 walker guards it: a misspelled key (<c>Cluster</c>), a map-shaped
/// entry (<code>Clusters:acme = true</code>) or a single value instead of a list all refuse
/// startup and reload. The switch that protects against a silent configuration mistake must
/// not itself be silent about one — an unarmed kill switch reads exactly like a vendor that
/// was never disabled.
/// </summary>
internal sealed class KillSwitchBinder(IConfiguration configuration)
{
    /// <summary>The configuration section the switch reads.</summary>
    public const string SectionPath = "CredProx:KillSwitch";

    // Both keys are lists the binder populates by index; the walker's list rule checks
    // every entry key is an index (M18) and the binder below also rejects a lone value
    // and blank entries, which the generic walker leaves to the consumer.
    private static readonly IReadOnlyDictionary<string, Type?> AllowedKeys =
        new Dictionary<string, Type?>(StringComparer.OrdinalIgnoreCase)
        {
            ["Clusters"] = typeof(List<string>),
            ["Callers"] = typeof(List<string>),
        };

    /// <summary>
    /// Binds the current configuration into a registry, collecting every problem into one
    /// <see cref="OptionsValidationException"/>.
    /// </summary>
    public KillSwitchRegistry Bind()
    {
        var section = configuration.GetSection(SectionPath);
        var errors = new List<string>();
        ConfigKeyValidator.RejectUnknownKeys(
            section, AllowedKeys, $"'{SectionPath}' section", SectionPath, errors);

        var clusters = ReadIds(section, "Clusters", errors);
        var callers = ReadIds(section, "Callers", errors);

        if (errors.Count > 0)
        {
            throw new OptionsValidationException(SectionPath, typeof(object), errors);
        }

        return new KillSwitchRegistry(clusters, callers);
    }

    private static IReadOnlyList<string> ReadIds(
        IConfigurationSection parent, string key, List<string> errors)
    {
        var section = parent.GetSection(key);
        var ids = new List<string>();

        // "Clusters": "acme" — the binder consumes children, never the section value, so
        // a single value would silently arm nothing.
        if (!string.IsNullOrWhiteSpace(section.Value))
        {
            errors.Add(
                $"The '{SectionPath}' section takes '{key}' as a list of ids "
                + $"(write '{key}:0' = \"acme\", '{key}:1' = …); a single value under "
                + $"'{key}' is ignored by the binder, which would silently leave the switch unarmed.");
            return ids;
        }

        foreach (var entry in section.GetChildren())
        {
            // Non-index keys and blocks under an index were already refused by the walker;
            // here only the value itself can be missing or blank ("Clusters:0" = "").
            if (string.IsNullOrWhiteSpace(entry.Value))
            {
                errors.Add(
                    $"The '{SectionPath}' section declares an empty '{key}' entry at "
                    + $"'{entry.Path}'; every entry must name exactly one id to disable — "
                    + "remove it or give it the id.");
                continue;
            }

            ids.Add(entry.Value);
        }

        return ids;
    }
}
