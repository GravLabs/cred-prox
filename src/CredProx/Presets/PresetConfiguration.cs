using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;

namespace CredProx;

/// <summary>
/// Layers the presets a credential references beneath the host's own configuration
/// (see <c>docs/credprox-plan.md</c> §3 "Vendor presets"): each
/// <c>CredProx:Credentials:&lt;name&gt;</c> section carrying a <c>Preset</c> key gets the
/// named fragment flattened into configuration keys under its section, added as a
/// <em>lower-priority</em> source — so every field the host writes wins over the preset,
/// and a credential whose whole section is <c>{"Preset": "acme-oauth"}</c> binds completely.
/// </summary>
/// <remarks>
/// Because the composed configuration is what both the binder and the startup secret scan
/// read, a <c>secret:</c> reference introduced by a preset is validated exactly like one
/// the host wrote: it must resolve through the host's configured
/// <see cref="CredProx.Abstractions.ISecretSource"/> or startup fails — a preset cannot
/// introduce a secret reference the host did not configure (§5.2 "Presets").
/// Since 0.4.0 the library ships no built-in presets: fragments come from the host's
/// <c>CredProx:Presets</c> configuration or from its own <see cref="IPresetSource"/>
/// registrations.
/// Preset fragments are re-layered on every composition, and the registry rebinds on a
/// configuration reload — so changing which preset a credential references takes effect
/// on reload like any other credential field.
/// </remarks>
[Experimental("CREDPROX001")]
internal static class PresetConfiguration
{
    /// <summary>
    /// The six vendor presets CredProx 0.3 embedded and 0.4 removed: the library ships no
    /// built-in vendor knowledge, and every vendor is shown as explicit config in its own
    /// sample. A credential that still names one of these gets an error pointing at the
    /// sample whose config replaces the preset — unless the host defines a preset of that
    /// name itself, which wins (the name is the host's to reuse).
    /// </summary>
    private static readonly Dictionary<string, string> RemovedBuiltInPresets =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["spotify"] = "samples/Spotify",
            ["microsoft-graph"] = "samples/MicrosoftGraph",
            ["github-app"] = "samples/GitHubApp",
            ["keycloak"] = "samples/OAuthKeycloak",
            ["adp"] = "samples/ADP",
            ["cayuse"] = "samples/LoginExchange",
        };

    /// <summary>
    /// Returns <paramref name="configuration"/> with every referenced preset layered under
    /// its credential section, or the same instance when no credential references a preset.
    /// Unknown presets are appended to <paramref name="errors"/> and skipped — the caller
    /// reports them like every other binding problem, never as values.
    /// </summary>
    public static IConfiguration Compose(
        IConfiguration configuration,
        IEnumerable<IPresetSource> presetSources,
        List<string> errors)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(presetSources);
        ArgumentNullException.ThrowIfNull(errors);

        var sources = presetSources as IReadOnlyList<IPresetSource> ?? presetSources.ToList();
        var presetKeys = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

        foreach (var section in configuration.GetSection("CredProx:Credentials").GetChildren())
        {
            if (section["Preset"] is not { Length: > 0 } presetName)
            {
                continue;
            }

            if (!TryFind(presetName, sources, out var fragment))
            {
                errors.Add(RemovedBuiltInPresets.TryGetValue(presetName, out var sample)
                    ? $"The credential '{section.Key}' references the built-in preset '{presetName}', which was removed in 0.4.0. "
                        + $"Configure the vendor explicitly — the full config is in {sample}."
                    : $"The credential '{section.Key}' references unknown preset '{presetName}'.");
                continue;
            }

            if (fragment.ValueKind != JsonValueKind.Object)
            {
                errors.Add(
                    $"The preset '{presetName}' referenced by credential '{section.Key}' is not a JSON object.");
                continue;
            }

            Flatten($"CredProx:Credentials:{section.Key}", fragment, presetKeys);
        }

        if (presetKeys.Count == 0)
        {
            return configuration;
        }

        // In-memory first, host configuration chained after: later sources win, so every
        // host-written field overrides the preset field beneath it.
        return new ConfigurationBuilder()
            .AddInMemoryCollection(presetKeys)
            .AddConfiguration(configuration)
            .Build();
    }

    private static bool TryFind(string name, IReadOnlyList<IPresetSource> sources, out JsonElement fragment)
    {
        foreach (var source in sources)
        {
            if (source.TryGetPreset(name, out fragment))
            {
                return true;
            }
        }

        fragment = default;
        return false;
    }

    /// <summary>
    /// Flattens a preset fragment into configuration keys (objects join with <c>:</c>,
    /// arrays index from <c>0</c>) exactly as the JSON configuration provider would.
    /// Null members carry nothing — the host value or the options default stands.
    /// </summary>
    private static void Flatten(string path, JsonElement element, Dictionary<string, string?> keys)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    Flatten(path + ":" + property.Name, property.Value, keys);
                }

                break;

            case JsonValueKind.Array:
                var index = 0;
                foreach (var item in element.EnumerateArray())
                {
                    Flatten(path + ":" + index++, item, keys);
                }

                break;

            case JsonValueKind.Null or JsonValueKind.Undefined:
                break;

            default:
                keys[path] = element.ValueKind == JsonValueKind.String
                    ? element.GetString()
                    : element.GetRawText();
                break;
        }
    }
}
