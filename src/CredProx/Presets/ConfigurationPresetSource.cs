using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;

namespace CredProx;

/// <summary>
/// Presets written in the host's own configuration under
/// <c>CredProx:Presets:&lt;name&gt;</c> (see <c>docs/credprox-plan.md</c> §3 plugin points:
/// "presets from configuration"). A section shaped like a
/// <c>CredProx:Credentials</c> entry is a preset a credential can reference by that name —
/// community-contributed vendor knowledge with no code and no new package.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class ConfigurationPresetSource : IPresetSource
{
    private readonly IConfiguration _configuration;

    /// <summary>
    /// Creates the source over the given configuration root.
    /// </summary>
    /// <param name="configuration">The application configuration holding <c>CredProx:Presets</c>.</param>
    public ConfigurationPresetSource(IConfiguration configuration)
    {
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
    }

    /// <inheritdoc />
    public bool TryGetPreset(string name, out JsonElement preset)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);

        var section = _configuration.GetSection("CredProx:Presets").GetSection(name);
        if (section.Value is null && !section.GetChildren().Any())
        {
            preset = default;
            return false;
        }

        preset = JsonSerializer.SerializeToElement(ToNode(section));
        return true;
    }

    /// <summary>
    /// Rebuilds a configuration section as JSON: leaf values become JSON strings (the
    /// configuration layer is stringly-typed and the options binder parses them the same
    /// way), all-numeric child keys become an array (the JSON provider's array shape).
    /// </summary>
    private static JsonNode? ToNode(IConfigurationSection section)
    {
        var children = section.GetChildren().ToList();
        if (children.Count == 0)
        {
            return section.Value is { } value ? JsonValue.Create(value) : null;
        }

        if (children.All(c => int.TryParse(c.Key, NumberStyles.None, CultureInfo.InvariantCulture, out _)))
        {
            var array = new JsonArray();
            foreach (var child in children.OrderBy(c => int.Parse(c.Key, CultureInfo.InvariantCulture)))
            {
                array.Add(ToNode(child));
            }

            return array;
        }

        var obj = new JsonObject();
        foreach (var child in children)
        {
            obj[child.Key] = ToNode(child);
        }

        return obj;
    }
}
