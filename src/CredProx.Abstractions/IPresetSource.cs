using System.Diagnostics.CodeAnalysis;
using System.Text.Json;

namespace CredProx.Abstractions;

/// <summary>
/// Supplies vendor presets: named JSON fragments of CredProx configuration (token
/// endpoint, client authentication style, lifetime defaults, required secrets) that a
/// credential can reference by name and override field by field. Presets are data, so
/// contributing one requires no executable code.
/// </summary>
[Experimental("CREDPROX001")]
public interface IPresetSource
{
    /// <summary>
    /// Looks up a preset by name, for example <c>spotify</c>.
    /// </summary>
    /// <param name="name">The preset name referenced from configuration.</param>
    /// <param name="preset">
    /// When found, the preset as a JSON object shaped like a <c>CredProx:Credentials</c>
    /// entry. A preset must not introduce a secret reference the host did not configure.
    /// </param>
    /// <returns><see langword="true"/> when a preset with that name exists.</returns>
    bool TryGetPreset(string name, out JsonElement preset);
}
