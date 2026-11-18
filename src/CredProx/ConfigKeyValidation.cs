using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Configuration;

namespace CredProx;

/// <summary>
/// The public entry to the fail-closed unknown-key rule for add-on packages that
/// own a top-level <c>CredProx:*</c> configuration section: unknown keys under a section the
/// binder does not consume would be silently dropped, so the add-on's registration calls this
/// and refuses startup exactly like the core sections do. Allowed keys come from the options
/// type by reflection — a package declares its keys simply by having them on its options type.
/// The core's own sections keep calling the internal walker directly.
/// </summary>
[Experimental("CREDPROX001")]
public static class CredProxConfigValidation
{
    /// <summary>
    /// Walks <c>configuration.GetSection(path)</c> against the keys
    /// <paramref name="optionsType"/> exposes and throws the collected problems as one
    /// <see cref="Microsoft.Extensions.Options.OptionsValidationException"/> — the same shape
    /// the eager options validators use, so a bad key fails startup alongside a bad value.
    /// </summary>
    /// <param name="configuration">The application configuration root.</param>
    /// <param name="path">The section path the add-on owns (e.g. <c>CredProx:Throttling</c>).</param>
    /// <param name="optionsType">The options type the add-on binds the section into.</param>
    public static void RejectUnknownKeysAtStartup(
        IConfiguration configuration,
        string path,
        Type optionsType)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(optionsType);

        ConfigKeyValidator.RejectUnknownKeysAtStartup(configuration, path, optionsType);
    }
}
