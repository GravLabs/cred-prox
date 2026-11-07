using Microsoft.Extensions.Configuration;

namespace CredProx;

/// <summary>
/// Finds <c>secret:</c> references in configuration values. Two forms exist in
/// <c>docs/credprox-plan.md</c> §3.2: a whole value that is a reference
/// (<c>"ClientId": "secret:adp-client-id"</c>) and a reference embedded in a template
/// (<c>"...?tenant_id={secret:cayuse-{partition}-tenantid}"</c>). A reference name may itself
/// contain <c>{placeholder}</c> segments, so the templated form is matched by brace depth,
/// not a flat pattern: <c>{secret:cayuse-{partition}-tenantid}</c> yields the name
/// <c>cayuse-{partition}-tenantid</c>.
/// </summary>
internal static class SecretReferences
{
    /// <summary>The scheme prefix of a secret reference.</summary>
    public const string Prefix = "secret:";

    private const string TemplatedPrefix = "{secret:";

    /// <summary>
    /// The reference names (without the <c>secret:</c> prefix) used by a single value.
    /// </summary>
    public static IEnumerable<string> FindInValue(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            yield break;
        }

        if (value.StartsWith(Prefix, StringComparison.Ordinal))
        {
            yield return value[Prefix.Length..];
        }

        for (var i = 0; i < value.Length; i++)
        {
            if (value[i] != '{' || !value.AsSpan(i).StartsWith(TemplatedPrefix.AsSpan(), StringComparison.Ordinal))
            {
                continue;
            }

            // Match the closing brace by depth so a name may contain {partition} and friends.
            var depth = 1;
            var end = i + TemplatedPrefix.Length;
            while (end < value.Length && depth > 0)
            {
                if (value[end] == '{')
                {
                    depth++;
                }
                else if (value[end] == '}')
                {
                    depth--;
                }

                end++;
            }

            if (depth == 0)
            {
                var name = value[(i + TemplatedPrefix.Length)..(end - 1)];
                if (name.Length > 0)
                {
                    yield return name;
                }

                i = end - 1; // resume after the reference
            }
        }
    }

    /// <summary>
    /// The distinct reference names used anywhere under <paramref name="section"/>,
    /// recursively.
    /// </summary>
    public static IReadOnlySet<string> FindInSection(IConfigurationSection section)
    {
        ArgumentNullException.ThrowIfNull(section);

        var names = new HashSet<string>(StringComparer.Ordinal);
        Collect(section, names);
        return names;
    }

    private static void Collect(IConfigurationSection section, HashSet<string> names)
    {
        if (section.Value is { } value)
        {
            foreach (var name in FindInValue(value))
            {
                names.Add(name);
            }
        }

        foreach (var child in section.GetChildren())
        {
            Collect(child, names);
        }
    }
}
