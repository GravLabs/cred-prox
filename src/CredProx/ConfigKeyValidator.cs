using System.Collections;
using System.Globalization;
using System.Reflection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace CredProx;

/// <summary>
/// The fail-closed unknown-key walker behind the M14a/M16/M17 rule: a configuration key the
/// binder does not consume is silently dropped, so a misspelled or foreign key must refuse
/// startup (and the reload, where the section rebinds — the previous registry keeps serving)
/// instead of quietly disabling the setting it was meant to control.
/// </summary>
/// <remarks>
/// Allowed keys come from an options type by reflection (the same rule M16 established for
/// credentials): public settable properties, plus get-only collections, dictionaries and
/// complex objects the binder populates in place — so a plugin declares its own keys simply
/// by having them on its options type. Binders that consume a fixed key set (connections)
/// pass the set explicitly. Keys nested under an options type the host section does not own
/// (the fixed <c>CredProx:*</c> subsections at the root) are listed as trusted: the walker
/// allows them as blocks and their own binders validate their contents.
/// </remarks>
internal static class ConfigKeyValidator
{
    /// <summary>
    /// Walks <paramref name="section"/> against the keys <paramref name="optionsType"/>
    /// exposes, appending one clear message per problem to <paramref name="errors"/>.
    /// </summary>
    /// <param name="section">The section to walk (its children are the keys being checked).</param>
    /// <param name="optionsType">The options type the binder binds this section into.</param>
    /// <param name="entity">Who owns the section, for the error text (e.g. <c>credential 'x'</c>).</param>
    /// <param name="scope">The section's configuration path, for the error text.</param>
    /// <param name="errors">Where the messages are appended.</param>
    /// <param name="addTypeAndPreset">Whether <c>Type</c>/<c>Preset</c> are allowed (credential roots).</param>
    /// <param name="trustedNames">Keys owned by other binders: allowed as blocks, never descended into.</param>
    public static void RejectUnknownKeys(
        IConfigurationSection section,
        Type optionsType,
        string entity,
        string scope,
        List<string> errors,
        bool addTypeAndPreset = false,
        IReadOnlySet<string>? trustedNames = null)
    {
        RejectRecursive(section, AllowedKeys(optionsType, addTypeAndPreset), entity, scope, path: null, trustedNames, errors);
    }

    /// <summary>
    /// Walks <paramref name="section"/> against an explicit allowed-key set. A
    /// <see langword="null"/> value marks a key the binder consumes as a single value, so a
    /// block nested under it is rejected like under any other scalar.
    /// </summary>
    public static void RejectUnknownKeys(
        IConfigurationSection section,
        IReadOnlyDictionary<string, Type?> allowedKeys,
        string entity,
        string scope,
        List<string> errors)
    {
        RejectRecursive(section, allowedKeys, entity, scope, path: null, trustedNames: null, errors);
    }

    /// <summary>
    /// Startup-time rejection for a whole options section: walks
    /// <c>configuration.GetSection(path)</c> against <paramref name="optionsType"/> and
    /// throws the collected problems as one <see cref="OptionsValidationException"/>, the
    /// same shape the eager options validators use (a bad value also fails startup there).
    /// </summary>
    public static void RejectUnknownKeysAtStartup(
        IConfiguration configuration,
        string path,
        Type optionsType,
        IReadOnlySet<string>? trustedNames = null)
    {
        var errors = new List<string>();
        RejectUnknownKeys(
            configuration.GetSection(path), optionsType, $"'{path}' section", path, errors,
            addTypeAndPreset: false, trustedNames);
        if (errors.Count > 0)
        {
            throw new OptionsValidationException(optionsType.Name, optionsType, errors);
        }
    }

    private static void RejectRecursive(
        IConfigurationSection section,
        IReadOnlyDictionary<string, Type?> allowed,
        string entity,
        string scope,
        string? path,
        IReadOnlySet<string>? trustedNames,
        List<string> errors)
    {
        foreach (var child in section.GetChildren())
        {
            var childPath = path is null ? child.Key : path + ":" + child.Key;

            // A key owned by another binder (a fixed CredProx subsection): legitimate block,
            // and its own binder validates what is inside it.
            if (trustedNames is not null && trustedNames.Contains(child.Key))
            {
                continue;
            }

            if (!allowed.TryGetValue(child.Key, out var childType))
            {
                AddUnknownKeyError(errors, entity, scope, childPath, allowed.Keys, trustedNames);
                continue;
            }

            if (childType is null)
            {
                // A value-only key (Type and Preset at a credential root, the connection's
                // certificate keys): the binder consumes them as values, not blocks — a block
                // under one is dropped exactly like under any other scalar (M16 review F1 class;
                // a nested Type is already caught by the no-Type error before the walker).
                if (child.GetChildren().Any())
                {
                    AddScalarNestingError(errors, entity, childPath, child);
                }

                continue;
            }

            if (IsBindableComplex(childType))
            {
                // Nested complex block (Partition, Basic, Form, …): check its keys too.
                RejectRecursive(
                    child, AllowedKeys(childType, addTypeAndPreset: false), entity, scope, childPath,
                    trustedNames: null, errors);
            }
            else if (TryGetTypedDictionaryValue(childType, out var valueType) && IsBindableComplex(valueType))
            {
                // A dictionary of typed options (Throttling/Resilience Clusters): the keys
                // stay user-defined (cluster names), but each entry is bound from that
                // section into the value type — so the entry's own keys are checked against
                // it (M17: a per-cluster field typo must not bind to nothing either).
                foreach (var entry in child.GetChildren())
                {
                    RejectRecursive(
                        entry, AllowedKeys(valueType, addTypeAndPreset: false), entity, scope,
                        childPath + ":" + entry.Key, trustedNames: null, errors);
                }
            }
            else if (TryGetListItem(childType, out var itemType) && !IsBindableComplex(itemType))
            {
                // A list of scalars (Allowed, IncludeHeaders, the kill switch's id lists):
                // the binder reads indices as elements and ignores every other child key,
                // and a block under an index drops the element's value — both are silent
                // drops (M18: the kill switch must not be silently unarmed by a key that
                // looks like a dictionary entry, Clusters:acme = true).
                foreach (var entry in child.GetChildren())
                {
                    var entryPath = childPath + ":" + entry.Key;
                    if (!int.TryParse(entry.Key, NumberStyles.None, CultureInfo.InvariantCulture, out _))
                    {
                        AddListIndexError(errors, entity, entryPath, childPath);
                    }
                    else if (entry.GetChildren().Any())
                    {
                        AddScalarNestingError(errors, entity, entryPath, entry);
                    }
                }
            }
            else if (!BinderCanPopulate(childType) && child.GetChildren().Any())
            {
                // A scalar (string, enum, TimeSpan, …) takes a single value; the binder reads
                // the value and drops any children. A block written under a scalar — a
                // Partition-shaped "Scope": { "From": … } — would lose both the value and the
                // block in silence, the exact class M16 closes. Leaf arrays and dictionaries
                // are exempt: their children are values or user-defined keys, which is what
                // the binder consumes there.
                AddScalarNestingError(errors, entity, childPath, child);
            }
        }
    }

    private static Dictionary<string, Type?> AllowedKeys(Type levelType, bool addTypeAndPreset)
    {
        var allowed = new Dictionary<string, Type?>(StringComparer.OrdinalIgnoreCase);

        // The binder itself consumes Type and Preset at the credential level.
        if (addTypeAndPreset)
        {
            allowed["Type"] = null;
            allowed["Preset"] = null;
        }

        foreach (var property in levelType.GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (property.GetIndexParameters().Length > 0)
            {
                continue; // indexer: not a bindable configuration key
            }

            // The binder writes a property when it has a public setter (a getter is not needed),
            // or in place when it is a get-only collection/dictionary/complex object. A get-only
            // computed scalar (OAuth's Location/Name/Prefix) is neither — writing it in config
            // does nothing, so it is rejected like any other unknown key.
            if (property.SetMethod?.IsPublic == true
                || (property.GetMethod?.IsPublic == true && BinderCanPopulate(property.PropertyType)))
            {
                allowed[property.Name] = property.PropertyType;
            }
        }

        return allowed;
    }

    // A complex block the walker descends into: a non-scalar type with at least one public
    // settable property. Strings, primitives, enums, TimeSpan-like structs and every collection
    // or dictionary (children are indices or arbitrary keys) are leaves.
    private static bool IsBindableComplex(Type type)
    {
        type = Nullable.GetUnderlyingType(type) ?? type;
        if (type == typeof(string) || type.IsPrimitive || type.IsEnum
            || typeof(IEnumerable).IsAssignableFrom(type))
        {
            return false;
        }

        return type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Any(p => p.SetMethod?.IsPublic == true);
    }

    // Whether the binder can write a value into a get-only property of this type (collections,
    // dictionaries and complex objects it populates in place), as opposed to a get-only scalar.
    private static bool BinderCanPopulate(Type type)
    {
        type = Nullable.GetUnderlyingType(type) ?? type;
        return type != typeof(string)
            && (typeof(IEnumerable).IsAssignableFrom(type) || IsBindableComplex(type));
    }

    // The element type of a list the binder populates (List<string> and friends). Dictionaries
    // are excluded — their keys are user data, not indices (typed option dictionaries take
    // their own branch above; value-only dictionaries stay untouched leaves).
    private static bool TryGetListItem(Type type, out Type itemType)
    {
        type = Nullable.GetUnderlyingType(type) ?? type;
        var enumerable = new[] { type }
            .Concat(type.GetInterfaces())
            .FirstOrDefault(i => i.IsGenericType && i.GetGenericTypeDefinition() == typeof(IEnumerable<>));
        if (enumerable is null || type == typeof(string)
            || typeof(IDictionary).IsAssignableFrom(type))
        {
            itemType = typeof(void);
            return false;
        }

        itemType = enumerable.GetGenericArguments()[0];
        return true;
    }

    // The value type of a dictionary the binder populates (Dictionary<string, Options> and
    // friends): the keys are user data, the values are bound from the entry sections.
    private static bool TryGetTypedDictionaryValue(Type type, out Type valueType)
    {
        type = Nullable.GetUnderlyingType(type) ?? type;
        var dictionary = new[] { type }
            .Concat(type.GetInterfaces())
            .FirstOrDefault(i => i.IsGenericType && i.GetGenericTypeDefinition() == typeof(IDictionary<,>));
        if (dictionary is null)
        {
            valueType = typeof(void);
            return false;
        }

        valueType = dictionary.GetGenericArguments()[1];
        return true;
    }

    private static void AddScalarNestingError(
        List<string> errors, string entity, string path, IConfigurationSection scalar)
    {
        var found = string.Join(", ", scalar.GetChildren()
            .Select(c => path + ":" + c.Key).Order(StringComparer.Ordinal));
        errors.Add(
            $"The {entity} declares a nested block under '{path}', which takes a single "
            + $"value (found {found}). The binder cannot bind both a value and a block, so the "
            + "nested keys are dropped — remove the nesting or move the keys to the block that "
            + "owns them.");
    }

    private static void AddListIndexError(List<string> errors, string entity, string path, string listPath)
    {
        errors.Add(
            $"The {entity} declares the key '{path}' inside the list '{listPath}'. List entries "
            + $"must be indexed ('{listPath}:0', '{listPath}:1', …): the binder ignores every "
            + "other key, so this entry configures nothing — index it or remove it.");
    }

    private static void AddUnknownKeyError(
        List<string> errors,
        string entity,
        string scope,
        string path,
        IEnumerable<string> allowed,
        IReadOnlySet<string>? trustedNames)
    {
        IEnumerable<string> names = trustedNames is null ? allowed : allowed.Concat(trustedNames);
        var known = string.Join(", ", names.Order(StringComparer.Ordinal));
        errors.Add(
            $"The {entity} declares the unknown configuration key '{path}' under "
            + $"'{scope}'. Known keys at that level: {known}. An unknown key is "
            + "ignored by the binder, which would silently drop the setting it was meant to control — "
            + "fix the spelling or remove the key.");
    }
}
