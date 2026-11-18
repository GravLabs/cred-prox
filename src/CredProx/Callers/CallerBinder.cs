using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace CredProx;

/// <summary>
/// Binds every <c>CredProx:Callers:&lt;id&gt;</c> section into a <see cref="CallerRegistry"/>
/// : a broken operation pattern or budget
/// fails startup with one <see cref="OptionsValidationException"/> naming the caller.
/// Unknown configuration keys under a caller are rejected too (M14a): a typo in an
/// allow-list entry must fail closed, never silently widen the caller's access.
/// </summary>
/// <remarks>
/// The core reads the policy shape only. <c>Keys</c> is accepted but not read here — the
/// <c>CredProx.CallerKeys</c> add-on owns its entries (its contributed rules validate them
/// at startup and on every rebind). <c>TokenClientIds</c> likewise belongs to
/// <c>CredProx.CallerTokens</c>. A 0.11.0 configuration binds unchanged.
/// </remarks>
[Experimental("CREDPROX001")]
public sealed class CallerBinder
{
    private readonly IConfiguration _configuration;
    private readonly IReadOnlyList<ICallerRegistryValidator> _validators;

    /// <summary>Creates the binder.</summary>
    /// <param name="configuration">The application configuration root.</param>
    /// <param name="accessorFactory">
    /// Unused by the core since caller keys moved to <c>CredProx.CallerKeys</c>; kept for
    /// the 0.11.0 constructor shape. Feature packages that read secret references build
    /// their own accessors from the same factory.
    /// </param>
    /// <param name="validators">
    /// Rules contributed by feature packages (see <see cref="ICallerRegistryValidator"/>).
    /// Every one runs over the complete registry view on every bind and rebind — a refused
    /// registry never takes effect.
    /// </param>
    public CallerBinder(
        IConfiguration configuration,
        SecretAccessorFactory accessorFactory,
        IEnumerable<ICallerRegistryValidator> validators)
    {
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        ArgumentNullException.ThrowIfNull(accessorFactory);
        _validators = [.. validators ?? throw new ArgumentNullException(nameof(validators))];
    }

    /// <summary>
    /// Binds every configured caller. At least one caller must be configured: registering
    /// caller authentication with no callers would authenticate nobody.
    /// </summary>
    /// <exception cref="OptionsValidationException">
    /// No caller is configured, or one fails validation.
    /// </exception>
    public CallerRegistry Bind()
    {
        var (registry, errors) = BindCore();

        if (registry is not null && registry.Count == 0)
        {
            errors.Add("Caller authentication is registered but no caller is configured under 'CredProx:Callers'.");
        }

        if (errors.Count > 0)
        {
            throw new OptionsValidationException("CredProx", typeof(object), errors);
        }

        return registry!;
    }

    /// <summary>
    /// Rebinds after a configuration change: callers are rebuilt from the current
    /// configuration (removing a caller's last key revokes it; removing every caller is a
    /// deliberate kill switch and is allowed here, unlike at startup). A failed rebind
    /// keeps the previous registry serving.
    /// </summary>
    /// <param name="previous">The registry the provider is serving; unused — callers are plain data.</param>
    /// <exception cref="OptionsValidationException">A caller fails to bind.</exception>
    public CallerRegistry Rebind(CallerRegistry previous)
    {
        ArgumentNullException.ThrowIfNull(previous);
        return RebindCore();
    }

    private CallerRegistry RebindCore()
    {
        var (registry, errors) = BindCore();

        if (errors.Count > 0)
        {
            throw new OptionsValidationException("CredProx", typeof(object), errors);
        }

        return registry!;
    }

    private (CallerRegistry? Registry, List<string> Errors) BindCore()
    {
        var errors = new List<string>();
        var callers = new Dictionary<string, CallerDefinition>(StringComparer.OrdinalIgnoreCase);
        var entries = new List<CallerRegistryEntry>();

        foreach (var section in _configuration.GetSection("CredProx:Callers").GetChildren())
        {
            entries.Add(new CallerRegistryEntry(section.Key, section));
            if (TryBindOne(section, errors, out var definition))
            {
                callers[section.Key] = definition;
            }
        }

        // The contributed rules see the complete configured set in configuration order —
        // cross-caller rules (one client id claimed by two callers) are why every entry
        // arrives in a single call — and they see it on every rebind too: a live edit
        // into a refused shape fails here, before any swap, so the provider keeps the
        // previous registry serving.
        foreach (var validator in _validators)
        {
            errors.AddRange(validator.Validate(entries));
        }

        return (errors.Count == 0 ? new CallerRegistry(callers) : null, errors);
    }

    private bool TryBindOne(IConfigurationSection section, List<string> errors, out CallerDefinition definition)
    {
        var callerId = section.Key;
        RejectUnknownKeys(section, callerId, errors);

        // Keys and TokenClientIds are accepted-but-unread configuration sections: each
        // feature package validates its own entries through ICallerRegistryValidator, on
        // this bind and on every rebind. The core binds the policy only.
        var operations = new List<CallerOperationRule>();
        foreach (var ruleSection in section.GetSection("Operations").GetChildren())
        {
            if (TryBindOperation(callerId, ruleSection, errors, out var rule))
            {
                operations.Add(rule);
            }
        }

        CallerLimits? limits = null;
        var limitsSection = section.GetSection("Limits");
        if (limitsSection.Exists())
        {
            limits = TryBindLimits(callerId, limitsSection, errors);
        }

        definition = null!;
        if (errors.Count > 0)
        {
            return false;
        }

        definition = new CallerDefinition(callerId, operations, limits);
        return true;
    }

    // Budget values are plain config here (no secret: references); a malformed number or
    // window fails the bind like any other config error (§3.7). Returns null on error so
    // the caller-level error list decides; an empty-but-present Limits section binds to
    // an unlimited CallerLimits (PermitsPerInterval 0) — legal, just pointless.
    private static CallerLimits? TryBindLimits(string callerId, IConfigurationSection limitsSection, List<string> errors)
    {
        var limits = new CallerLimits();

        var permits = limitsSection["PermitsPerInterval"];
        if (!string.IsNullOrWhiteSpace(permits))
        {
            if (!int.TryParse(permits, NumberStyles.None, CultureInfo.InvariantCulture, out var parsedPermits)
                || parsedPermits < 0)
            {
                errors.Add($"The caller '{callerId}' declares Limits:PermitsPerInterval '{permits}', which must be a non-negative integer.");
                return null;
            }

            limits.PermitsPerInterval = parsedPermits;
        }

        var interval = limitsSection["Interval"];
        if (!string.IsNullOrWhiteSpace(interval))
        {
            if (!TryParseInterval(interval, out var parsedInterval) || parsedInterval <= TimeSpan.Zero)
            {
                errors.Add($"The caller '{callerId}' declares Limits:Interval '{interval}', which must be a positive TimeSpan.");
                return null;
            }

            limits.Interval = parsedInterval;
        }

        foreach (var clusterSection in limitsSection.GetSection("Clusters").GetChildren())
        {
            var cluster = new CallerClusterLimits();

            var clusterPermits = clusterSection["PermitsPerInterval"];
            if (!string.IsNullOrWhiteSpace(clusterPermits))
            {
                if (!int.TryParse(clusterPermits, NumberStyles.None, CultureInfo.InvariantCulture, out var parsedClusterPermits)
                    || parsedClusterPermits < 0)
                {
                    errors.Add($"The caller '{callerId}' declares Limits:Clusters:{clusterSection.Key}:PermitsPerInterval '{clusterPermits}', which must be a non-negative integer.");
                    return null;
                }

                cluster.PermitsPerInterval = parsedClusterPermits;
            }

            var clusterInterval = clusterSection["Interval"];
            if (!string.IsNullOrWhiteSpace(clusterInterval))
            {
                if (!TryParseInterval(clusterInterval, out var parsedClusterInterval) || parsedClusterInterval <= TimeSpan.Zero)
                {
                    errors.Add($"The caller '{callerId}' declares Limits:Clusters:{clusterSection.Key}:Interval '{clusterInterval}', which must be a positive TimeSpan.");
                    return null;
                }

                cluster.Interval = parsedClusterInterval;
            }

            limits.Clusters[clusterSection.Key] = cluster;
        }

        return limits;
    }

    private static bool TryParseInterval(string value, out TimeSpan interval) =>
        TimeSpan.TryParse(value, CultureInfo.InvariantCulture, out interval);

    private static bool TryBindOperation(
        string callerId, IConfigurationSection ruleSection, List<string> errors, out CallerOperationRule rule)
    {
        rule = null!;
        var route = ruleSection["Route"];
        if (route is not null && string.IsNullOrWhiteSpace(route))
        {
            errors.Add($"The caller '{callerId}' declares an operation with an empty Route.");
            return false;
        }

        var methods = ruleSection.GetSection("Methods").GetChildren().Select(m => m.Value).ToList();
        if (methods.Any(string.IsNullOrWhiteSpace))
        {
            errors.Add($"The caller '{callerId}' declares an operation with an empty Methods entry.");
            return false;
        }

        var patterns = ruleSection.GetSection("Paths").GetChildren().Select(p => p.Value).ToList();
        foreach (var pattern in patterns)
        {
            if (pattern is null || !PathPatterns.IsValidPattern(pattern))
            {
                errors.Add(
                    $"The caller '{callerId}' declares the path pattern '{pattern}', which must start with '/' and use '*' (one segment) or a trailing '**' as wildcards.");
                return false;
            }
        }

        // M39 (ADR-0004): an optional scope name, e.g. an Entra app-role value. An empty
        // name would match no role — the same typo-shaped fail-closed family as Route.
        var name = ruleSection["Name"];
        if (name is not null && string.IsNullOrWhiteSpace(name))
        {
            errors.Add($"The caller '{callerId}' declares an operation with an empty Name.");
            return false;
        }

        // M39: scope matching is ordinal, so a padded name — config-clean at a
        // glance — can never intersect a real role and locks the rule out for everyone.
        // Refused like a padded TokenClientIds entry, never silently trimmed.
        if (name is not null && !string.Equals(name, name.Trim(), StringComparison.Ordinal))
        {
            errors.Add(
                $"The caller '{callerId}' declares '{ruleSection.Path}' with a Name that has leading or "
                + "trailing whitespace — scope names are matched verbatim, so a padded name admits nobody.");
            return false;
        }

        rule = new CallerOperationRule(
            route,
            methods.Where(m => m is not null).Select(m => m!).ToList(),
            patterns.Where(p => p is not null).Select(p => p!).ToList(),
            name);
        return true;
    }

    // The exact key shape this binder reads. Anything else under a caller is a typo —
    // and a typo in an allow-list entry (e.g. "PathPatterns" for "Paths") would otherwise
    // be silently ignored and admit the caller to EVERYTHING. A security allow-list fails
    // closed on a config error (M14a), at startup and on reload alike.
    // Keys and TokenClientIds are accepted but not read here: CredProx.CallerKeys and
    // CredProx.CallerTokens own those sections' values (their contributed rules validate
    // entries at startup and on every rebind); the core keeps both names so a 0.11.0
    // config still binds.
    private static readonly HashSet<string> CallerLevelKeys =
        new(StringComparer.OrdinalIgnoreCase) { "Keys", "Operations", "Limits", "TokenClientIds" };

    private static readonly HashSet<string> OperationEntryKeys =
        new(StringComparer.OrdinalIgnoreCase) { "Route", "Methods", "Paths", "Name" };

    // M15 (§3.7): a typo under Limits (e.g. "Permits" for "PermitsPerInterval") must fail
    // closed too — silently ignoring it would run the caller UNLIMITED, the exact
    // fail-open the M14a rule exists to prevent.
    private static readonly HashSet<string> LimitsKeys =
        new(StringComparer.OrdinalIgnoreCase) { "PermitsPerInterval", "Interval", "Clusters" };

    private static readonly HashSet<string> ClusterLimitsEntryKeys =
        new(StringComparer.OrdinalIgnoreCase) { "PermitsPerInterval", "Interval" };

    private static void RejectUnknownKeys(IConfigurationSection callerSection, string callerId, List<string> errors)
    {
        foreach (var child in callerSection.GetChildren())
        {
            if (!CallerLevelKeys.Contains(child.Key))
            {
                AddUnknownKeyError(errors, callerId, child.Key, CallerLevelKeys);
            }
        }

        RejectUnknownEntryKeys(callerSection.GetSection("Operations"), "Operations", OperationEntryKeys, callerId, errors);

        var limitsSection = callerSection.GetSection("Limits");
        foreach (var child in limitsSection.GetChildren())
        {
            if (!LimitsKeys.Contains(child.Key))
            {
                AddUnknownKeyError(errors, callerId, $"Limits:{child.Key}", LimitsKeys);
            }
        }

        RejectUnknownEntryKeys(
            limitsSection.GetSection("Clusters"), "Limits:Clusters", ClusterLimitsEntryKeys, callerId, errors);
    }

    /// <summary>
    /// Checks one level under each <c>Keys:&lt;i&gt;</c> / <c>Operations:&lt;i&gt;</c> entry.
    /// <c>Methods</c> and <c>Paths</c> are leaf arrays — their children are indexed values,
    /// not keys, and malformed entries there already fail their own validation.
    /// </summary>
    private static void RejectUnknownEntryKeys(
        IConfigurationSection parent, string parentName, HashSet<string> allowed, string callerId, List<string> errors)
    {
        foreach (var entry in parent.GetChildren())
        {
            foreach (var child in entry.GetChildren())
            {
                if (!allowed.Contains(child.Key))
                {
                    AddUnknownKeyError(errors, callerId, $"{parentName}:{entry.Key}:{child.Key}", allowed);
                }
            }
        }
    }

    private static void AddUnknownKeyError(List<string> errors, string callerId, string path, HashSet<string> allowed)
    {
        var known = string.Join(", ", allowed.Order(StringComparer.Ordinal));
        errors.Add(
            $"The caller '{callerId}' declares the unknown configuration key '{path}' under 'CredProx:Callers'. "
            + $"Known keys at that level: {known}. An unknown key is ignored by the binder, which would "
            + "silently weaken the caller's allow-list — fix the spelling or remove the key.");
    }

}
