using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace CredProx;

/// <summary>
/// Binds every <c>CredProx:Callers:&lt;id&gt;</c> section into a <see cref="CallerRegistry"/>
/// (see <c>docs/credprox-plan.md</c> §4 Phase B): keys are validated and their hashes
/// resolved at startup, so a malformed hash, an unresolvable <c>secret:</c> reference or a
/// broken operation pattern fails startup with one
/// <see cref="OptionsValidationException"/> naming the caller and key id — never a key
/// value or hash. Unknown configuration keys under a caller are rejected too (M14a): a
/// typo in an allow-list entry must fail closed, never silently widen the caller's access.
/// </summary>
/// <remarks>
/// A key hash is configured as <c>sha256:&lt;hex&gt;</c> or as a <c>secret:</c> reference
/// whose resolved value has that shape — the hash itself may live in any secret source.
/// </remarks>
[Experimental("CREDPROX001")]
public sealed class CallerBinder
{
    private readonly IConfiguration _configuration;
    private readonly SecretAccessorFactory _accessorFactory;

    /// <summary>Creates the binder.</summary>
    /// <param name="configuration">The application configuration root.</param>
    /// <param name="accessorFactory">Scopes each caller to its own secret references.</param>
    public CallerBinder(IConfiguration configuration, SecretAccessorFactory accessorFactory)
    {
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        _accessorFactory = accessorFactory ?? throw new ArgumentNullException(nameof(accessorFactory));
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

        foreach (var section in _configuration.GetSection("CredProx:Callers").GetChildren())
        {
            if (TryBindOne(section, errors, out var definition))
            {
                callers[section.Key] = definition;
            }
        }

        return (errors.Count == 0 ? new CallerRegistry(callers) : null, errors);
    }

    private bool TryBindOne(IConfigurationSection section, List<string> errors, out CallerDefinition definition)
    {
        var callerId = section.Key;
        RejectUnknownKeys(section, callerId, errors);
        var secrets = _accessorFactory.CreateAccessor(section);
        var keys = new List<CallerKey>();
        var keyIds = new HashSet<string>(StringComparer.Ordinal);

        foreach (var keySection in section.GetSection("Keys").GetChildren())
        {
            var keyId = keySection["KeyId"];
            if (string.IsNullOrWhiteSpace(keyId))
            {
                errors.Add($"The caller '{callerId}' has a key with no KeyId.");
                continue;
            }

            if (!keyIds.Add(keyId))
            {
                errors.Add($"The caller '{callerId}' declares the KeyId '{keyId}' twice.");
                continue;
            }

            var hashDeclaration = keySection["KeyHash"];
            if (string.IsNullOrWhiteSpace(hashDeclaration))
            {
                errors.Add($"The caller '{callerId}' key '{keyId}' has no KeyHash.");
                continue;
            }

            var hash = ResolveHash(secrets, hashDeclaration, callerId, keyId, errors);
            if (hash is null)
            {
                continue;
            }

            DateTimeOffset? expiresAt = null;
            var expiry = keySection["ExpiresAt"];
            if (!string.IsNullOrWhiteSpace(expiry))
            {
                if (!DateTimeOffset.TryParse(expiry, CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed))
                {
                    errors.Add($"The caller '{callerId}' key '{keyId}' has an ExpiresAt that is not a date-time.");
                    continue;
                }

                expiresAt = parsed;
            }

            keys.Add(new CallerKey(keyId, hash, expiresAt));
        }

        if (keys.Count == 0 && errors.Count == 0)
        {
            errors.Add($"The caller '{callerId}' declares no usable key under Keys.");
        }

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
        if (errors.Count > 0 || keys.Count == 0)
        {
            return false;
        }

        definition = new CallerDefinition(callerId, keys, operations, limits);
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

        rule = new CallerOperationRule(
            route,
            methods.Where(m => m is not null).Select(m => m!).ToList(),
            patterns.Where(p => p is not null).Select(p => p!).ToList());
        return true;
    }

    // The exact key shape this binder reads. Anything else under a caller is a typo —
    // and a typo in an allow-list entry (e.g. "PathPatterns" for "Paths") would otherwise
    // be silently ignored and admit the caller to EVERYTHING. A security allow-list fails
    // closed on a config error (M14a), at startup and on reload alike.
    private static readonly HashSet<string> CallerLevelKeys =
        new(StringComparer.OrdinalIgnoreCase) { "Keys", "Operations", "Limits" };

    private static readonly HashSet<string> KeyEntryKeys =
        new(StringComparer.OrdinalIgnoreCase) { "KeyId", "KeyHash", "ExpiresAt" };

    private static readonly HashSet<string> OperationEntryKeys =
        new(StringComparer.OrdinalIgnoreCase) { "Route", "Methods", "Paths" };

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

        RejectUnknownEntryKeys(callerSection.GetSection("Keys"), "Keys", KeyEntryKeys, callerId, errors);
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

    private byte[]? ResolveHash(
        ScopedSecretAccessor secrets,
        string declaration,
        string callerId,
        string keyId,
        List<string> errors)
    {
        var value = declaration;
        if (declaration.StartsWith(SecretReferences.Prefix, StringComparison.Ordinal))
        {
            var name = declaration[SecretReferences.Prefix.Length..];
            try
            {
                value = secrets.GetSecretAsync(name, CancellationToken.None).AsTask().GetAwaiter().GetResult();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                errors.Add($"The caller '{callerId}' key '{keyId}' could not resolve its KeyHash secret: {ex.Message}");
                return null;
            }

            if (string.IsNullOrWhiteSpace(value))
            {
                errors.Add($"The caller '{callerId}' key '{keyId}' resolved an empty KeyHash secret.");
                return null;
            }
        }

        if (!TryParseHash(value!, out var hash))
        {
            errors.Add($"The caller '{callerId}' key '{keyId}' has a KeyHash that is not 'sha256:<64 hex digits>'.");
            return null;
        }

        return hash;
    }

    /// <summary>
    /// Parses <c>sha256:&lt;hex&gt;</c> (case-insensitive hex). The hash — never the key —
    /// is what configuration stores.
    /// </summary>
    internal static bool TryParseHash(string value, out byte[] hash)
    {
        hash = [];
        const string prefix = "sha256:";
        if (!value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) || value.Length != prefix.Length + 64)
        {
            return false;
        }

        var hex = value[prefix.Length..];
        var bytes = new byte[32];
        for (var i = 0; i < 32; i++)
        {
            if (!byte.TryParse(hex.AsSpan(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var b))
            {
                return false;
            }

            bytes[i] = b;
        }

        hash = bytes;
        return true;
    }
}
