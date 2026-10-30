using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// One active API key of a caller (§4 Phase B): an id for audit and rotation, the SHA-256
/// hash of the key value (the value itself is never stored), and an optional expiry. A
/// revoked key is simply removed from configuration — the reload drops it from the live
/// registry.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class CallerKey
{
    /// <summary>Creates a key entry. Hash material stays internal to the core.</summary>
    /// <param name="keyId">The key's identifier within its caller.</param>
    /// <param name="hash">The 32-byte SHA-256 hash of the key value.</param>
    /// <param name="expiresAt">When the key stops authenticating; <see langword="null"/> for never.</param>
    public CallerKey(string keyId, byte[] hash, DateTimeOffset? expiresAt)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyId);
        ArgumentNullException.ThrowIfNull(hash);
        if (hash.Length != 32)
        {
            throw new ArgumentException("A caller key hash must be 32 bytes (SHA-256).", nameof(hash));
        }

        KeyId = keyId;
        Hash = hash;
        ExpiresAt = expiresAt;
    }

    /// <summary>The key's identifier within its caller; safe to log.</summary>
    public string KeyId { get; }

    /// <summary>When the key stops authenticating; <see langword="null"/> for never.</summary>
    public DateTimeOffset? ExpiresAt { get; }

    /// <summary>The SHA-256 hash of the key value; never leaves the core.</summary>
    internal byte[] Hash { get; }
}

/// <summary>
/// One operation-allow-list entry of a caller (§4 Phase B): which route (any when
/// omitted), which methods (any when empty) and which path patterns (any when empty) the
/// caller may use. Patterns are matched against the decoded request path; <c>*</c> matches
/// exactly one path segment, a trailing <c>**</c> matches the remaining segments (zero or
/// more). Matching is ordinal and case-sensitive — the strictest reading, so case tricks
/// and homoglyphs simply do not match.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class CallerOperationRule
{
    /// <summary>Creates one allow-list entry.</summary>
    /// <param name="route">The route id this entry applies to; <see langword="null"/> for any route.</param>
    /// <param name="methods">The admitted HTTP methods; empty for any.</param>
    /// <param name="pathPatterns">The admitted path patterns; empty for any path.</param>
    public CallerOperationRule(string? route, IReadOnlyCollection<string> methods, IReadOnlyCollection<string> pathPatterns)
    {
        Route = string.IsNullOrEmpty(route) ? null : route;
        Methods = new HashSet<string>(methods ?? [], StringComparer.Ordinal);
        PathPatterns = (pathPatterns ?? []).ToArray();
    }

    /// <summary>The route id this entry applies to; <see langword="null"/> for any route.</summary>
    public string? Route { get; }

    /// <summary>The admitted HTTP methods (ordinal); empty for any.</summary>
    public IReadOnlySet<string> Methods { get; }

    /// <summary>The admitted path patterns; empty for any path.</summary>
    public IReadOnlyList<string> PathPatterns { get; }

    /// <summary>Whether this entry admits the given operation.</summary>
    /// <param name="routeId">The matched route id.</param>
    /// <param name="method">The request method.</param>
    /// <param name="decodedPath">The decoded, PathBase-stripped request path.</param>
    public bool Matches(string? routeId, string method, string decodedPath)
    {
        if (Route is not null && !string.Equals(Route, routeId, StringComparison.Ordinal))
        {
            return false;
        }

        if (Methods.Count > 0 && !Methods.Contains(method))
        {
            return false;
        }

        if (PathPatterns.Count > 0 && !PathPatterns.Any(p => CredProx.PathPatterns.Matches(decodedPath, p)))
        {
            return false;
        }

        return true;
    }
}

/// <summary>
/// A configured caller: its identity, its active keys, its operation allow-list (an empty
/// list means every operation is allowed — the allow-list is opt-in per caller) and its
/// request budget (M15, plan §3.7 — <see langword="null"/> means unlimited, also opt-in).
/// </summary>
[Experimental("CREDPROX001")]
public sealed class CallerDefinition
{
    /// <summary>Creates a caller definition.</summary>
    /// <param name="callerId">The configured caller id (the config key).</param>
    /// <param name="keys">The active keys; must not be empty.</param>
    /// <param name="operations">The operation allow-list entries; empty means unrestricted.</param>
    /// <param name="limits">The request budget; <see langword="null"/> for unlimited.</param>
    public CallerDefinition(
        string callerId,
        IReadOnlyList<CallerKey> keys,
        IReadOnlyList<CallerOperationRule> operations,
        CallerLimits? limits = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(callerId);
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(operations);

        if (keys.Count == 0)
        {
            throw new ArgumentException($"Caller '{callerId}' must declare at least one key.", nameof(keys));
        }

        CallerId = callerId;
        Keys = keys;
        Operations = operations;
        Limits = limits;
    }

    /// <summary>The configured caller id; also the value the <c>caller:</c> partition source yields.</summary>
    public string CallerId { get; }

    /// <summary>The caller's active keys (multiple during rotation).</summary>
    public IReadOnlyList<CallerKey> Keys { get; }

    /// <summary>The operation allow-list; empty means every operation is allowed.</summary>
    public IReadOnlyList<CallerOperationRule> Operations { get; }

    /// <summary>The caller's request budget (§3.7); <see langword="null"/> means unlimited.</summary>
    public CallerLimits? Limits { get; }
}

/// <summary>
/// One caller's request budget (§3.7): at most <see cref="PermitsPerInterval"/> requests per
/// <see cref="Interval"/>, with per-cluster overrides keyed by YARP cluster id. The budget
/// is per caller app — key rotation and delegated (M14) per-user tokens share it. Exceeding
/// it answers <c>429 credprox.caller_throttled</c> with <c>Retry-After</c>; unlike the
/// cluster throttle there is no queueing. Single-instance, in-memory scope.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class CallerLimits
{
    /// <summary>
    /// Permits allowed per <see cref="Interval"/>; 0 disables the budget (unlimited).
    /// </summary>
    public int PermitsPerInterval { get; set; }

    /// <summary>The budget window; must be positive when <see cref="PermitsPerInterval"/> is set.</summary>
    public TimeSpan Interval { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Per-cluster budget overrides keyed by YARP cluster id; a <see langword="null"/>
    /// member inherits the caller default (same idiom as <c>ThrottleClusterOptions</c>).
    /// </summary>
    public Dictionary<string, CallerClusterLimits> Clusters { get; } = new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// Per-cluster budget overrides; <see langword="null"/> members inherit the caller default.
/// Bound from <c>CredProx:Callers:&lt;id&gt;:Limits:Clusters:&lt;clusterId&gt;</c>.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class CallerClusterLimits
{
    /// <summary>Overrides <see cref="CallerLimits.PermitsPerInterval"/>; 0 disables for this cluster.</summary>
    public int? PermitsPerInterval { get; set; }

    /// <summary>Overrides <see cref="CallerLimits.Interval"/>.</summary>
    public TimeSpan? Interval { get; set; }
}
