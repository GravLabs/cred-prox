using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// One operation-allow-list entry of a caller: which route (any when
/// omitted), which methods (any when empty) and which path patterns (any when empty) the
/// caller may use, optionally gated by a scope <see cref="CallerOperationRule.Name"/>
/// (ADR-0004). Patterns are matched against the decoded request path; <c>*</c> matches
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
    /// <param name="name">
    /// The scope name of this entry (ADR-0004): on a request carrying a scope set
    /// (a caller token's <c>roles</c>/<c>scp</c>) only named entries run, and only when
    /// their name is among the request's scopes. <see langword="null"/> means the entry
    /// admits keys but never a token — name your rules to give an agent caller scopes.
    /// </param>
    public CallerOperationRule(
        string? route,
        IReadOnlyCollection<string> methods,
        IReadOnlyCollection<string> pathPatterns,
        string? name = null)
    {
        Route = string.IsNullOrEmpty(route) ? null : route;
        Methods = new HashSet<string>(methods ?? [], StringComparer.Ordinal);
        PathPatterns = (pathPatterns ?? []).ToArray();
        Name = string.IsNullOrEmpty(name) ? null : name;
    }

    /// <summary>The route id this entry applies to; <see langword="null"/> for any route.</summary>
    public string? Route { get; }

    /// <summary>The admitted HTTP methods (ordinal); empty for any.</summary>
    public IReadOnlySet<string> Methods { get; }

    /// <summary>The admitted path patterns; empty for any path.</summary>
    public IReadOnlyList<string> PathPatterns { get; }

    /// <summary>
    /// The scope name of this entry (ADR-0004), compared ordinal to the request's
    /// scope set; <see langword="null"/> for an unnamed entry, which no token request
    /// can match (the caller-key path ignores it). <see cref="Matches"/> ignores it —
    /// the allow-list stage applies it.
    /// </summary>
    public string? Name { get; }

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
/// A configured caller: its identity, its operation allow-list (an empty list means every
/// operation is allowed — the allow-list is opt-in per caller) and its request budget
/// (<see langword="null"/> means unlimited, also opt-in). Authentication
/// material — caller keys under <c>CredProx.CallerKeys</c>, token client ids under
/// <c>CredProx.CallerTokens</c> — is read by the package that owns it, never by the core.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class CallerDefinition
{
    /// <summary>Creates a caller definition.</summary>
    /// <param name="callerId">The configured caller id (the config key).</param>
    /// <param name="operations">The operation allow-list entries; empty means unrestricted.</param>
    /// <param name="limits">The request budget; <see langword="null"/> for unlimited.</param>
    public CallerDefinition(
        string callerId,
        IReadOnlyList<CallerOperationRule> operations,
        CallerLimits? limits = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(callerId);
        ArgumentNullException.ThrowIfNull(operations);

        CallerId = callerId;
        Operations = operations;
        Limits = limits;
    }

    /// <summary>The configured caller id; also the value the <c>caller:</c> partition source yields.</summary>
    public string CallerId { get; }

    /// <summary>The operation allow-list; empty means every operation is allowed.</summary>
    public IReadOnlyList<CallerOperationRule> Operations { get; }

    /// <summary>The caller's request budget; <see langword="null"/> means unlimited.</summary>
    public CallerLimits? Limits { get; }
}

/// <summary>
/// One caller's request budget: at most <see cref="PermitsPerInterval"/> requests per
/// <see cref="Interval"/>, with per-cluster overrides keyed by YARP cluster id. The budget
/// is per caller app — key rotation and delegated per-user tokens share it. Exceeding
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
    /// member inherits the caller default (the idiom <c>CredProx.Operations</c> uses for
    /// <c>ThrottleClusterOptions</c>).
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
