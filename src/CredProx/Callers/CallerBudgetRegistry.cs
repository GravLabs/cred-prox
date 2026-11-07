using System.Collections.Concurrent;
using System.Threading.RateLimiting;

namespace CredProx;

/// <summary>
/// Per-caller request-budget limiters (M15, plan §3.7): one fixed-window counter per
/// (caller id × cluster) pair, created lazily from the caller's effective limits. Keys come
/// from <em>configuration</em> (caller ids and cluster ids), never from request data — an
/// attacker or a hostile IdP cannot grow this dictionary (§3.7).
/// </summary>
/// <remarks>
/// Singleton like <see cref="ClusterThrottleRegistry"/>. Each key holds one immutable record
/// pairing the limiter with the limits that produced it, so a first concurrent burst against
/// a fresh key converges on a single limiter: <c>GetOrAdd</c> is atomic and the replace block
/// is entered only when the configured limits genuinely differ (review F1 — the earlier
/// two-dictionary shape let every thread in a first burst replace a live limiter, which both
/// disposed a limiter another thread held and over-admitted the budget). A config rebind that
/// changes a caller's limits replaces that pair's record (fresh window — the design states
/// windows reset on rebind); unchanged limits keep it. A replaced limiter is never disposed:
/// in-flight threads may still hold it, it owns no unmanaged resources, and with
/// <c>queueLimit: 0</c> and only <see cref="RateLimiter.AttemptAcquire(int)"/> there are no
/// queued waiters to strand. A benign race may let one window straddle a limits change,
/// never a leak and never an over-admission within a window.
/// </remarks>
internal sealed class CallerBudgetRegistry(TimeProvider time)
{
    // The default-budget key for requests whose cluster is unknown at this stage.
    public const string DefaultClusterKey = "*";

    private sealed record Budget(FixedWindowRateLimiter Limiter, int Permits, TimeSpan Interval);

    private readonly ConcurrentDictionary<string, Budget> _budgets = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Tries to take one permit from the caller's budget for <paramref name="clusterKey"/>.
    /// Returns <see langword="true"/> when admitted; on rejection,
    /// <paramref name="retryAfter"/> carries the time to the window reset.
    /// </summary>
    public bool TryAcquire(string callerId, string clusterKey, int permitsPerInterval, TimeSpan interval, out TimeSpan retryAfter)
    {
        var key = string.Concat(callerId, "|", clusterKey);
        var state = (Permits: permitsPerInterval, Interval: interval, Time: time);

        var budget = _budgets.GetOrAdd(key, static (k, s) => Create(s), state);

        // Replace on a limits change (rebind): same key, fresh window (§3.7). The factory
        // compares the current record's own limits, so concurrent replacements converge onto
        // one surviving record and a first burst never replaces a live limiter.
        if (budget.Permits != permitsPerInterval || budget.Interval != interval)
        {
            budget = _budgets.AddOrUpdate(
                key,
                static (k, s) => Create(s),
                static (k, current, s) => current.Permits == s.Permits && current.Interval == s.Interval
                    ? current
                    : Create(s),
                state);
        }

        using var lease = budget.Limiter.AttemptAcquire(1);
        if (lease.IsAcquired)
        {
            retryAfter = default;
            return true;
        }

        retryAfter = lease.TryGetMetadata(MetadataName.RetryAfter, out var advertised)
            ? (TimeSpan)advertised!
            : interval;
        return false;
    }

    /// <summary>Drops every window (whole-registry rebind; tests).</summary>
    public void Clear()
    {
        foreach (var key in _budgets.Keys.ToArray())
        {
            // No Dispose: in-flight threads may still hold the record, and the limiters own
            // no unmanaged resources (see type remarks).
            _budgets.TryRemove(key, out _);
        }
    }

    private static Budget Create((int Permits, TimeSpan Interval, TimeProvider Time) state) =>
        new(new FixedWindowRateLimiter(state.Permits, state.Interval, queueLimit: 0, state.Time), state.Permits, state.Interval);
}
