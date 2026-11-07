using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.ExceptionServices;
using CredProx.Abstractions;
using Microsoft.Extensions.Options;

namespace CredProx;

/// <summary>
/// The default in-memory <see cref="ITokenCache"/> (see <c>docs/credprox-plan.md</c> §3.3):
/// single-flight per <c>(credential, partition)</c> key, early refresh before expiry, and a
/// short negative cache on failure. All state transitions for a key happen under that key's
/// lock, and at most one fetch per key is in flight at a time.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class InMemoryTokenCache : ITokenCache
{
    private readonly ConcurrentDictionary<TokenCacheKey, KeyState> _states = new();
    private readonly TokenCacheOptions _options;
    private readonly TimeProvider _time;

    /// <summary>
    /// Creates the cache.
    /// </summary>
    /// <param name="options">The cache behaviour options.</param>
    /// <param name="time">The time source used for all expiry decisions.</param>
    public InMemoryTokenCache(IOptions<TokenCacheOptions> options, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options.Value;
        _time = time ?? throw new ArgumentNullException(nameof(time));
    }

    /// <inheritdoc />
    public async ValueTask<string> GetTokenAsync(
        string credential,
        string? partition,
        Func<CancellationToken, ValueTask<(string Value, DateTimeOffset ExpiresAt)>> acquire,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(acquire);

        var state = _states.GetOrAdd(new TokenCacheKey(credential, partition), static _ => new KeyState());

        // Fast path: a fresh token is served without touching the gate.
        lock (state.Sync)
        {
            if (Serve(state) is { } cached)
            {
                CredProxDiagnostics.RecordCacheResult(credential, hit: true);
                return cached;
            }
        }

        // One gate wait per key: the first caller fetches, everyone else waits on the gate
        // and then reads the result the fetcher stored. The fetch itself runs with
        // CancellationToken.None, so cancelling one waiter never cancels the shared fetch.
        await state.Gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (state.Sync)
            {
                if (Serve(state) is { } cached)
                {
                    CredProxDiagnostics.RecordCacheResult(credential, hit: true);
                    return cached;
                }
            }

            CredProxDiagnostics.RecordCacheResult(credential, hit: false);

            var generation = Volatile.Read(ref state.Generation);
            var startedAt = _time.GetUtcNow();
            string value;
            DateTimeOffset expiresAt;
            Exception? error = null;
            var fetchStart = Stopwatch.GetTimestamp();
            using (var activity = CredProxDiagnostics.ActivitySource.StartActivity("token.fetch"))
            {
                activity?.SetTag("credprox.credential", credential);
                activity?.SetTag("credprox.partition", partition);
                try
                {
                    (value, expiresAt) = await acquire(CancellationToken.None).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    value = string.Empty;
                    expiresAt = default;
                    error = ex;
                }
            }

            CredProxDiagnostics.RecordFetch(
                credential, success: error is null, Stopwatch.GetElapsedTime(fetchStart).TotalSeconds);

            lock (state.Sync)
            {
                // A concurrent Invalidate bumped the generation: this fetch predates it, so
                // its result is dropped and the next caller refetches.
                if (state.Generation == generation)
                {
                    if (error is null)
                    {
                        state.Token = new CachedToken(value, ComputeRefreshAt(startedAt, expiresAt));
                        state.Failure = null;
                    }
                    else
                    {
                        state.Failure = new CachedFailure(error, _time.GetUtcNow() + _options.NegativeCacheTtl);
                        state.Token = null;
                    }
                }
            }

            // This waiter asked to be cancelled: hand back its cancellation, but the result
            // above is already stored for the waiters that stayed.
            cancellationToken.ThrowIfCancellationRequested();

            if (error is not null)
            {
                ExceptionDispatchInfo.Capture(error).Throw();
            }

            return value;
        }
        finally
        {
            state.Gate.Release();
        }
    }

    /// <inheritdoc />
    public void Invalidate(string credential, string? partition)
    {
        ArgumentNullException.ThrowIfNull(credential);

        if (_states.TryGetValue(new TokenCacheKey(credential, partition), out var state))
        {
            lock (state.Sync)
            {
                state.Generation++;
                state.Token = null;
                state.Failure = null;
            }
        }
    }

    /// <summary>
    /// Returns a cached token when one is valid, rethrows a negatively cached failure, or
    /// returns <see langword="null"/> when a fetch is needed. The caller must hold
    /// <c>state.Sync</c>.
    /// </summary>
    private string? Serve(KeyState state)
    {
        var now = _time.GetUtcNow();
        if (state.Token is { } token && now < token.RefreshAt)
        {
            return token.Value;
        }

        if (state.Failure is { } failure && now < failure.Until)
        {
            ExceptionDispatchInfo.Capture(failure.Error).Throw();
        }

        return null;
    }

    /// <summary>
    /// A token is served while <c>now &lt; min(started + lifetime × RefreshFraction,
    /// ExpiresAt − Skew)</c> — whichever comes first.
    /// </summary>
    private DateTimeOffset ComputeRefreshAt(DateTimeOffset startedAt, DateTimeOffset expiresAt)
    {
        var refreshAt = startedAt + (expiresAt - startedAt) * _options.RefreshFraction;
        var skewBound = expiresAt - _options.Skew;
        return skewBound < refreshAt ? skewBound : refreshAt;
    }

    private readonly record struct TokenCacheKey(string Credential, string? Partition);

    private sealed class KeyState
    {
        /// <summary>Protects every field below. Never held across an await.</summary>
        public readonly object Sync = new();

        /// <summary>Serializes fetches for this key; held across the fetch.</summary>
        public readonly SemaphoreSlim Gate = new(1, 1);

        public long Generation;

        public CachedToken? Token;

        public CachedFailure? Failure;
    }

    private sealed record CachedToken(string Value, DateTimeOffset RefreshAt);

    private sealed record CachedFailure(Exception Error, DateTimeOffset Until);
}
