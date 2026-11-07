using BenchmarkDotNet.Attributes;
using CredProx;
using Microsoft.Extensions.Options;

namespace CredProx.Benchmarks;

/// <summary>
/// The token cache hot paths (plan §3.3): the lock-guarded fresh-token fast path every
/// proxied request takes on a warm key, and the single-flight gate when a cold key is
/// hit by many requests at once — one fetch, everyone else waits and reads.
/// </summary>
[MemoryDiagnoser]
public class TokenCacheBenchmarks
{
    private const int SingleFlightConcurrency = 64;

    private InMemoryTokenCache _cache = null!;

    [GlobalSetup]
    public void Setup()
    {
        _cache = new InMemoryTokenCache(Options.Create(new TokenCacheOptions()), TimeProvider.System);

        // Warm the key the hit benchmark reads: a day of freshness keeps it out of the
        // early-refresh window for the whole run.
        _cache.GetTokenAsync(
            "hit",
            null,
            _ => ValueTask.FromResult(("cached-token", DateTimeOffset.UtcNow.AddDays(1))),
            default).AsTask().GetAwaiter().GetResult();
    }

    /// <summary>Warm key: dictionary lookup + lock + expiry check; the acquire never runs.</summary>
    [Benchmark(Baseline = true)]
    public ValueTask<string> CacheHit() =>
        _cache.GetTokenAsync(
            "hit",
            null,
            _ => ValueTask.FromResult(("never-called", DateTimeOffset.UtcNow.AddDays(1))),
            default);

    /// <summary>
    /// Cold key, 64 concurrent callers: one fetch through the gate, 63 reads of its
    /// result. The key is invalidated per operation so every operation pays the full
    /// single-flight cycle.
    /// </summary>
    [Benchmark]
    public async ValueTask<string> SingleFlight()
    {
        _cache.Invalidate("cold", null);

        var waiters = new ValueTask<string>[SingleFlightConcurrency];
        for (var i = 0; i < SingleFlightConcurrency; i++)
        {
            waiters[i] = _cache.GetTokenAsync("cold", null, AcquireAsync, default);
        }

        string last = string.Empty;
        for (var i = 0; i < SingleFlightConcurrency; i++)
        {
            last = await waiters[i].ConfigureAwait(false);
        }

        return last;
    }

    private static async ValueTask<(string Value, DateTimeOffset ExpiresAt)> AcquireAsync(CancellationToken cancellationToken)
    {
        await Task.Delay(1, CancellationToken.None).ConfigureAwait(false); // stands in for a vendor round trip
        return ("fresh-token", DateTimeOffset.UtcNow.AddDays(1));
    }
}
