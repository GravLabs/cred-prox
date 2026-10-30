using CredProx;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace CredProx.LoadTests;

/// <summary>
/// §5.2 "Token cache" under sustained load: through repeated waves of concurrent
/// callers spanning several refresh cycles, the cache stays single-flight — one vendor
/// fetch per refresh cycle, never one per caller.
/// </summary>
[Trait("Layer", "Nightly")]
public sealed class TokenCacheLoadTests
{
    private static readonly DateTimeOffset T0 = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task SustainedWaves_CacheStaysSingleFlight()
    {
        const int Waves = 5;
        const int PerWave = 100;
        var time = new FakeTimeProvider(T0);
        var cache = new InMemoryTokenCache(Options.Create(new TokenCacheOptions()), time);
        var fetches = 0;

        for (var wave = 1; wave <= Waves; wave++)
        {
            var expected = $"token-{wave}";
            var tokens = await Task
                .WhenAll(Enumerable.Range(0, PerWave).Select(async _ =>
                {
                    // Stagger inside the wave so callers arrive while the fetch is in
                    // flight and after it lands — both must join the same single flight.
                    await Task.Delay(Random.Shared.Next(0, 5));
                    return await cache.GetTokenAsync(
                        "cred",
                        partition: null,
                        async ct =>
                        {
                            Interlocked.Increment(ref fetches);
                            await Task.Delay(20, ct);
                            return (expected, time.GetUtcNow() + TimeSpan.FromMinutes(60));
                        },
                        CancellationToken.None);
                }))
                .WaitBoundedAsync($"wave {wave}");

            Assert.All(tokens, token => Assert.Equal(expected, token));

            // Past the refresh point: the next wave legitimately refetches — once.
            time.Advance(TimeSpan.FromMinutes(61));
        }

        Assert.Equal(Waves, Volatile.Read(ref fetches));
    }
}
