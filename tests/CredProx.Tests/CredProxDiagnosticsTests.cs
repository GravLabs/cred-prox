using System.Diagnostics.Metrics;
using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// §5.2 "Diagnostics" row: token fetches and cache hits/misses are observable through a
/// <see cref="Meter"/> with credential and outcome tags — never token values.
/// </summary>
public sealed class CredProxDiagnosticsTests
{
    [Fact]
    public async Task CacheMissThenHit_RecordFetchAndCacheCounters()
    {
        // Parallel tests emit into the same static instruments, so the sink must be
        // thread-safe.
        var measurements = new System.Collections.Concurrent.ConcurrentQueue<(string Instrument, Dictionary<string, object?> Tags)>();

        // The instruments are static and may be published before this listener exists
        // (parallel test collections), so enable them directly rather than via
        // InstrumentPublished.
        using var listener = new MeterListener();
        listener.EnableMeasurementEvents(CredProxDiagnostics.TokenFetches);
        listener.EnableMeasurementEvents(CredProxDiagnostics.TokenCacheResults);
        listener.EnableMeasurementEvents(CredProxDiagnostics.TokenFetchDuration);
        void Record(string name, ReadOnlySpan<KeyValuePair<string, object?>> tags) =>
            measurements.Enqueue((name, tags.ToArray().ToDictionary(t => t.Key, t => t.Value)));
        listener.SetMeasurementEventCallback<long>((instrument, _, tags, _) => Record(instrument.Name, tags));
        listener.SetMeasurementEventCallback<double>((instrument, _, tags, _) => Record(instrument.Name, tags));
        listener.Start();

        var cache = new InMemoryTokenCache(Options.Create(new TokenCacheOptions()), new FakeTimeProvider());
        await cache.GetTokenAsync("arm", "p1", _ => new(("tok", DateTimeOffset.UtcNow + TimeSpan.FromHours(1))), default);
        await cache.GetTokenAsync("arm", "p1", _ => new(("tok", DateTimeOffset.UtcNow + TimeSpan.FromHours(1))), default);

        Assert.Contains(measurements, m => m.Instrument == "credprox.token.cache"
            && Equals(m.Tags["credprox.credential"], "arm") && Equals(m.Tags["result"], "miss"));
        Assert.Contains(measurements, m => m.Instrument == "credprox.token.cache"
            && Equals(m.Tags["credprox.credential"], "arm") && Equals(m.Tags["result"], "hit"));
        Assert.Contains(measurements, m => m.Instrument == "credprox.token.fetches"
            && Equals(m.Tags["outcome"], "success"));
        Assert.Contains(measurements, m => m.Instrument == "credprox.token.fetch.duration"
            && Equals(m.Tags["credprox.credential"], "arm"));
    }

    [Fact]
    public async Task FailedFetch_RecordsFailureOutcome()
    {
        var outcomes = new System.Collections.Concurrent.ConcurrentQueue<string?>();
        using var listener = new MeterListener();
        listener.EnableMeasurementEvents(CredProxDiagnostics.TokenFetches);
        listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, state) =>
            outcomes.Enqueue(tags.ToArray().FirstOrDefault(t => t.Key == "outcome").Value as string));
        listener.Start();

        var cache = new InMemoryTokenCache(Options.Create(new TokenCacheOptions()), new FakeTimeProvider());

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            cache.GetTokenAsync("arm", null, _ => ValueTask.FromException<(string, DateTimeOffset)>(
                new InvalidOperationException("vendor down")), default).AsTask());

        Assert.Contains("failure", outcomes);
    }
}
