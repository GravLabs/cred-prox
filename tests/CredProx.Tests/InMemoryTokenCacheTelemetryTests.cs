using System.Diagnostics;
using System.Diagnostics.Metrics;
using CredProx;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage for <see cref="InMemoryTokenCache">: the operator-visible
/// telemetry (cache hit/miss metrics on both serve paths, the named fetch activity
/// with its tags) and the ctor guards. Telemetry is behaviour — these mutants survive
/// every token-correctness test because nothing read the counters or the activity.
/// </summary>
public sealed class InMemoryTokenCacheTelemetryTests
{
    private static readonly DateTimeOffset T0 = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Ctor_NullOptions_Throws_NamingOptions()
    {
        var ex = Assert.Throws<ArgumentNullException>(() =>
            new InMemoryTokenCache(null!, new FakeTimeProvider(T0)));

        Assert.Equal("options", ex.ParamName);
    }

    [Fact]
    public void Ctor_NullTime_Throws_NamingTime()
    {
        var ex = Assert.Throws<ArgumentNullException>(() =>
            new InMemoryTokenCache(Options.Create(new TokenCacheOptions()), null!));

        Assert.Equal("time", ex.ParamName);
    }

    [Fact]
    public async Task CacheResults_Metric_RecordsMissThenFastPathHit()
    {
        const string Cred = "tel-sequential";
        using var _ = ListenCacheResults(Cred, out var results);
        var cache = CreateCache();
        var fetches = 0;

        ValueTask<(string, DateTimeOffset)> Acquire(CancellationToken ct)
        {
            fetches++;
            return ValueTask.FromResult(("tok", T0.AddMinutes(5)));
        }

        Assert.Equal("tok", await cache.GetTokenAsync(Cred, null, Acquire, default));
        Assert.Equal("tok", await cache.GetTokenAsync(Cred, null, Acquire, default));

        Assert.Equal(1, fetches);
        Assert.Equal(["miss", "hit"], results);
    }

    // The gate-waiter serve (after the fetcher stored the token) must record its hit
    // too — otherwise single-flight hits are invisible to cache-hit-rate operations.
    [Fact]
    public async Task CacheResults_Metric_WaiterServedInsideGate_RecordsHit()
    {
        const string Cred = "tel-waiter";
        using var _ = ListenCacheResults(Cred, out var results);
        var cache = CreateCache();
        using var release = new SemaphoreSlim(0);
        var fetchStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        async ValueTask<(string, DateTimeOffset)> Acquire(CancellationToken ct)
        {
            fetchStarted.SetResult();
            await release.WaitAsync(ct);
            return ("tok", T0.AddMinutes(5));
        }

        var first = cache.GetTokenAsync(Cred, null, Acquire, default);
        await fetchStarted.Task;
        var second = cache.GetTokenAsync(Cred, null, Acquire, default);
        await Task.Delay(50); // ensure the waiter is parked on the gate before the fetch lands
        release.Release();

        Assert.Equal("tok", await first);
        Assert.Equal("tok", await second);
        Assert.Single(results, r => r == "miss"); // exactly one fetch
        Assert.Contains("hit", results); // the waiter's inside-gate serve recorded it
    }

    [Fact]
    public async Task Fetch_Activity_NamedTokenFetch_TagsCredentialAndPartition()
    {
        var stopped = new List<Activity>();
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == CredProxDiagnostics.ActivitySourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity =>
            {
                lock (stopped)
                {
                    stopped.Add(activity);
                }
            },
        };
        ActivitySource.AddActivityListener(listener);

        var cache = CreateCache();
        await cache.GetTokenAsync(
            "tel-activity", "tenant-9",
            _ => ValueTask.FromResult(("tok", T0.AddMinutes(5))),
            default);

        // Snapshot under the lock before asserting: the process-wide ActivitySource
        // also fires for parallel test classes, whose listener callbacks would
        // otherwise mutate the list mid-enumeration (Collection was modified).
        Activity[] snapshot;
        lock (stopped)
        {
            snapshot = stopped.ToArray();
        }

        var fetch = Assert.Single(
            snapshot,
            a => (string?)a.GetTagItem("credprox.credential") == "tel-activity");
        Assert.Equal("token.fetch", fetch.OperationName);
        Assert.Equal("tenant-9", (string?)fetch.GetTagItem("credprox.partition"));
    }

    private static InMemoryTokenCache CreateCache() =>
        new(Options.Create(new TokenCacheOptions()), new FakeTimeProvider(T0));

    // Measurements are filtered to one credential so the class stays parallel-safe
    // against other cache tests emitting on the same shared meter.
    private static MeterListener ListenCacheResults(string credential, out List<string> results)
    {
        var seen = new List<string>();
        var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter.Name == CredProxDiagnostics.MeterName
                && instrument.Name == "credprox.token.cache")
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((_, _, tags, _) =>
        {
            if (tags.Length < 2)
            {
                return;
            }

            var cred = tags[0].Value as string;
            var result = tags[1].Value as string;
            if (cred == credential && result is not null)
            {
                lock (seen)
                {
                    seen.Add(result);
                }
            }
        });
        listener.Start();
        results = seen;
        return listener;
    }
}
