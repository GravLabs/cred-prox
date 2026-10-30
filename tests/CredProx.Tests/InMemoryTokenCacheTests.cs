using CredProx;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// §5.2 "Token cache" row: single fetch under 100 concurrent requests; refresh before expiry
/// (at 80% / expires_in − skew); failure cached only for the negative TTL, then retried; one
/// key's failure does not affect other keys; Invalidate forces a refetch; cancellation of one
/// waiter does not cancel the shared fetch.
/// </summary>
public sealed class InMemoryTokenCacheTests
{
    private static readonly DateTimeOffset T0 = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task GetTokenAsync_100ConcurrentWaiters_CallsAcquireExactlyOnce()
    {
        var cache = CreateCache();
        var fetchStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var fetchRelease = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var calls = 0;

        var waiters = Enumerable.Range(0, 100).Select(_ => cache.GetTokenAsync(
            "cred",
            partition: null,
            async ct =>
            {
                Interlocked.Increment(ref calls);
                fetchStarted.TrySetResult();
                await fetchRelease.Task.WaitAsync(TimeSpan.FromSeconds(30)).ConfigureAwait(false);
                return ("token-1", T0 + TimeSpan.FromSeconds(3600));
            },
            CancellationToken.None).AsTask()).ToArray();

        await fetchStarted.Task.WaitAsync(TimeSpan.FromSeconds(30));
        fetchRelease.SetResult();

        var tokens = await Task.WhenAll(waiters);

        Assert.All(tokens, token => Assert.Equal("token-1", token));
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task GetTokenAsync_ServesCachedTokenUntilRefreshPoint_ThenRefetches()
    {
        var time = new FakeTimeProvider(T0);
        var cache = CreateCache(time);
        var calls = 0;

        ValueTask<(string, DateTimeOffset)> Acquire()
        {
            calls++;
            return ValueTask.FromResult(("token-" + calls, T0 + TimeSpan.FromSeconds(100)));
        }

        // Lifetime 100 s: 80% is +80 s, skew bound is +70 s → refresh at +70 s.
        Assert.Equal("token-1", await cache.GetTokenAsync("cred", null, _ => Acquire(), default));
        Assert.Equal(1, calls);

        time.SetUtcNow(T0 + TimeSpan.FromSeconds(69));
        Assert.Equal("token-1", await cache.GetTokenAsync("cred", null, _ => Acquire(), default));
        Assert.Equal(1, calls);

        time.SetUtcNow(T0 + TimeSpan.FromSeconds(71));
        Assert.Equal("token-2", await cache.GetTokenAsync("cred", null, _ => Acquire(), default));
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task GetTokenAsync_ShortLifetime_SkewTriggersRefreshBeforeEightyPercent()
    {
        var time = new FakeTimeProvider(T0);
        var cache = CreateCache(time);
        var calls = 0;

        ValueTask<(string, DateTimeOffset)> Acquire()
        {
            calls++;
            return ValueTask.FromResult(("token-" + calls, time.GetUtcNow() + TimeSpan.FromSeconds(60)));
        }

        // Lifetime 60 s: 80% is +48 s, but the 30 s skew binds at +30 s.
        Assert.Equal("token-1", await cache.GetTokenAsync("cred", null, _ => Acquire(), default));

        time.SetUtcNow(T0 + TimeSpan.FromSeconds(29));
        Assert.Equal("token-1", await cache.GetTokenAsync("cred", null, _ => Acquire(), default));
        Assert.Equal(1, calls);

        time.SetUtcNow(T0 + TimeSpan.FromSeconds(31));
        Assert.Equal("token-2", await cache.GetTokenAsync("cred", null, _ => Acquire(), default));
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task GetTokenAsync_FailureIsCachedOnlyForTheNegativeTtl_ThenRetried()
    {
        var time = new FakeTimeProvider(T0);
        var cache = CreateCache(time);
        var failure = new HttpRequestException("vendor down");
        var calls = 0;

        async ValueTask<(string, DateTimeOffset)> Acquire(CancellationToken ct)
        {
            calls++;
            if (calls == 1)
            {
                throw failure;
            }

            return await ValueTask.FromResult(("token-2", time.GetUtcNow() + TimeSpan.FromSeconds(3600)));
        }

        await Assert.ThrowsAsync<HttpRequestException>(() => cache.GetTokenAsync("cred", null, Acquire, default).AsTask());
        Assert.Equal(1, calls);

        // Within the negative TTL the cached failure is rethrown without a new fetch.
        time.SetUtcNow(T0 + TimeSpan.FromSeconds(4));
        var second = await Assert.ThrowsAsync<HttpRequestException>(
            () => cache.GetTokenAsync("cred", null, Acquire, default).AsTask());
        Assert.Same(failure, second);
        Assert.Equal(1, calls);

        // After the TTL the fetch is attempted again.
        time.SetUtcNow(T0 + TimeSpan.FromSeconds(6));
        Assert.Equal("token-2", await cache.GetTokenAsync("cred", null, Acquire, default));
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task GetTokenAsync_FailureOnOneKey_DoesNotAffectOtherKeys()
    {
        var cache = CreateCache();

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => cache.GetTokenAsync("broken", null, _ => throw new InvalidOperationException("no"), default).AsTask());

        Assert.Equal(
            "fine",
            await cache.GetTokenAsync("healthy", null, _ => ValueTask.FromResult(("fine", T0 + TimeSpan.FromHours(1))), default));
    }

    [Fact]
    public async Task Invalidate_ForcesRefetch()
    {
        var cache = CreateCache();
        var calls = 0;

        ValueTask<(string, DateTimeOffset)> Acquire()
        {
            calls++;
            return ValueTask.FromResult(("token-" + calls, T0 + TimeSpan.FromSeconds(3600)));
        }

        Assert.Equal("token-1", await cache.GetTokenAsync("cred", null, _ => Acquire(), default));
        Assert.Equal("token-1", await cache.GetTokenAsync("cred", null, _ => Acquire(), default));
        Assert.Equal(1, calls);

        cache.Invalidate("cred", null);

        Assert.Equal("token-2", await cache.GetTokenAsync("cred", null, _ => Acquire(), default));
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task Invalidate_ForcesRefetchAfterFailure()
    {
        var cache = CreateCache();
        var calls = 0;

        ValueTask<(string, DateTimeOffset)> Acquire(CancellationToken ct)
        {
            calls++;
            if (calls == 1)
            {
                return ValueTask.FromException<(string, DateTimeOffset)>(new InvalidOperationException("down"));
            }

            return ValueTask.FromResult(("token-2", T0 + TimeSpan.FromSeconds(3600)));
        }

        await Assert.ThrowsAsync<InvalidOperationException>(() => cache.GetTokenAsync("cred", null, Acquire, default).AsTask());

        // Still inside the negative TTL, but Invalidate clears it.
        cache.Invalidate("cred", null);
        Assert.Equal("token-2", await cache.GetTokenAsync("cred", null, Acquire, default));
    }

    [Fact]
    public async Task Invalidate_DuringInFlightFetch_DiscardsTheStaleResult()
    {
        var cache = CreateCache();
        var fetchStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var fetchRelease = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var calls = 0;

        var inFlight = cache.GetTokenAsync(
            "cred",
            null,
            async ct =>
            {
                Interlocked.Increment(ref calls);
                fetchStarted.TrySetResult();
                await fetchRelease.Task.WaitAsync(TimeSpan.FromSeconds(30)).ConfigureAwait(false);
                return ("stale-token", T0 + TimeSpan.FromSeconds(3600));
            },
            CancellationToken.None).AsTask();

        await fetchStarted.Task.WaitAsync(TimeSpan.FromSeconds(30));

        // Invalidate while the fetch is in flight; the generation guard must discard its
        // result instead of caching it. The caller that started the fetch is still served
        // (its request predates the invalidation), but nothing is left in the cache.
        cache.Invalidate("cred", null);
        fetchRelease.SetResult();

        Assert.Equal("stale-token", await inFlight);

        ValueTask<(string, DateTimeOffset)> FreshAcquire(CancellationToken ct)
        {
            calls++;
            return ValueTask.FromResult(("fresh-token", T0 + TimeSpan.FromSeconds(3600)));
        }

        Assert.Equal("fresh-token", await cache.GetTokenAsync("cred", null, FreshAcquire, default));
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task CancellationOfOneWaiter_DoesNotCancelTheSharedFetch()
    {
        var cache = CreateCache();
        var fetchStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var fetchRelease = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var calls = 0;

        using var cancellingWaiterCts = new CancellationTokenSource();

        var cancellingWaiter = cache.GetTokenAsync(
            "cred",
            null,
            async ct =>
            {
                Interlocked.Increment(ref calls);
                fetchStarted.TrySetResult();
                await fetchRelease.Task.WaitAsync(TimeSpan.FromSeconds(30)).ConfigureAwait(false);
                return ("token-1", T0 + TimeSpan.FromSeconds(3600));
            },
            cancellingWaiterCts.Token).AsTask();

        await fetchStarted.Task.WaitAsync(TimeSpan.FromSeconds(30));

        // A second waiter queues on the gate behind the in-flight fetch.
        var patientWaiter = cache.GetTokenAsync(
            "cred",
            null,
            _ => throw new InvalidOperationException("must not fetch again"),
            CancellationToken.None);

        cancellingWaiterCts.Cancel();
        fetchRelease.SetResult();

        // The cancelling waiter comes back cancelled, but the shared fetch completed and the
        // patient waiter is served its result — acquire ran exactly once.
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancellingWaiter);
        Assert.Equal("token-1", await patientWaiter);
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task GetTokenAsync_PartitionedKeysAreCachedSeparately()
    {
        var cache = CreateCache();
        var calls = 0;

        ValueTask<(string, DateTimeOffset)> Acquire()
        {
            calls++;
            return ValueTask.FromResult(("token-" + calls, T0 + TimeSpan.FromSeconds(3600)));
        }

        Assert.Equal("token-1", await cache.GetTokenAsync("cred", "uat", _ => Acquire(), default));
        Assert.Equal("token-2", await cache.GetTokenAsync("cred", "app", _ => Acquire(), default));
        Assert.Equal("token-1", await cache.GetTokenAsync("cred", "uat", _ => Acquire(), default));
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task GetTokenAsync_RejectsNullArguments()
    {
        var cache = CreateCache();

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => cache.GetTokenAsync(null!, null, _ => default, default).AsTask());
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => cache.GetTokenAsync("cred", null, null!, default).AsTask());
        Assert.Throws<ArgumentNullException>(() => cache.Invalidate(null!, null));
    }

    private static InMemoryTokenCache CreateCache(TimeProvider? time = null) =>
        new(Options.Create(new TokenCacheOptions()), time ?? new FakeTimeProvider(T0));
}
