using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;
using Xunit;

namespace CredProx.Testing;

/// <summary>
/// The conformance suite for <see cref="ITokenCache"/> implementations (see
/// <c>docs/credprox-plan.md</c> §5.2 "Token cache"): single fetch under concurrency,
/// <c>Invalidate</c> forces a refetch, one key's failure does not affect other keys, and
/// cancelling one waiter does not cancel the shared fetch. The built-in cache runs this
/// same suite.
/// </summary>
/// <typeparam name="TCache">The cache under test.</typeparam>
[Experimental("CREDPROX001")]
public abstract class TokenCacheConformanceTests<TCache>
    where TCache : ITokenCache
{
    /// <summary>Creates a fresh cache instance for one test.</summary>
    protected abstract TCache CreateCache();

    private static (string Value, DateTimeOffset ExpiresAt) Token(string value) =>
        (value, DateTimeOffset.UtcNow.AddHours(1));

    /// <summary>100 concurrent requests for one key perform a single fetch.</summary>
    [Fact]
    public async Task SingleFetch_UnderConcurrentRequests()
    {
        var cache = CreateCache();
        var fetches = 0;

        var acquires = Enumerable.Range(0, 100)
            .Select(_ => cache.GetTokenAsync(
                "shared", null,
                _ =>
                {
                    Interlocked.Increment(ref fetches);
                    return new ValueTask<(string, DateTimeOffset)>(Token("tok-1"));
                },
                default).AsTask())
            .ToArray();

        var values = await Task.WhenAll(acquires);

        Assert.Equal(1, fetches);
        Assert.All(values, v => Assert.Equal("tok-1", v));
    }

    /// <summary><c>Invalidate</c> drops the entry so the next acquire refetches.</summary>
    [Fact]
    public async Task Invalidate_ForcesRefetch()
    {
        var cache = CreateCache();
        var fetches = 0;
        ValueTask<(string, DateTimeOffset)> Acquire(CancellationToken _) =>
            new(Token($"tok-{++fetches}"));

        Assert.Equal("tok-1", await cache.GetTokenAsync("c", null, Acquire, default));
        cache.Invalidate("c", null);
        Assert.Equal("tok-2", await cache.GetTokenAsync("c", null, Acquire, default));
        Assert.Equal(2, fetches);
    }

    /// <summary>Keys are independent: different names and partitions never share entries.</summary>
    [Fact]
    public async Task Keys_AreIsolatedPerCredentialAndPartition()
    {
        var cache = CreateCache();
        var fetches = 0;
        ValueTask<(string, DateTimeOffset)> Acquire(CancellationToken _) =>
            new(Token($"tok-{++fetches}"));

        await cache.GetTokenAsync("a", "p1", Acquire, default);
        await cache.GetTokenAsync("b", "p1", Acquire, default);
        await cache.GetTokenAsync("a", "p2", Acquire, default);

        Assert.Equal(3, fetches);
    }

    /// <summary>One key's failure does not affect other keys.</summary>
    [Fact]
    public async Task Failure_UnderOneKeyDoesNotAffectAnother()
    {
        var cache = CreateCache();

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            cache.GetTokenAsync(
                "failing", null,
                _ => throw new InvalidOperationException("vendor said no"),
                default).AsTask());

        var value = await cache.GetTokenAsync(
            "healthy", null,
            _ => new ValueTask<(string, DateTimeOffset)>(Token("ok")),
            default);

        Assert.Equal("ok", value);
    }

    /// <summary>Cancelling one waiter does not cancel the shared fetch for the others.</summary>
    [Fact]
    public async Task CancellationOfOneWaiter_DoesNotCancelTheSharedFetch()
    {
        var cache = CreateCache();
        using var waiterCts = new CancellationTokenSource();
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        async ValueTask<(string, DateTimeOffset)> SlowAcquire(CancellationToken cancellationToken)
        {
            await release.Task.WaitAsync(cancellationToken);
            return Token("tok-1");
        }

        var shared = cache.GetTokenAsync("c", null, SlowAcquire, default).AsTask();
        var cancelled = cache.GetTokenAsync("c", null, SlowAcquire, waiterCts.Token).AsTask();

        await Task.Yield();
        waiterCts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelled);

        release.SetResult();
        Assert.Equal("tok-1", await shared);
    }
}
