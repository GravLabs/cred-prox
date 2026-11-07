using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;
using Xunit;

namespace CredProx.Testing;

/// <summary>
/// The conformance suite for providers that cache through <see cref="ITokenCache"/> —
/// the OAuth-style contract (see <c>docs/credprox-plan.md</c> §5.2 "Token cache" and
/// "Refresh-on-401"): concurrent acquires collapse to one token call, and the
/// invalidate-then-acquire pair the refresh-on-401 handler performs yields a fresh token.
/// Inherit this instead of <see cref="CredentialProviderConformanceTests{TProvider,TOptions}"/>
/// when your provider acquires vendor tokens.
/// </summary>
/// <typeparam name="TProvider">The provider under test.</typeparam>
/// <typeparam name="TOptions">Its options type.</typeparam>
[Experimental("CREDPROX001")]
public abstract class CachingCredentialProviderConformanceTests<TProvider, TOptions>
    : CredentialProviderConformanceTests<TProvider, TOptions>
    where TProvider : class, ICredentialProvider<TOptions>
    where TOptions : class
{
    /// <summary>
    /// §5.2 "Token cache": 100 concurrent requests perform a single token fetch and all
    /// observe the same value.
    /// </summary>
    [Fact]
    public async Task TokenCache_CollapsesConcurrentAcquires()
    {
        await using var host = BuildHost();

        var acquires = Enumerable.Range(0, 100)
            .Select(_ => host.Acquire().AsTask())
            .ToArray();
        var values = await Task.WhenAll(acquires);

        Assert.Equal(1, host.TokenServer.CallCount);
        Assert.Single(values.Distinct());
    }

    /// <summary>
    /// §5.2 "Refresh-on-401" contract at the provider level: the handler's
    /// invalidate-then-refetch yields a fresh token value, not the cached one.
    /// </summary>
    [Fact]
    public async Task RefreshOn401Contract_InvalidateThenAcquireReturnsFreshToken()
    {
        await using var host = BuildHost();

        var first = await host.Acquire();
        host.Cache.Invalidate(CredentialName, Partition);
        var second = await host.Acquire();

        Assert.Equal(2, host.TokenServer.CallCount);
        Assert.NotEqual(first, second);
    }

    /// <summary>
    /// §5.2 "Token cache": one key's failure does not affect other keys — the same
    /// credential under a different partition value acquires independently.
    /// </summary>
    [Fact]
    public async Task TokenCache_FailureUnderOnePartitionDoesNotPoisonAnother()
    {
        await using var host = BuildHost();

        var poisoned = new CredentialRequestContext
        {
            CredentialName = CredentialName,
            Partition = Partition,
        };
        var healthy = new CredentialRequestContext
        {
            CredentialName = CredentialName,
            Partition = Partition is null ? "other" : $"{Partition}-other",
        };

        host.TokenServer.Enqueue(System.Net.HttpStatusCode.InternalServerError, """{"error":"nope"}""");
        await Assert.ThrowsAnyAsync<Exception>(
            () => host.Binding.GetCredential(poisoned, default).AsTask());

        var value = await host.Binding.GetCredential(healthy, default);

        Assert.False(string.IsNullOrEmpty(value));
    }
}
