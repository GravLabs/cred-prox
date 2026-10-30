using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;
using Xunit;

namespace CredProx.Testing;

/// <summary>
/// The conformance suite for <see cref="ISecretSource"/> implementations (see
/// <c>docs/credprox-plan.md</c> §5.2 "Secrets"): a configured reference resolves to its
/// value, an unknown reference resolves to <see langword="null"/> (the caller turns that
/// into a startup error naming the reference — never a value), and the same name resolves
/// consistently. The built-in configuration source runs this same suite.
/// </summary>
/// <typeparam name="TSource">The secret source under test.</typeparam>
[Experimental("CREDPROX001")]
public abstract class SecretSourceConformanceTests<TSource>
    where TSource : ISecretSource
{
    /// <summary>Creates a source carrying <see cref="KnownSecret"/> and nothing else.</summary>
    protected abstract TSource CreateSource();

    /// <summary>A reference the source can resolve, and its value.</summary>
    protected abstract (string Name, string Value) KnownSecret { get; }

    /// <summary>A configured reference resolves to its exact value.</summary>
    [Fact]
    public async Task KnownReference_ResolvesToItsValue()
    {
        var source = CreateSource();

        var value = await source.GetSecretAsync(KnownSecret.Name, default);

        Assert.Equal(KnownSecret.Value, value);
    }

    /// <summary>An unknown reference resolves to <see langword="null"/>, not a throw.</summary>
    [Fact]
    public async Task UnknownReference_ResolvesToNull()
    {
        var source = CreateSource();

        Assert.Null(await source.GetSecretAsync("no-such-secret-anywhere", default));
    }

    /// <summary>Resolution is consistent across calls (no one-shot caches, no drift).</summary>
    [Fact]
    public async Task Resolution_IsConsistentAcrossCalls()
    {
        var source = CreateSource();

        var first = await source.GetSecretAsync(KnownSecret.Name, default);
        var second = await source.GetSecretAsync(KnownSecret.Name, default);

        Assert.Equal(first, second);
    }
}
