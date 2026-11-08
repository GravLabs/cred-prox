using CredProx;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage (Destinations, second pass): the placeholder/source guard is
/// load-bearing only for its one-error doctrine, and the two public guards need
/// paramName pins (the downstream throws absorb the null with different names).
/// </summary>
public sealed class DestinationsSurvivorM31bTests
{
    private sealed class StubSource : IPartitionSource
    {
        public ValueTask<string?> GetPartitionAsync(HttpContext context, CancellationToken cancellationToken) =>
            new((string?)null);
    }

    private static IConfiguration Config(params (string Key, string? Value)[] data) =>
        new ConfigurationBuilder().AddInMemoryCollection(
            data.ToDictionary(d => d.Key, d => d.Value, StringComparer.OrdinalIgnoreCase)).Build();

    [Fact]
    public void Binder_PlaceholderWithoutSource_StillOneErrorWhenAllowListPresent()
    {
        // The early guard keeps the placeholder-without-source diagnosis to exactly one
        // error; falling through, the allow-list-without-source rule stacks a second
        // complaint onto the same destination.
        var ex = Assert.Throws<OptionsValidationException>(() => new DestinationBinder(
            Config(
                ("CredProx:Destinations:d:Template", "https://x.example/{partition}/"),
                ("CredProx:Destinations:d:Allowed:0", "p1")),
            [new HeaderPartitionSourceFactory()]).Bind());

        var failure = Assert.Single(ex.Failures);
        Assert.Contains("declares no Partition source", failure, StringComparison.Ordinal);
    }

    [Fact]
    public void CreateSource_NullArgument_ThrowsArgumentNullNamingArgument()
    {
        var error = Assert.Throws<ArgumentNullException>(
            () => new HeaderPartitionSourceFactory().CreateSource(null!));
        Assert.Equal("argument", error.ParamName); // the ctor's own guard would name "headerName"
    }

    [Fact]
    public void CreateSource_EmptyArgument_ThrowsArgument()
    {
        Assert.Throws<ArgumentException>(
            () => new HeaderPartitionSourceFactory().CreateSource(string.Empty));
    }

    [Fact]
    public async Task ResolveAsync_NullContext_ThrowsArgumentNullNamingContext()
    {
        var binding = new PartitionSourceBinding(new StubSource(), ["a"], "test binding");

        var error = await Assert.ThrowsAsync<ArgumentNullException>(
            () => binding.ResolveAsync(null!, default).AsTask());
        Assert.Equal("context", error.ParamName); // source-level failures must not masquerade as this guard
    }
}
