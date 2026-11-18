using CredProx;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage (Features): both argument guards of the hygiene feature were
/// surviving as NRE-vs-ANE accidents — the documented exception contract is pinned here.
/// </summary>
public sealed class HeaderHygieneGuardTests
{
    [Fact]
    public void Ctor_NullConfiguration_ThrowsArgumentNullNamingConfiguration()
    {
        var error = Assert.Throws<ArgumentNullException>(
            () => new HeaderHygieneFeature(new CredProxCoreOptions(), null!));
        Assert.Equal("configuration", error.ParamName);
    }

    [Fact]
    public async Task ApplyAsync_NullContext_ThrowsArgumentNullNamingContext()
    {
        var feature = new HeaderHygieneFeature(new CredProxCoreOptions(), new ConfigurationBuilder().Build());

        var error = await Assert.ThrowsAsync<ArgumentNullException>(
            () => feature.ApplyAsync(null!, default).AsTask());
        Assert.Equal("context", error.ParamName);
    }
}
