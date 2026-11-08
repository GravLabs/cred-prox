using CredProx;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage (Features): both argument guards of the hygiene feature were
/// surviving as NRE-vs-ANE accidents — the documented exception contract is pinned here.
/// </summary>
public sealed class HeaderHygieneGuardTests
{
    [Fact]
    public void Ctor_NullCallerKeyOptions_ThrowsArgumentNullNamingCallerKeyOptions()
    {
        var error = Assert.Throws<ArgumentNullException>(
            () => new HeaderHygieneFeature(new CredProxCoreOptions(), null!));
        Assert.Equal("callerKeyOptions", error.ParamName);
    }

    [Fact]
    public async Task ApplyAsync_NullContext_ThrowsArgumentNullNamingContext()
    {
        var feature = new HeaderHygieneFeature(new CredProxCoreOptions(), Array.Empty<CallerKeyOptions>());

        var error = await Assert.ThrowsAsync<ArgumentNullException>(
            () => feature.ApplyAsync(null!, default).AsTask());
        Assert.Equal("context", error.ParamName);
    }
}
