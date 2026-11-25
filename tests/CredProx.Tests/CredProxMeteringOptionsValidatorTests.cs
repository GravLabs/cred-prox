using CredProx;
using Microsoft.Extensions.Options;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M50 fold LOW-3 remainder: the metering window's two bounds arms must refuse startup
/// rather than silently disable (non-positive) or unbind (oversized) the usage peek.
/// The checker's P13/P14 executed these arms but were never committed; the boundary
/// values pass as-is, because 64 MiB is the ceiling, not a violation.
/// </summary>
public sealed class CredProxMeteringOptionsValidatorTests
{
    private static ValidateOptionsResult Validate(long maxUsageParseBytes) =>
        new CredProxMeteringOptionsValidator().Validate(
            null!,
            new CredProxMeteringOptions { MaxUsageParseBytes = maxUsageParseBytes });

    [Theory]
    [InlineData(0L)]
    [InlineData(-1L)]
    public void NonPositiveWindow_FailsStartup(long window)
    {
        var result = Validate(window);
        Assert.False(result.Succeeded);
        Assert.Contains(
            "CredProx:Metering:MaxUsageParseBytes must be positive.",
            Assert.Single(result.Failures!));
    }

    [Fact]
    public void WindowAboveTheCeiling_FailsStartup()
    {
        var result = Validate(64L * 1024 * 1024 + 1);
        Assert.False(result.Succeeded);
        Assert.Contains(
            "CredProx:Metering:MaxUsageParseBytes must be at most 67108864 (64 MiB).",
            Assert.Single(result.Failures!));
    }

    [Theory]
    [InlineData(1L)]
    [InlineData(64L * 1024 * 1024)]
    public void WindowInsideTheBounds_Passes(long window) =>
        Assert.True(Validate(window).Succeeded);
}
