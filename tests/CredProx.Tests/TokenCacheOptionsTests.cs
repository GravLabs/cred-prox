using CredProx;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage for <see cref="TokenCacheOptions">: the setter guards were
/// NoCoverage in the sweep — a config typo (RefreshFraction 8, negative skew) must
/// refuse at binding time with the range named, never bind and silently change
/// refresh behaviour.
/// </summary>
public sealed class TokenCacheOptionsTests
{
    [Theory]
    [InlineData(0.0)]
    [InlineData(-0.1)]
    [InlineData(1.1)]
    public void RefreshFraction_OutOfRange_Throws_NamingRange(double value)
    {
        var options = new TokenCacheOptions();

        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => options.RefreshFraction = value);

        Assert.Equal("value", ex.ParamName);
        Assert.Contains("(0, 1]", ex.Message);
    }

    [Theory]
    [InlineData(0.0001)]
    [InlineData(0.5)]
    [InlineData(1.0)]
    public void RefreshFraction_InRange_Accepts(double value)
    {
        var options = new TokenCacheOptions { RefreshFraction = value };

        Assert.Equal(value, options.RefreshFraction);
    }

    [Fact]
    public void Skew_Negative_Throws_KeepsPreviousValue()
    {
        var options = new TokenCacheOptions { Skew = TimeSpan.FromSeconds(10) };

        Assert.Throws<ArgumentOutOfRangeException>(() => options.Skew = TimeSpan.FromSeconds(-1));
        Assert.Equal(TimeSpan.FromSeconds(10), options.Skew);
    }

    [Fact]
    public void Skew_Zero_Accepts()
    {
        var options = new TokenCacheOptions { Skew = TimeSpan.Zero };

        Assert.Equal(TimeSpan.Zero, options.Skew);
    }

    [Fact]
    public void NegativeCacheTtl_Negative_Throws_KeepsPreviousValue()
    {
        var options = new TokenCacheOptions { NegativeCacheTtl = TimeSpan.FromSeconds(3) };

        Assert.Throws<ArgumentOutOfRangeException>(() => options.NegativeCacheTtl = TimeSpan.FromSeconds(-0.5));
        Assert.Equal(TimeSpan.FromSeconds(3), options.NegativeCacheTtl);
    }

    [Fact]
    public void NegativeCacheTtl_Zero_Accepts()
    {
        var options = new TokenCacheOptions { NegativeCacheTtl = TimeSpan.Zero };

        Assert.Equal(TimeSpan.Zero, options.NegativeCacheTtl);
    }
}
