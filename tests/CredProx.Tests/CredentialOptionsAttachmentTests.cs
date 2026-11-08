using CredProx;
using CredProx.Abstractions;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage for the attachment surface of the exchange options: the defaults
/// bind the provider to the vendor's wire shape ('expires_in', 'Bearer'), and the
/// <see cref="IHasAttachment.Prefix"/> rule — empty TokenTypeName means attach the raw
/// token — decides every outbound Authorization header. No mutant of either may survive.
/// </summary>
public sealed class CredentialOptionsAttachmentTests
{
    [Fact]
    public void JwtAssertion_Defaults_PinWireShape()
    {
        var options = new JwtAssertionOptions();

        Assert.Equal("expires_in", options.ExpiresInField);
        Assert.Equal("Bearer", options.TokenTypeName);
        Assert.Equal(CredentialLocation.Header, options.Location);
        Assert.Equal("Authorization", options.Name);
        Assert.Equal("Bearer ", options.Prefix);
    }

    [Theory]
    [InlineData("Bearer", "Bearer ")]
    [InlineData("MAC", "MAC ")]
    [InlineData("", null)] // 'attach the raw token' — an empty scheme must mean nothing before the token
    public void JwtAssertion_Prefix_FollowsTokenTypeName(string tokenTypeName, string? expected)
    {
        var options = new JwtAssertionOptions { TokenTypeName = tokenTypeName };

        Assert.Equal(expected, options.Prefix);
    }

    [Fact]
    public void TokenExchange_Defaults_PinWireShape()
    {
        var options = new TokenExchangeOptions();

        Assert.Equal("expires_in", options.ExpiresInField);
        Assert.Equal("Bearer", options.TokenTypeName);
        Assert.Equal(CredentialLocation.Header, options.Location);
        Assert.Equal("Authorization", options.Name);
        Assert.Equal("Bearer ", options.Prefix);
    }

    [Theory]
    [InlineData("Bearer", "Bearer ")]
    [InlineData("MAC", "MAC ")]
    [InlineData("", null)]
    public void TokenExchange_Prefix_FollowsTokenTypeName(string tokenTypeName, string? expected)
    {
        var options = new TokenExchangeOptions { TokenTypeName = tokenTypeName };

        Assert.Equal(expected, options.Prefix);
    }
}
