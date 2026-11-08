using System.Security.Claims;
using CredProx.Abstractions;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation survivors, Abstractions: the FromPrincipal null/empty guards and the
/// InboundTokenRejectedException reason guard were untested at the type level (only
/// reached incidentally through feature tests). These close the gaps the mutants
/// exposed (plan §5.2 "Abstractions contract" row).
/// </summary>
public class AbstractionsGuardTests
{
    [Fact]
    public void FromPrincipal_NullPrincipal_ReturnsNull()
    {
        Assert.Null(CallerIdentity.FromPrincipal(null));
    }

    [Fact]
    public void FromPrincipal_NoCredProxClaims_ReturnsNull()
    {
        var principal = new ClaimsPrincipal(
            new ClaimsIdentity([new Claim(ClaimTypes.Name, "someone")], authenticationType: "test"));

        Assert.Null(CallerIdentity.FromPrincipal(principal));
    }

    [Fact]
    public void FromPrincipal_EmptyCallerClaim_ReturnsNull()
    {
        var principal = new ClaimsPrincipal(
            new ClaimsIdentity(
                [new Claim(CallerIdentity.CallerClaimType, string.Empty)],
                authenticationType: "test"));

        Assert.Null(CallerIdentity.FromPrincipal(principal));
    }

    [Fact]
    public void FromPrincipal_CallerWithoutKeyIdClaim_KeyIdIsEmpty()
    {
        var principal = new ClaimsPrincipal(
            new ClaimsIdentity(
                [new Claim(CallerIdentity.CallerClaimType, "billing")],
                authenticationType: "test"));

        var identity = CallerIdentity.FromPrincipal(principal);

        Assert.NotNull(identity);
        Assert.Equal("billing", identity.CallerId);
        Assert.Equal(string.Empty, identity.KeyId);
    }

    [Fact]
    public void InboundTokenRejectedException_EmptyReason_Throws()
    {
        Assert.Throws<ArgumentException>(
            () => new InboundTokenRejectedException(string.Empty, "the key rotated"));
    }

    [Fact]
    public void InboundTokenRejectedException_NullReason_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new InboundTokenRejectedException(null!, "the key rotated"));
    }

    [Fact]
    public void InboundTokenRejectedException_ValidReason_KeepsReasonAndMessage()
    {
        var error = new InboundTokenRejectedException("expired", "credential 'x' token expired");

        Assert.Equal("expired", error.Reason);
        Assert.Equal("credential 'x' token expired", error.Message);
    }
}
