using CredProx;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The <c>caller:</c> partition source (§3.2, §4 Phase B "Per-caller credentials"): the
/// partition is the authenticated caller id, an unauthenticated request has no partition,
/// and a rejection answers 403 <c>credprox.operation_not_allowed</c> — the caller's
/// identity simply has no mapping, they did not request a bad value (§3.4).
/// </summary>
public sealed class CallerPartitionSourceTests
{
    [Fact]
    public async Task FeatureIdentity_BecomesThePartition()
    {
        var context = new DefaultHttpContext();
        context.Features.Set(new CallerIdentity("app-a", "k1"));

        var partition = await new CallerPartitionSource().GetPartitionAsync(context, default);

        Assert.Equal("app-a", partition);
    }

    [Fact]
    public async Task PrincipalClaimIdentity_BecomesThePartition()
    {
        // Hosts that authenticate through middleware set User without the feature.
        var context = new DefaultHttpContext
        {
            User = new System.Security.Claims.ClaimsPrincipal(
                new System.Security.Claims.ClaimsIdentity(
                    [new System.Security.Claims.Claim(CallerIdentity.CallerClaimType, "app-b")],
                    authenticationType: "test")),
        };

        var partition = await new CallerPartitionSource().GetPartitionAsync(context, default);

        Assert.Equal("app-b", partition);
    }

    [Fact]
    public async Task Unauthenticated_HasNoPartition()
    {
        var partition = await new CallerPartitionSource()
            .GetPartitionAsync(new DefaultHttpContext(), default);

        Assert.Null(partition);
    }

    [Fact]
    public void Rejection_IsForbidden() =>
        Assert.Equal(PartitionRejection.Forbidden, new CallerPartitionSource().Rejection);

    [Fact]
    public async Task UnmappedCaller_BindingThrows_403Shaped()
    {
        var context = new DefaultHttpContext();
        context.Features.Set(new CallerIdentity("app-a", "k1"));

        // The caller authenticates but the credential's allow-list has no entry for them:
        // §5.2 "caller with no mapping → 403, no token fetch".
        var binding = new PartitionSourceBinding(
            new CallerPartitionSourceFactory().CreateSource(""),
            ["app-b"],
            "caller:");

        var ex = await Assert.ThrowsAsync<PartitionNotAllowedException>(
            () => binding.ResolveAsync(context, default).AsTask());

        Assert.Equal(StatusCodes.Status403Forbidden, ex.StatusCode);
        Assert.Equal("credprox.operation_not_allowed", ex.Code);
        Assert.Equal("The caller is not allowed this operation.", ex.Title);
        Assert.DoesNotContain("app-a", ex.Message); // the rejected value never appears
    }

    [Fact]
    public async Task MappedCaller_Resolves()
    {
        var context = new DefaultHttpContext();
        context.Features.Set(new CallerIdentity("app-a", "k1"));

        var binding = new PartitionSourceBinding(
            new CallerPartitionSourceFactory().CreateSource(""),
            ["app-a", "app-b"],
            "caller:");

        Assert.Equal("app-a", await binding.ResolveAsync(context, default));
    }

    [Fact]
    public void HeaderSource_KeepsBadRequestRejection()
    {
        // The DIM default: existing sources keep the §3.4 400 shape.
        Assert.Equal(
            PartitionRejection.BadRequest,
            ((IPartitionSource)new HeaderPartitionSource("X-Env")).Rejection);
    }

    [Fact]
    public void Factory_RejectsNonEmptyArgument() =>
        Assert.Throws<ArgumentException>(() => new CallerPartitionSourceFactory().CreateSource("app-a"));

    [Fact]
    public void Factory_SchemeIsCaller() =>
        Assert.Equal("caller", new CallerPartitionSourceFactory().Scheme);
}
