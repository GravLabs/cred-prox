using System.Net.Http;
using System.Text.Json;
using CredProx;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The <see cref="Stage.ResolveDestination"/> feature (§3.2/§3.4): the partition header
/// decides the outbound address, a disallowed partition answers
/// <c>400 credprox.partition_not_allowed</c> with a problem document that never echoes the
/// value, and a route without the metadata is left to the cluster's static destinations.
/// </summary>
public sealed class DestinationResolutionFeatureTests
{
    private static DestinationRegistryProvider Provider() =>
        TestProviders.Destinations(TestConfig.Root(
            ("CredProx:Destinations:acme:Template", "https://{partition}.acme.example/"),
            ("CredProx:Destinations:acme:Partition", "header:X-Env"),
            ("CredProx:Destinations:acme:Allowed:0", "prod"),
            ("CredProx:Destinations:static:Template", "https://api.vendor.example/")));

    private static DestinationResolutionFeature Feature() => new(Provider());

    [Fact]
    public async Task AllowedPartition_ExpandsTemplateAndPublishesState()
    {
        var context = M4Contexts.Create(
            out var proxyRequest,
            new() { [CredProxMetadata.Destination] = "acme" });
        context.Request.Headers["X-Env"] = "prod";

        await Feature().ApplyAsync(context, default);

        Assert.False(context.Features.Get<CredProxRequestState>()!.IsAborted);
        Assert.Equal("https://prod.acme.example/", context.Features.Get<CredProxRequestState>()!.DestinationPrefix);
        Assert.Equal("prod", context.Features.Get<CredProxRequestState>()!.Partition);
        Assert.Equal("http://upstream/api", proxyRequest.RequestUri!.ToString()); // applied later by the transform
    }

    [Fact]
    public async Task DisallowedPartition_Aborts400WithProblemCodeAndEchoesNothing()
    {
        var context = M4Contexts.Create(
            out _,
            new() { [CredProxMetadata.Destination] = "acme" });
        context.Request.Headers["X-Env"] = "attacker.com";

        await Feature().ApplyAsync(context, default);

        var state = context.Features.Get<CredProxRequestState>()!;
        Assert.True(state.IsAborted);
        Assert.Null(state.DestinationPrefix);
        Assert.Null(state.Partition);
        Assert.Equal(400, context.Response.StatusCode);
        Assert.Equal("application/problem+json", context.Response.ContentType);

        var body = M4Contexts.ResponseBody(context);
        using var problem = JsonDocument.Parse(body);
        Assert.Equal("credprox.partition_not_allowed", problem.RootElement.GetProperty("extensions").GetProperty("code").GetString());
        Assert.Equal(400, problem.RootElement.GetProperty("status").GetInt32());
        Assert.DoesNotContain("attacker.com", body);
    }

    [Fact]
    public async Task MissingPartitionHeader_Aborts400()
    {
        var context = M4Contexts.Create(out _, new() { [CredProxMetadata.Destination] = "acme" });

        await Feature().ApplyAsync(context, default);

        Assert.True(context.Features.Get<CredProxRequestState>()!.IsAborted);
        Assert.Equal(400, context.Response.StatusCode);
    }

    [Fact]
    public async Task StaticDestination_ResolvesWithoutAnyPartition()
    {
        var context = M4Contexts.Create(out _, new() { [CredProxMetadata.Destination] = "static" });

        await Feature().ApplyAsync(context, default);

        var state = context.Features.Get<CredProxRequestState>()!;
        Assert.False(state.IsAborted);
        Assert.Equal("https://api.vendor.example/", state.DestinationPrefix);
        Assert.Null(state.Partition);
    }

    [Fact]
    public async Task RouteWithoutDestinationMetadata_IsLeftAlone()
    {
        var context = M4Contexts.Create(out _);

        await Feature().ApplyAsync(context, default);

        var state = context.Features.Get<CredProxRequestState>()!;
        Assert.False(state.IsAborted);
        Assert.Null(state.DestinationPrefix);
    }

    [Fact]
    public async Task OutsideCredProxTransform_IsNoOp()
    {
        // No CredProxRequestState feature: the feature must not run (plugin-host safety).
        var plain = new DefaultHttpContext();

        await Feature().ApplyAsync(plain, default);

        Assert.False(plain.Response.HasStarted);
    }
}
