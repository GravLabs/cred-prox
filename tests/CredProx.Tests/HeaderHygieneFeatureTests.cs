using CredProx;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The <see cref="Stage.ShapeHeaders"/> feature (§3.2, §5.2 "Header hygiene"): the inbound
/// caller key never reaches the upstream, the caller's own <c>Authorization</c> and
/// <c>Cookie</c> are stripped on every route unless the route opts out with
/// <c>CredProx.CallerHeaderStrip = "off"</c> (M45 F-4), and the partition header is
/// stripped only when the resolved destination declares <c>StripHeader: true</c>.
/// </summary>
public sealed class HeaderHygieneFeatureTests
{
    private static HeaderHygieneFeature Feature(CredProxCoreOptions? options = null) =>
        new(options ?? new CredProxCoreOptions(), new ConfigurationBuilder().Build());

    [Fact]
    public async Task InboundKeyHeader_IsRemovedFromOutboundRequest()
    {
        var context = M4Contexts.Create(out var proxyRequest);
        proxyRequest.Headers.Add("X-API-Key", "caller-key");
        proxyRequest.Headers.Add("X-Trace", "keep-me");

        await Feature().ApplyAsync(context, default);

        Assert.False(proxyRequest.Headers.Contains("X-API-Key"));
        Assert.True(proxyRequest.Headers.Contains("X-Trace")); // only the key header goes
    }

    [Fact]
    public async Task PartitionHeader_StrippedWhenDestinationDeclaresIt()
    {
        var provider = TestProviders.Destinations(TestConfig.Root(
            ("CredProx:Destinations:acme:Template", "https://{partition}.acme.example/"),
            ("CredProx:Destinations:acme:Partition", "header:X-Env"),
            ("CredProx:Destinations:acme:Allowed:0", "prod"),
            ("CredProx:Destinations:acme:StripHeader", "true")));

        var context = M4Contexts.Create(out var proxyRequest, new() { [CredProxMetadata.Destination] = "acme" });
        context.Request.Headers["X-Env"] = "prod";
        await new DestinationResolutionFeature(provider).ApplyAsync(context, default);
        proxyRequest.Headers.Add("X-Env", "prod");
        proxyRequest.Headers.Add("X-API-Key", "caller-key");

        await Feature().ApplyAsync(context, default);

        Assert.False(proxyRequest.Headers.Contains("X-Env"));
        Assert.False(proxyRequest.Headers.Contains("X-API-Key"));
    }

    [Fact]
    public async Task PartitionHeader_KeptWhenStripHeaderNotDeclared()
    {
        var provider = TestProviders.Destinations(TestConfig.Root(
            ("CredProx:Destinations:acme:Template", "https://{partition}.acme.example/"),
            ("CredProx:Destinations:acme:Partition", "header:X-Env"),
            ("CredProx:Destinations:acme:Allowed:0", "prod")));

        var context = M4Contexts.Create(out var proxyRequest, new() { [CredProxMetadata.Destination] = "acme" });
        context.Request.Headers["X-Env"] = "prod";
        await new DestinationResolutionFeature(provider).ApplyAsync(context, default);
        proxyRequest.Headers.Add("X-Env", "prod");

        await Feature().ApplyAsync(context, default);

        Assert.True(proxyRequest.Headers.Contains("X-Env"));
    }

    [Fact]
    public async Task CallerAuthorizationAndCookie_AreStrippedByDefault()
    {
        // M47 finding F-4: the caller's own credentials no longer ride to the vendor.
        var context = M4Contexts.Create(out var proxyRequest);
        proxyRequest.Headers.Add("Authorization", "Bearer caller-own");
        proxyRequest.Headers.Add("Cookie", "sess=caller");
        proxyRequest.Headers.Add("X-Trace", "keep-me");

        await Feature().ApplyAsync(context, default);

        Assert.False(proxyRequest.Headers.Contains("Authorization"));
        Assert.False(proxyRequest.Headers.Contains("Cookie"));
        Assert.True(proxyRequest.Headers.Contains("X-Trace")); // only the credential-bearing headers go
    }

    [Fact]
    public async Task CallerHeaders_KeptWhenRouteSwitchIsOff()
    {
        // ADR-0006: a switch that says off is off — this route keeps the old ride.
        // The name match is case-insensitive, like every other route-metadata switch.
        var context = M4Contexts.Create(
            out var proxyRequest, new() { [CredProxMetadata.CallerHeaderStrip] = "OFF" });
        proxyRequest.Headers.Add("Authorization", "Bearer caller-own");
        proxyRequest.Headers.Add("Cookie", "sess=caller");

        await Feature().ApplyAsync(context, default);

        Assert.True(proxyRequest.Headers.Contains("Authorization"));
        Assert.True(proxyRequest.Headers.Contains("Cookie"));
    }

    [Fact]
    public async Task CallerHeaders_StrippedWhenSwitchValueIsNotOff()
    {
        var context = M4Contexts.Create(
            out var proxyRequest, new() { [CredProxMetadata.CallerHeaderStrip] = "no" });
        proxyRequest.Headers.Add("Authorization", "Bearer caller-own");
        proxyRequest.Headers.Add("Cookie", "sess=caller");

        await Feature().ApplyAsync(context, default);

        Assert.False(proxyRequest.Headers.Contains("Authorization"));
        Assert.False(proxyRequest.Headers.Contains("Cookie"));
    }

    [Fact]
    public async Task CustomInboundKeyHeader_IsHonored()
    {
        var context = M4Contexts.Create(out var proxyRequest);
        proxyRequest.Headers.Add("X-Tenant-Key", "caller-key");
        proxyRequest.Headers.Add("X-API-Key", "legacy-stays");

        await Feature(new CredProxCoreOptions { InboundKeyHeader = "X-Tenant-Key" })
            .ApplyAsync(context, default);

        Assert.False(proxyRequest.Headers.Contains("X-Tenant-Key"));
        Assert.True(proxyRequest.Headers.Contains("X-API-Key"));
    }
}
