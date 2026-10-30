using CredProx;
using FsCheck;
using FsCheck.Xunit;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace CredProx.SecurityTests;

/// <summary>
/// §5.2 "Destinations" as a property: the allow-list is the single gate. For every
/// generated partition value — hostile or not — only the exact allowed value resolves a
/// destination; everything else aborts with the constant problem document (so nothing
/// value-specific can ride it out), and the template is never expanded.
/// </summary>
public sealed class PartitionAllowListProperties
{
    private const string Allowed = "prod";

    private static DestinationRegistryProvider Provider()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["CredProx:Destinations:acme:Template"] = "https://{partition}.acme.example/",
                ["CredProx:Destinations:acme:Partition"] = "header:X-Env",
                ["CredProx:Destinations:acme:Allowed:0"] = Allowed,
            })
            .Build();
        return new DestinationRegistryProvider(
            new DestinationBinder(config, [new HeaderPartitionSourceFactory()]),
            new ConfigurationSecretSource(config),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<DestinationRegistryProvider>.Instance);
    }

    /// <summary>
    /// The rejection document is constant — captured once — so "the body never echoes the
    /// value" reduces to "the body is this constant for every value".
    /// </summary>
    private static readonly string RejectedBody = RejectAsync("zzzz-sentinel-zzzz").GetAwaiter().GetResult();

    private static async Task<string> RejectAsync(string value)
    {
        var context = SecurityContexts.Create(out _, "acme");
        context.Request.Headers["X-Env"] = value;
        await new DestinationResolutionFeature(Provider()).ApplyAsync(context, default);
        return SecurityContexts.ResponseBody(context);
    }

    [Property(MaxTest = 500)]
    public async Task PartitionAllowList_IsTheOnlyGate(NonEmptyString generated)
    {
        var value = generated.Get;
        var context = SecurityContexts.Create(out _, "acme");
        context.Request.Headers["X-Env"] = value;

        await new DestinationResolutionFeature(Provider()).ApplyAsync(context, default);

        var state = context.Features.Get<CredProxRequestState>()!;
        if (value == Allowed)
        {
            Assert.False(state.IsAborted);
            Assert.Equal("https://prod.acme.example/", state.DestinationPrefix);
            return;
        }

        Assert.True(state.IsAborted);
        Assert.Null(state.DestinationPrefix);
        Assert.Null(state.Partition);
        Assert.Equal(400, context.Response.StatusCode);

        // Constant document: no value-specific content can reach the caller.
        Assert.Equal(RejectedBody, SecurityContexts.ResponseBody(context));
    }

    /// <summary>The §5.2 hostile-value list, explicitly, alongside the generated inputs.</summary>
    [Theory]
    [InlineData("attacker.com/app?")]
    [InlineData("app#")]
    [InlineData("app@evil")]
    [InlineData("../")]
    [InlineData("%2eprod")]
    [InlineData("prоd")] // Cyrillic о — homoglyph of the allowed value
    [InlineData("prod\r\nX-Evil: 1")] // CRLF injection attempt
    [InlineData("prod\nX-Evil: 1")]
    [InlineData("")]
    [InlineData("Prod")]
    [InlineData(" prod")]
    [InlineData("prod ")]
    public async Task HostilePartitionValues_AreRejected(string value)
    {
        var context = SecurityContexts.Create(out _, "acme");
        context.Request.Headers["X-Env"] = value;

        await new DestinationResolutionFeature(Provider()).ApplyAsync(context, default);

        var state = context.Features.Get<CredProxRequestState>()!;
        Assert.True(state.IsAborted);
        Assert.Null(state.DestinationPrefix);
        Assert.Equal(400, context.Response.StatusCode);
        Assert.Equal(RejectedBody, SecurityContexts.ResponseBody(context));
    }

    [Fact]
    public async Task VeryLongPartitionValue_IsRejected()
    {
        await HostilePartitionValues_AreRejected(new string('a', 100_000));
    }
}
