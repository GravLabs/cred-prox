using CredProx;
using Microsoft.Extensions.Options;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// Startup validation of <c>CredProx:Destinations</c> (§3.2/§3.3, §5.2 "Validation"):
/// every misconfiguration is a startup failure naming the destination — never a value —
/// and a bound destination expands only through an admitted partition.
/// </summary>
public sealed class DestinationBinderTests
{
    private static DestinationRegistry Bind(params (string Key, string? Value)[] entries) =>
        new DestinationBinder(
                TestConfig.Root(entries.Select(e => ("CredProx:" + e.Key, e.Value)).ToArray()),
                [new HeaderPartitionSourceFactory()])
            .Bind();

    [Fact]
    public void StaticDestination_BindsAndResolvesWithoutPartition()
    {
        var registry = Bind(("Destinations:vendor:Template", "https://api.vendor.example/"));

        var entry = registry.Get("vendor");
        Assert.Null(entry.Partition);
        Assert.Equal("https://api.vendor.example/", entry.ResolvePrefix(string.Empty));
    }

    [Fact]
    public void PartitionedDestination_BindsAndExpandsAdmittedValue()
    {
        var registry = Bind(
            ("Destinations:acme:Template", "https://{partition}.acme.example/"),
            ("Destinations:acme:Partition", "header:X-Env"),
            ("Destinations:acme:Allowed:0", "prod"),
            ("Destinations:acme:Allowed:1", "staging"));

        var entry = registry.Get("acme");
        Assert.NotNull(entry.Partition);
        Assert.Equal("https://staging.acme.example/", entry.ResolvePrefix("staging"));
    }

    [Fact]
    public void MissingTemplate_FailsStartup()
    {
        var error = Assert.Throws<OptionsValidationException>(() =>
            Bind(("Destinations:empty:Partition", "header:X-Env"), ("Destinations:empty:Allowed:0", "p")));

        Assert.Contains("empty", error.Message);
        Assert.Contains("no Template", error.Message);
    }

    [Theory]
    [InlineData("api.example.com")]            // no scheme
    [InlineData("ftp://api.example.com/")]     // wrong scheme
    [InlineData("{partition}")]                // the whole address is the partition value
    public void NonAbsoluteHttpTemplate_FailsStartup(string template)
    {
        var error = Assert.Throws<OptionsValidationException>(() =>
            Bind(("Destinations:bad:Template", template)));

        Assert.Contains("bad", error.Message);
        Assert.Contains("absolute http(s)", error.Message);
    }

    [Fact]
    public void PartitionPlaceholder_WithoutSource_FailsStartup()
    {
        var error = Assert.Throws<OptionsValidationException>(() =>
            Bind(("Destinations:loose:Template", "https://{partition}.example.com/")));

        Assert.Contains("loose", error.Message);
        Assert.Contains("no Partition source", error.Message);
    }

    [Fact]
    public void Partition_WithoutAllowList_FailsStartup()
    {
        var error = Assert.Throws<OptionsValidationException>(() =>
            Bind(
                ("Destinations:ungated:Template", "https://{partition}.example.com/"),
                ("Destinations:ungated:Partition", "header:X-Env")));

        Assert.Contains("ungated", error.Message);
        Assert.Contains("no Allowed values", error.Message);
    }

    [Fact]
    public void AllowList_WithoutPartitionSource_FailsStartup()
    {
        var error = Assert.Throws<OptionsValidationException>(() =>
            Bind(
                ("Destinations:orphan:Template", "https://api.example.com/"),
                ("Destinations:orphan:Allowed:0", "prod")));

        Assert.Contains("orphan", error.Message);
        Assert.Contains("no Partition/From source", error.Message);
    }

    [Fact]
    public void PartitionSpec_WithoutSchemeSeparator_FailsStartup()
    {
        var error = Assert.Throws<OptionsValidationException>(() =>
            Bind(
                ("Destinations:misshaped:Template", "https://{partition}.example.com/"),
                ("Destinations:misshaped:Partition", "X-Env"),
                ("Destinations:misshaped:Allowed:0", "prod")));

        Assert.Contains("misshaped", error.Message);
        Assert.Contains("scheme:argument", error.Message);
    }

    [Fact]
    public void PartitionScheme_WithoutRegisteredFactory_FailsStartupNamingKnownSchemes()
    {
        var error = Assert.Throws<OptionsValidationException>(() =>
            Bind(
                ("Destinations:future:Template", "https://{partition}.example.com/"),
                ("Destinations:future:Partition", "claim:env"),
                ("Destinations:future:Allowed:0", "prod")));

        Assert.Contains("future", error.Message);
        Assert.Contains("claim", error.Message);
        Assert.Contains("header", error.Message); // known schemes are listed
    }

    [Fact]
    public void AllErrors_AreCollectedIntoOneStartupFailure()
    {
        var error = Assert.Throws<OptionsValidationException>(() => Bind(
            ("Destinations:a:Partition", "header:X"),
            ("Destinations:a:Template", "https://a.example.com/"),
            ("Destinations:b:Template", "not-a-url")));

        Assert.Contains("'a'", error.Message);
        Assert.Contains("'b'", error.Message);
    }

    [Fact]
    public void Lookup_IsCaseInsensitive_AndUnknownNamesFailWithMessage()
    {
        var registry = Bind(("Destinations:Vendor:Template", "https://api.vendor.example/"));

        Assert.True(registry.TryGet("vendor", out _));
        var error = Assert.Throws<InvalidOperationException>(() => registry.Get("nope"));
        Assert.Contains("nope", error.Message);
    }
}
