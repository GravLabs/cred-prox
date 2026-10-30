using CredProx;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The reload-aware destination registry (the config-reload story, M5): a reload that adds
/// or removes a destination takes effect without a restart; a bad reload keeps the
/// previous registry.
/// </summary>
public sealed class DestinationRegistryProviderTests
{
    private static (DestinationRegistryProvider Provider, ReloadableMemoryConfigurationProvider Reloadable) Build(
        Dictionary<string, string?> entries)
    {
        var source = new ReloadableMemoryConfigurationSource(entries);
        var config = new ConfigurationBuilder().Add(source).Build();
        var provider = new DestinationRegistryProvider(
            new DestinationBinder(config, [new HeaderPartitionSourceFactory()]),
            new ConfigurationSecretSource(config),
            NullLogger<DestinationRegistryProvider>.Instance);
        return (provider, (ReloadableMemoryConfigurationProvider)config.Providers
            .OfType<ReloadableMemoryConfigurationProvider>().Single());
    }

    private static Dictionary<string, string?> Entries() => new()
    {
        ["CredProx:Destinations:acme:Template"] = "https://{partition}.acme.example/",
        ["CredProx:Destinations:acme:Partition"] = "header:X-Env",
        ["CredProx:Destinations:acme:Allowed:0"] = "prod",
    };

    [Fact]
    public void Reload_AddsDestination_ResolvableWithoutRestart()
    {
        var (provider, reloadable) = Build(Entries());
        Assert.False(provider.Current.TryGet("contoso", out _));

        reloadable.Set("CredProx:Destinations:contoso:Template", "https://api.contoso.example/");
        reloadable.Reload();

        Assert.True(provider.Current.TryGet("contoso", out var entry));
        Assert.Equal("https://api.contoso.example/", entry!.ResolvePrefix(string.Empty));
    }

    [Fact]
    public void Reload_RemovesDestination_DropsOutOfRegistry()
    {
        var (provider, reloadable) = Build(Entries());
        Assert.True(provider.Current.TryGet("acme", out _));

        reloadable.Remove("CredProx:Destinations:acme:Template");
        reloadable.Remove("CredProx:Destinations:acme:Partition");
        reloadable.Remove("CredProx:Destinations:acme:Allowed:0");
        reloadable.Reload();

        Assert.False(provider.Current.TryGet("acme", out _));
    }

    [Fact]
    public void Reload_BadNewDestination_KeepsPreviousRegistry()
    {
        var (provider, reloadable) = Build(Entries());
        var before = provider.Current;

        // A template that is not an absolute HTTP(S) address fails the binder.
        reloadable.Set("CredProx:Destinations:broken:Template", "not a url");
        reloadable.Reload();

        Assert.Same(before, provider.Current); // a bad reload must not take down the running proxy
        Assert.True(provider.Current.TryGet("acme", out _));
        Assert.False(provider.Current.TryGet("broken", out _));
    }

    [Fact]
    public void InitialBind_BadDestination_Throws()
    {
        var entries = new Dictionary<string, string?>
        {
            ["CredProx:Destinations:broken:Template"] = "not a url",
        };

        Assert.Throws<OptionsValidationException>(() => Build(entries));
    }
}
