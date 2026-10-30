using CredProx;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The reload-aware credential registry (§3.3 config reload): a secret-source change
/// rebinds the registry — a credential added by the reload becomes live without a restart —
/// and a reload that breaks the configuration keeps the previous registry serving traffic.
/// </summary>
public sealed class CredentialRegistryProviderTests
{
    private static (CredentialRegistryProvider Provider, ReloadableMemoryConfigurationProvider Reloadable) Build(
        Dictionary<string, string?> entries)
    {
        var source = new ReloadableMemoryConfigurationSource(entries);
        var config = new ConfigurationBuilder().Add(source).Build();

        var services = new ServiceCollection();
        services.AddCredProxTokenCache();
        services.AddCredProxConfigurationSecrets(config);
        services.AddCredProxBuiltInCredentials();
        services.AddCredProxCredentials(config);
        return (services.BuildServiceProvider().GetRequiredService<CredentialRegistryProvider>(),
            (ReloadableMemoryConfigurationProvider)config.Providers
                .OfType<ReloadableMemoryConfigurationProvider>().Single());
    }

    private static Dictionary<string, string?> Entries() => new()
    {
        ["CredProx:Credentials:contoso:Type"] = "StaticKey",
        ["CredProx:Credentials:contoso:Secret"] = "secret:contoso-key",
        ["CredProx:Credentials:contoso:Name"] = "X-Contoso",
        ["CredProx:Secrets:contoso-key"] = "value",
    };

    [Fact]
    public void InitialBind_HappensInConstruction()
    {
        var (provider, _) = Build(Entries());

        Assert.NotNull(provider.Current.Get("contoso"));
    }

    [Fact]
    public void Reload_AddsCredentialsWithoutRestart()
    {
        var (provider, reloadable) = Build(Entries());
        Assert.False(provider.Current.TryGet("late", out _));

        reloadable.Set("CredProx:Credentials:late:Type", "StaticKey");
        reloadable.Set("CredProx:Credentials:late:Secret", "secret:late-key");
        reloadable.Set("CredProx:Credentials:late:Name", "X-Late");
        reloadable.Set("CredProx:Secrets:late-key", "late-value");
        reloadable.Reload();

        Assert.NotNull(provider.Current.Get("late"));
    }

    [Fact]
    public void BrokenReload_KeepsThePreviousRegistry()
    {
        var (provider, reloadable) = Build(Entries());
        var before = provider.Current;

        reloadable.Set("CredProx:Credentials:broken:Type", "Magic"); // unknown type
        reloadable.Reload();

        Assert.Same(before, provider.Current);
        Assert.NotNull(provider.Current.Get("contoso"));
    }

    [Fact]
    public void UnknownKeyReload_KeepsThePreviousRegistry()
    {
        // M16: the unknown-key rule applies to reloads too — a typo arriving in a reload
        // must not silently drop the setting, and must not take down the serving registry.
        var (provider, reloadable) = Build(Entries());
        var before = provider.Current;

        reloadable.Set("CredProx:Credentials:contoso:Secrett", "secret:typo");
        reloadable.Reload();

        Assert.Same(before, provider.Current);
        Assert.NotNull(provider.Current.Get("contoso"));
    }

    [Fact]
    public void BadInitialConfig_FailsAtConstruction()
    {
        var entries = Entries();
        entries["CredProx:Credentials:bad:Type"] = "Magic";

        Assert.Throws<OptionsValidationException>(() => Build(entries));
    }
}
