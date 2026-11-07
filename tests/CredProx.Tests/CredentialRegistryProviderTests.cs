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

    [Fact]
    public void RemovedEntraOboMode_FailsStartupBinding()
    {
        // M27 (docs/adr/0002): the Entra OBO mode is gone. A config still naming it must
        // fail loudly at startup binding - never silently bind to the surviving
        // Rfc8693 shape and call the IdP with the wrong grant.
        var entries = Entries();
        entries["CredProx:Credentials:obo:Type"] = "TokenExchange";
        entries["CredProx:Credentials:obo:Authority"] = "https://issuer.example/";
        entries["CredProx:Credentials:obo:Audience"] = "api://credprox";
        entries["CredProx:Credentials:obo:ClientId"] = "client";
        entries["CredProx:Credentials:obo:Mode"] = "EntraObo";

        var ex = Assert.Throws<InvalidOperationException>(() => Build(entries));
        Assert.Contains("EntraObo", ex.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void NumericUndefinedMode_FailsStartupValidation()
    {
        // M27 review N1: the binder accepts any NUMBER for the enum - Mode: 1 (EntraObo's
        // old value) binds to the undefined enum with no error. The options validator
        // refuses undefined Mode values through the same startup path, naming the value,
        // so the no-degradation rule covers the numeric spelling too.
        var entries = Entries();
        entries["CredProx:Credentials:obo:Type"] = "TokenExchange";
        entries["CredProx:Credentials:obo:Authority"] = "https://issuer.example/";
        entries["CredProx:Credentials:obo:Audience"] = "api://credprox";
        entries["CredProx:Credentials:obo:ClientId"] = "client";
        entries["CredProx:Credentials:obo:Mode"] = "1";

        var ex = Assert.Throws<OptionsValidationException>(() => Build(entries));
        Assert.Contains("Mode is not a defined TokenExchangeMode value: '1'", ex.Message, StringComparison.Ordinal);
    }
}
