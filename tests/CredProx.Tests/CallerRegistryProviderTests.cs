using System.Security.Cryptography;
using System.Text;
using CredProx;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The live caller registry (the config-reload story applied to M6 callers): construction
/// argument guards, a reload that adds a caller taking effect without a restart, and a bad
/// reload keeping the previous registry — a failed rebind must never turn a running proxy
/// into one that authenticates nobody.
/// </summary>
public sealed class CallerRegistryProviderTests
{
    private static string Hash(string value) =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private static Dictionary<string, string?> Entries() => new()
    {
        ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
        ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("unused"),
    };

    private static (CallerRegistryProvider Provider, ReloadableMemoryConfigurationProvider Reloadable) Build(
        Dictionary<string, string?> entries)
    {
        var source = new ReloadableMemoryConfigurationSource(entries);
        var config = new ConfigurationBuilder().Add(source).Build();
        var provider = new CallerRegistryProvider(
            new CallerBinder(config, new SecretAccessorFactory(new ConfigurationSecretSource(config))),
            new ConfigurationSecretSource(config),
            NullLogger<CallerRegistryProvider>.Instance);
        return (provider, (ReloadableMemoryConfigurationProvider)config.Providers
            .OfType<ReloadableMemoryConfigurationProvider>().Single());
    }

    [Fact]
    public void Ctor_NullBinder_Throws()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(Entries()).Build();
        var secretSource = new ConfigurationSecretSource(config);

        Assert.Throws<ArgumentNullException>(
            () => new CallerRegistryProvider(null!, secretSource, NullLogger<CallerRegistryProvider>.Instance));
    }

    [Fact]
    public void Ctor_NullSecretSource_Throws()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(Entries()).Build();
        var binder = new CallerBinder(config, new SecretAccessorFactory(new ConfigurationSecretSource(config)));

        Assert.Throws<ArgumentNullException>(
            () => new CallerRegistryProvider(binder, null!, NullLogger<CallerRegistryProvider>.Instance));
    }

    [Fact]
    public void Ctor_NullLogger_Throws()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(Entries()).Build();
        var binder = new CallerBinder(config, new SecretAccessorFactory(new ConfigurationSecretSource(config)));

        Assert.Throws<ArgumentNullException>(
            () => new CallerRegistryProvider(binder, new ConfigurationSecretSource(config), null!));
    }

    [Fact]
    public void Registry_NullCallers_Throws_NamingCallers()
    {
        var ex = Assert.Throws<ArgumentNullException>(
            () => new CallerRegistry(null!));

        Assert.Equal("callers", ex.ParamName);
    }

    [Fact]
    public void Reload_AddsCaller_ResolvableWithoutRestart()
    {
        var (provider, reloadable) = Build(Entries());

        reloadable.Set("CredProx:Callers:app-b:Keys:0:KeyId", "k1");
        reloadable.Set("CredProx:Callers:app-b:Keys:0:KeyHash", Hash("other"));
        reloadable.Reload();

        Assert.True(provider.Current.TryGet("app-a", out _));
        Assert.True(provider.Current.TryGet("app-b", out _));
    }

    [Fact]
    public void Reload_BadConfig_KeepsPreviousRegistry()
    {
        // A reload that no longer binds (the caller lost its only key) must keep serving
        // from the last good registry, not from a broken one.
        var (provider, reloadable) = Build(Entries());
        var before = provider.Current;

        reloadable.Remove("CredProx:Callers:app-a:Keys:0:KeyId");
        reloadable.Reload();

        Assert.Same(before, provider.Current);
        Assert.True(provider.Current.TryGet("app-a", out var caller));
        Assert.Equal("k1", caller.Keys.Single().KeyId);
    }
}
