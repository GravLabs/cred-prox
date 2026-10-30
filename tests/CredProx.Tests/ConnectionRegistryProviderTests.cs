using CredProx;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The reload-aware connection registry (the config-reload story, M5, note N2): a reload
/// that adds or removes a connection takes effect without a restart; an unchanged
/// connection keeps its object so its <see cref="ClientCertificateConnection.Version"/>
/// stays monotonic for the client factory's reuse stamp; a bad reload keeps the previous
/// registry.
/// </summary>
public sealed class ConnectionRegistryProviderTests
{
    private static (ConnectionRegistryProvider Provider, ReloadableMemoryConfigurationProvider Reloadable) Build(
        Dictionary<string, string?> entries)
    {
        var source = new ReloadableMemoryConfigurationSource(entries);
        var config = new ConfigurationBuilder().Add(source).Build();
        var provider = new ConnectionRegistryProvider(
            new ConnectionBinder(
                config,
                new SecretAccessorFactory(new ConfigurationSecretSource(config)),
                NullLoggerFactory.Instance),
            new ConfigurationSecretSource(config),
            NullLogger<ConnectionRegistryProvider>.Instance);
        return (provider, (ReloadableMemoryConfigurationProvider)config.Providers
            .OfType<ReloadableMemoryConfigurationProvider>().Single());
    }

    private static Dictionary<string, string?> Entries()
    {
        using var cert = TestCertificates.CreateSelfSigned("reload-contoso");
        return new Dictionary<string, string?>
        {
            ["CredProx:Connections:contoso:ClientCertificate"] = "secret:contoso-cert",
            ["CredProx:Secrets:contoso-cert"] = TestCertificates.PfxBase64(cert),
        };
    }

    [Fact]
    public void Reload_AddsConnection_ResolvableWithoutRestart()
    {
        var (provider, reloadable) = Build(Entries());
        Assert.False(provider.Current.TryGet("beta", out _));

        using var beta = TestCertificates.CreateSelfSigned("reload-beta");
        reloadable.Set("CredProx:Connections:beta:ClientCertificate", "secret:beta-cert");
        reloadable.Set("CredProx:Secrets:beta-cert", TestCertificates.PfxBase64(beta));
        reloadable.Reload();

        Assert.True(provider.Current.TryGet("beta", out var connection));
        Assert.Equal("beta", connection!.Name);
    }

    [Fact]
    public void Reload_RemovesConnection_DropsOutOfRegistry()
    {
        var (provider, reloadable) = Build(Entries());
        Assert.True(provider.Current.TryGet("contoso", out _));

        reloadable.Remove("CredProx:Connections:contoso:ClientCertificate");
        reloadable.Reload();

        Assert.False(provider.Current.TryGet("contoso", out _));
    }

    [Fact]
    public void Reload_UnchangedConnection_KeepsSameObjectAndVersion()
    {
        var (provider, reloadable) = Build(Entries());
        var before = provider.Current.Get("contoso");
        var versionBefore = before.Version;

        reloadable.Set("CredProx:Secrets:unrelated", "x");
        reloadable.Reload();

        var after = provider.Current.Get("contoso");
        Assert.Same(before, after); // the reuse stamp depends on object identity staying stable
        Assert.Equal(versionBefore, after.Version);
    }

    [Fact]
    public void Reload_RotatedSecretValue_SameObjectPicksItUpOnRefresh()
    {
        var (provider, reloadable) = Build(Entries());
        var connection = provider.Current.Get("contoso");
        var thumbprintBefore = connection.Certificate.Thumbprint;
        var versionBefore = connection.Version;

        using var rotated = TestCertificates.CreateSelfSigned("reload-rotated");
        reloadable.Set("CredProx:Secrets:contoso-cert", TestCertificates.PfxBase64(rotated));
        reloadable.Reload();

        Assert.Same(connection, provider.Current.Get("contoso")); // unchanged references keep the object

        connection.Refresh();
        Assert.NotEqual(thumbprintBefore, connection.Certificate.Thumbprint);
        Assert.Equal(versionBefore + 1, connection.Version); // the reuse stamp advanced on the same object
    }

    [Fact]
    public void Reload_BadNewConnection_KeepsPreviousRegistry()
    {
        var (provider, reloadable) = Build(Entries());
        var before = provider.Current;

        reloadable.Set("CredProx:Connections:beta:ClientCertificate", "secret:beta-cert");
        reloadable.Set("CredProx:Secrets:beta-cert", "not-a-certificate");
        reloadable.Reload();

        Assert.Same(before, provider.Current); // a bad reload must not take down the running proxy
        Assert.True(provider.Current.TryGet("contoso", out _));
        Assert.False(provider.Current.TryGet("beta", out _));
    }

    [Fact]
    public void InitialBind_BadCertificate_Throws()
    {
        var entries = new Dictionary<string, string?>
        {
            ["CredProx:Connections:contoso:ClientCertificate"] = "secret:contoso-cert",
            ["CredProx:Secrets:contoso-cert"] = "not-a-certificate",
        };

        Assert.Throws<OptionsValidationException>(() => Build(entries));
    }
}
