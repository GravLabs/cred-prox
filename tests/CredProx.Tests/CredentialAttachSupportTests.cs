using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage for the credential attach support types: the registry provider's
/// constructor guards and rebind-success log line, the registry's name ordering and
/// lookup guard, and the token-client name rule. Each survivor was a statement or
/// boundary no existing assertion could see.
/// </summary>
public sealed class CredentialAttachSupportTests
{
    private static Dictionary<string, string?> Entries() => new()
    {
        ["CredProx:Credentials:contoso:Type"] = "StaticKey",
        ["CredProx:Credentials:contoso:Secret"] = "secret:contoso-key",
        ["CredProx:Credentials:contoso:Name"] = "X-Contoso",
        ["CredProx:Secrets:contoso-key"] = "value",
    };

    private static ServiceProvider Provider(Dictionary<string, string?> entries)
    {
        var config = new ConfigurationBuilder()
            .Add(new ReloadableMemoryConfigurationSource(entries))
            .Build();

        var services = new ServiceCollection();
        services.AddCredProxTokenCache();
        services.AddCredProxConfigurationSecrets(config);
        services.AddCredProxBuiltInCredentials();
        services.AddCredProxCredentials(config);
        return services.BuildServiceProvider();
    }

    [Fact]
    public void Ctor_NullBinder_Throws_NamingBinder()
    {
        var sp = Provider(Entries());

        var ex = Assert.Throws<ArgumentNullException>(() =>
            new CredentialRegistryProvider(
                null!,
                sp.GetRequiredService<ISecretSource>(),
                NullLogger<CredentialRegistryProvider>.Instance));

        Assert.Equal("binder", ex.ParamName);
    }

    [Fact]
    public void Ctor_NullSecretSource_Throws_NamingSecretSource()
    {
        var sp = Provider(Entries());

        var ex = Assert.Throws<ArgumentNullException>(() =>
            new CredentialRegistryProvider(
                sp.GetRequiredService<CredentialBinder>(),
                null!,
                NullLogger<CredentialRegistryProvider>.Instance));

        Assert.Equal("secretSource", ex.ParamName);
    }

    [Fact]
    public void Ctor_NullLogger_Throws_NamingLogger()
    {
        var sp = Provider(Entries());

        var ex = Assert.Throws<ArgumentNullException>(() =>
            new CredentialRegistryProvider(
                sp.GetRequiredService<CredentialBinder>(),
                sp.GetRequiredService<ISecretSource>(),
                null!));

        Assert.Equal("logger", ex.ParamName);
    }

    // The rebind-success line is the operator's witness that a config change took
    // effect; its removal must be visible to a test.
    [Fact]
    public void RebindSuccess_LogsInformation_NamingTheRebind()
    {
        var logs = new CapturingLoggerFactory();
        var entries = Entries();
        var source = new ReloadableMemoryConfigurationSource(entries);
        var config = new ConfigurationBuilder().Add(source).Build();

        var services = new ServiceCollection();
        services.AddCredProxTokenCache();
        services.AddCredProxConfigurationSecrets(config);
        services.AddCredProxBuiltInCredentials();
        services.AddCredProxCredentials(config);
        services.AddSingleton<ILoggerFactory>(logs);
        var provider = services.BuildServiceProvider().GetRequiredService<CredentialRegistryProvider>();
        var reloadable = (ReloadableMemoryConfigurationProvider)config.Providers
            .OfType<ReloadableMemoryConfigurationProvider>().Single();

        reloadable.Set("CredProx:Credentials:beta:Type", "StaticKey");
        reloadable.Set("CredProx:Credentials:beta:Secret", "plain-beta-key");
        reloadable.Set("CredProx:Credentials:beta:Name", "X-Beta");
        reloadable.Reload();

        Assert.NotNull(provider.Current.Get("beta"));
        Assert.Contains(
            logs.Entries,
            e => e.Level == LogLevel.Information
                && e.Message.Contains("credentials rebound", StringComparison.Ordinal));
    }

    [Fact]
    public void Names_AreOrdered_AscendingCaseInsensitive()
    {
        var entries = Entries();
        entries["CredProx:Credentials:alpha:Type"] = "StaticKey";
        entries["CredProx:Credentials:alpha:Secret"] = "plain-alpha";
        entries["CredProx:Credentials:alpha:Name"] = "X-Alpha";
        var provider = Provider(entries);

        Assert.Equal(["alpha", "contoso"], provider.GetRequiredService<CredentialRegistryProvider>().Current.Names);
    }

    [Fact]
    public void Get_NullName_Throws_NamingName()
    {
        var provider = Provider(Entries());

        // The dictionary fallthrough would name the parameter 'key'; the guard's
        // caller-facing name is 'name'.
        var ex = Assert.Throws<ArgumentNullException>(() => provider.GetRequiredService<CredentialRegistryProvider>().Current.Get(null!));

        Assert.Equal("name", ex.ParamName);
    }

    [Fact]
    public void Get_UnknownName_MessageNamesTheSection()
    {
        var provider = Provider(Entries());

        var ex = Assert.Throws<InvalidOperationException>(() => provider.GetRequiredService<CredentialRegistryProvider>().Current.Get("ghost"));

        Assert.Contains("is not configured under CredProx:Credentials", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null, "credprox-token")]
    [InlineData("", "credprox-token")]
    [InlineData("myconn", "credprox-token:myconn")]
    public void ForConnection(string? connection, string expected) =>
        Assert.Equal(expected, CredProxHttpClientNames.ForConnection(connection));
}
