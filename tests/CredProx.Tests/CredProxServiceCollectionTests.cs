using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The M2 service registrations resolve and are idempotent (TryAdd), with explicit
/// registration only (§3.5 rule 6).
/// </summary>
public sealed class CredProxServiceCollectionTests
{
    [Fact]
    public void AddCredProxTokenCache_RegistersInMemoryCache()
    {
        var services = new ServiceCollection();

        services.AddCredProxTokenCache();
        services.AddCredProxTokenCache(); // TryAdd: a second call is harmless

        var provider = services.BuildServiceProvider();

        var cache = provider.GetRequiredService<ITokenCache>();
        Assert.IsType<InMemoryTokenCache>(cache);
        Assert.Same(cache, provider.GetRequiredService<ITokenCache>());
    }

    [Fact]
    public void AddCredProxTokenCache_AppliesConfigureAction()
    {
        var services = new ServiceCollection();

        services.AddCredProxTokenCache(options => options.NegativeCacheTtl = TimeSpan.FromSeconds(42));

        var provider = services.BuildServiceProvider();

        Assert.Equal(TimeSpan.FromSeconds(42), provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<TokenCacheOptions>>().Value.NegativeCacheTtl);
    }

    [Fact]
    public void AddCredProxConfigurationSecrets_RegistersTheSecretStack()
    {
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder().AddInMemoryCollection().Build();

        services.AddCredProxConfigurationSecrets(configuration);

        var provider = services.BuildServiceProvider();

        Assert.IsType<ConfigurationSecretSource>(provider.GetRequiredService<ISecretSource>());
        Assert.NotNull(provider.GetRequiredService<SecretAccessorFactory>());
        Assert.NotNull(provider.GetRequiredService<SecretReferenceValidator>());
    }

    [Fact]
    public void Extensions_RejectNullArguments()
    {
        Assert.Throws<ArgumentNullException>(() => CredProxServiceCollectionExtensions.AddCredProxTokenCache(null!));

        var services = new ServiceCollection();
        Assert.Throws<ArgumentNullException>(() => services.AddCredProxConfigurationSecrets(null!));
    }
}
