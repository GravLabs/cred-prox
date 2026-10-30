using CredProx;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// §5.2 "Secrets" row: <c>secret:</c> references resolve; config reload updates resolved
/// values.
/// </summary>
public sealed class ConfigurationSecretSourceTests
{
    [Fact]
    public void Scheme_IsSecret()
    {
        Assert.Equal("secret", CreateSource(out _).Scheme);
    }

    [Fact]
    public async Task GetSecretAsync_ResolvesValuesFromSecretsSection()
    {
        var source = CreateSource(out _, ("CredProx:Secrets:contoso-client-id", "client-123"));

        Assert.Equal("client-123", await source.GetSecretAsync("contoso-client-id", default));
    }

    [Fact]
    public async Task GetSecretAsync_UnknownName_ReturnsNull()
    {
        var source = CreateSource(out _);

        Assert.Null(await source.GetSecretAsync("nope", default));
    }

    [Fact]
    public async Task GetSecretAsync_RejectsNullName()
    {
        var source = CreateSource(out _);

        await Assert.ThrowsAsync<ArgumentNullException>(() => source.GetSecretAsync(null!, default).AsTask());
    }

    [Fact]
    public async Task Reload_UpdatesResolvedValues()
    {
        var source = CreateSource(out var provider, ("CredProx:Secrets:contoso-client-id", "v1"));
        Assert.Equal("v1", await source.GetSecretAsync("contoso-client-id", default));

        provider.Set("CredProx:Secrets:contoso-client-id", "v2");
        provider.Reload();

        Assert.Equal("v2", await source.GetSecretAsync("contoso-client-id", default));
    }

    [Fact]
    public void GetChangeToken_FiresOnReload()
    {
        var source = CreateSource(out var provider);
        var token = source.GetChangeToken();
        var fired = false;
        token.RegisterChangeCallback(_ => fired = true, state: null);

        provider.Reload();

        Assert.True(fired);
    }

    [Fact]
    public void GetChangeToken_KeepsFiringAcrossReloads()
    {
        var source = CreateSource(out var provider);

        var first = source.GetChangeToken();
        provider.Reload();

        var second = source.GetChangeToken();
        provider.Reload();

        var firstFired = false;
        var secondFired = false;
        first.RegisterChangeCallback(_ => firstFired = true, state: null);
        second.RegisterChangeCallback(_ => secondFired = true, state: null);

        Assert.True(firstFired);
        Assert.True(secondFired);
    }

    private static ConfigurationSecretSource CreateSource(
        out ReloadableMemoryConfigurationProvider provider,
        params (string Key, string? Value)[] data)
    {
        var dictionary = data.ToDictionary(d => d.Key, d => d.Value, StringComparer.OrdinalIgnoreCase);
        var configuration = new ConfigurationBuilder()
            .Add(new ReloadableMemoryConfigurationSource(dictionary))
            .Build();
        provider = (ReloadableMemoryConfigurationProvider)configuration.Providers.OfType<ReloadableMemoryConfigurationProvider>().Single();
        return new ConfigurationSecretSource(configuration);
    }
}
