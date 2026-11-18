using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// Slice 5b (ADR-0005 item 5): <c>AddCredProx(configuration)</c> is the one core call a
/// host makes before its package calls. It must register the whole core default stack —
/// a sample host that calls nothing else must resolve every core service the granular
/// calls would have given it — and calling it twice must be the same as once.
/// </summary>
public sealed class CoreDefaultsRegistrationTests
{
    private static IConfiguration EmptyConfig() =>
        new ConfigurationBuilder().AddInMemoryCollection([]).Build();

    [Fact]
    public void AddCredProx_OneCall_RegistersTheWholeCoreDefaultStack()
    {
        var services = new ServiceCollection();
        services.AddCredProx(EmptyConfig());
        using var provider = services.BuildServiceProvider();

        Assert.NotNull(provider.GetRequiredService<ITokenCache>());
        Assert.NotNull(provider.GetRequiredService<ISecretSource>());
        Assert.NotNull(provider.GetRequiredService<SecretAccessorFactory>());
        Assert.NotNull(provider.GetRequiredService<CredentialRegistryProvider>().Current);

        // The StaticKey credential type rides in with its validator: a credentials-only
        // host gets exactly what AddCredProxBuiltInCredentials + AddCredProxCredentials gave.
        Assert.Contains(
            provider.GetServices<IValidateOptions<StaticKeyOptions>>(),
            validator => validator is StaticKeyOptionsValidator);
        Assert.Single(
            services,
            descriptor => descriptor.ServiceType == typeof(CredentialTypeRegistration));
    }

    [Fact]
    public void AddCredProx_CalledTwice_IsTheSameAsOnce()
    {
        // Idempotence is the contract: the marker guard must keep the granular calls from
        // stacking duplicates (a second CredentialTypeRegistration would shadow nothing
        // but double the registration set every binder walks).
        var services = new ServiceCollection();
        services.AddCredProx(EmptyConfig());
        services.AddCredProx(EmptyConfig());
        using var provider = services.BuildServiceProvider();

        Assert.Single(
            services,
            descriptor => descriptor.ServiceType == typeof(CredentialTypeRegistration));
        Assert.Single(provider.GetServices<ITokenCache>());
        Assert.NotNull(provider.GetRequiredService<CredentialRegistryProvider>().Current);
    }
}
