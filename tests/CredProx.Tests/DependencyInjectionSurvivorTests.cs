using CredProx;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage of the public registration surface: every Add* entry guards its
/// arguments, the built-in batch registers every credential-type validator, caller
/// authentication wires what the request path later resolves (logging, the system clock,
/// the caller policy, the secret-source plumbing, and the transient registry view), audit
/// and health carry their own host fallbacks, and the CallerAuth key errors keep their
/// full guidance text.
/// </summary>
public sealed class DependencyInjectionSurvivorTests
{
    private static IConfiguration EmptyConfig() =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>())
            .Build();

    // ---- argument guards ----
    // Each paramName is pinned too: the guard line being redundant downstream (the BCL
    // extensions and the registration ctors keep their own guards, all reporting the same
    // parameter names) is only an equivalence while the public paramName contract holds.

    private static void AssertGuard(Action act, string paramName) =>
        Assert.Equal(paramName, Assert.Throws<ArgumentNullException>(act).ParamName);

    [Fact]
    public void Guards_RejectNullCollectionsAndConfigs()
    {
        var config = EmptyConfig();
        var services = new ServiceCollection();

        AssertGuard(
            () => CredProxServiceCollectionExtensions.AddCredProxTokenCache(null!), "services");
        AssertGuard(
            () => CredProxServiceCollectionExtensions.AddCredProxConfigurationSecrets(null!, config), "services");
        AssertGuard(
            () => services.AddCredProxConfigurationSecrets(null!), "configuration");
        AssertGuard(
            () => CredProxServiceCollectionExtensions.AddCredProxCredentials(null!, config), "services");
        AssertGuard(
            () => services.AddCredProxCredentials(null!), "configuration");
        AssertGuard(
            () => CredProxServiceCollectionExtensions.AddCredProxBuiltInCredentials(null!), "services");
        AssertGuard(
            () => CredProxServiceCollectionExtensions.AddCredProxCallerAuthentication(null!, config), "services");
        AssertGuard(
            () => services.AddCredProxCallerAuthentication(null!), "configuration");
        AssertGuard(
            () => CredProxServiceCollectionExtensions.AddCredProxAudit(null!, config), "services");
        AssertGuard(
            () => services.AddCredProxAudit(null!), "configuration");
        AssertGuard(
            () => CredProxServiceCollectionExtensions.AddCredProxHealthProbes(null!, config), "services");
        AssertGuard(
            () => services.AddCredProxHealthProbes(null!), "configuration");
        AssertGuard(
            () => CredProxServiceCollectionExtensions.AddCredProxThrottling(null!, config), "services");
        AssertGuard(
            () => services.AddCredProxThrottling(null!), "configuration");
        AssertGuard(
            () => CredProxServiceCollectionExtensions.AddCredProxResilience(null!, config), "services");
        AssertGuard(
            () => services.AddCredProxResilience(null!), "configuration");
    }

    [Fact]
    public void CredentialType_GuardsServicesAndTypeName()
    {
        AssertGuard(
            () => CredProxServiceCollectionExtensions
                .AddCredProxCredentialType<StaticKeyProvider, StaticKeyOptions>(null!, "StaticKey"),
            "services");
        AssertGuard(
            () => new ServiceCollection()
                .AddCredProxCredentialType<StaticKeyProvider, StaticKeyOptions>(null!),
            "typeName");
        var empty = Assert.Throws<ArgumentException>(
            () => new ServiceCollection()
                .AddCredProxCredentialType<StaticKeyProvider, StaticKeyOptions>(string.Empty));
        Assert.Equal("typeName", empty.ParamName);
    }

    // ---- built-in credential batch ----

    [Fact]
    public void BuiltInCredentials_RegisterEveryTypeValidator()
    {
        var services = new ServiceCollection();
        services.AddCredProxBuiltInCredentials();
        using var provider = services.BuildServiceProvider();

        Assert.NotNull(provider.GetService<IValidateOptions<OAuthClientCredentialsOptions>>());
        Assert.NotNull(provider.GetService<IValidateOptions<LoginExchangeOptions>>());
        Assert.NotNull(provider.GetService<IValidateOptions<StaticKeyOptions>>());
        Assert.NotNull(provider.GetService<IValidateOptions<JwtAssertionOptions>>());
        Assert.NotNull(provider.GetService<IValidateOptions<HmacOptions>>());
        Assert.NotNull(provider.GetService<IValidateOptions<TokenExchangeOptions>>());
    }

    // ---- caller authentication wiring ----

    private static ServiceProvider WireCallerAuth()
    {
        // Caller authentication refuses to register with an empty registry, so the
        // wiring runs over one real caller.
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
                ["CredProx:Callers:app-a:Keys:0:KeyHash"] = "sha256:" + new string('a', 64),
            })
            .Build();
        var services = new ServiceCollection();
        services.AddCredProxConfigurationSecrets(config);
        services.AddCredProxCallerAuthentication(config);
        return services.BuildServiceProvider();
    }

    [Fact]
    public async Task CallerAuthentication_WiresWhatTheRequestPathResolves()
    {
        using var provider = WireCallerAuth();

        // Logging and the shared clock: the extensions add them so a bare host still
        // resolves every dependent service.
        Assert.NotNull(provider.GetRequiredService<ILoggerFactory>());
        Assert.Same(TimeProvider.System, provider.GetRequiredService<TimeProvider>());

        // The caller policy for middleware-fronted hosts.
        var policy = await provider
            .GetRequiredService<IAuthorizationPolicyProvider>()
            .GetPolicyAsync(CredProxAuth.CallerPolicy);
        Assert.NotNull(policy);

        // The secret plumbing and the store the handler resolves against.
        Assert.NotNull(provider.GetRequiredService<SecretAccessorFactory>());
        Assert.NotNull(provider.GetRequiredService<ICallerStore>());
    }

    [Fact]
    public void CallerAuthentication_WithoutTheConfigSecretSource_StillWiresThePlumbing()
    {
        // Callers authenticate against key hashes resolved through whatever ISecretSource
        // the host registered, not only the configuration-backed one: the extension's own
        // SecretAccessorFactory registration is the only source of that service here.
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
                ["CredProx:Callers:app-a:Keys:0:KeyHash"] = "sha256:" + new string('a', 64),
            })
            .Build();
        var services = new ServiceCollection();
        services.AddSingleton<ISecretSource>(new NullSecretSource());

        services.AddCredProxCallerAuthentication(config);

        Assert.NotNull(services.BuildServiceProvider().GetRequiredService<SecretAccessorFactory>());
    }

    private sealed class NullSecretSource : ISecretSource
    {
        public string Scheme => "triage";

        public ValueTask<string?> GetSecretAsync(string name, CancellationToken cancellationToken) =>
            new((string?)null);

        public IChangeToken GetChangeToken() => new CancellationChangeToken(new CancellationTokenSource().Token);
    }

    [Fact]
    public void CallerAuthentication_TransientRegistryIsTheLiveView()
    {
        using var provider = WireCallerAuth();

        var registryProvider = provider.GetRequiredService<CallerRegistryProvider>();
        Assert.Same(registryProvider.Current, provider.GetRequiredService<CallerRegistry>());
    }

    [Fact]
    public void CallerAuthentication_NestedHeaderName_RejectsAsNotScalar()
    {
        // The scalar rule's full guidance must stay pinned: half the sentence gone reads
        // like a different mistake.
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["CredProx:CallerAuth:HeaderName:Foo"] = "x",
            })
            .Build();
        var services = new ServiceCollection();

        var ex = Assert.Throws<OptionsValidationException>(
            () => services.AddCredProxCallerAuthentication(config));

        var failure = Assert.Single(ex.Failures);
        Assert.Contains("must be a scalar value", failure, StringComparison.Ordinal);
        Assert.Contains("not a section.", failure, StringComparison.Ordinal);
    }

    // ---- audit and health host fallbacks ----

    [Fact]
    public void Audit_AddsLoggingAndTheBuiltInSink()
    {
        var services = new ServiceCollection();
        services.AddCredProxAudit(EmptyConfig());
        using var provider = services.BuildServiceProvider();

        Assert.NotNull(provider.GetRequiredService<ILoggerFactory>());
        Assert.Contains(
            provider.GetServices<IAuditSink>(),
            sink => sink is LoggerAuditSink);
    }

    [Fact]
    public void HealthProbes_RegisterTheSharedClock()
    {
        var services = new ServiceCollection();
        services.AddCredProxHealthProbes(EmptyConfig());
        using var provider = services.BuildServiceProvider();

        Assert.Same(TimeProvider.System, provider.GetRequiredService<TimeProvider>());
    }
}
