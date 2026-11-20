using System.Security.Claims;
using System.Threading;
using CredProx;
using CredProx.Abstractions;
using CredProx.CallerKeys;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.Extensions.Time.Testing;
using Xunit;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;

namespace CredProx.Tests;

/// <summary>
/// ADR-0006 item 1: single services are replaced host-first — register your own before the
/// <c>AddCredProx…</c> call and it is the one used. One cell per documented replace path;
/// together they make the contract executable. Pipeline stages are deliberately NOT here:
/// extend-only is ADR-0006 item 2 and the stages' own cells pin their behaviour.
/// </summary>
public sealed class HostFirstReplacementTests
{
    private static IConfiguration Config(params (string Key, string Value)[] entries) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(entries.ToDictionary(e => e.Key, e => e.Value)!)
            .Build();

    // ---- the single services: host registers first, the host's instance resolves ----

    [Fact]
    public void ITokenCache_HostRegisteredBeforeAddCredProx_Resolves()
    {
        var cache = new HostTokenCache();
        var services = new ServiceCollection();
        services.AddSingleton<ITokenCache>(cache);
        services.AddCredProx(Config());

        using var provider = services.BuildServiceProvider();
        Assert.Same(cache, provider.GetRequiredService<ITokenCache>());
        // The built-in cache was not added beside it (TryAdd, not Add).
        Assert.Single(provider.GetServices<ITokenCache>());
    }

    [Fact]
    public void ISecretSource_HostRegisteredBeforeAddCredProx_Resolves()
    {
        var source = new HostSecretSource();
        var services = new ServiceCollection();
        services.AddSingleton<ISecretSource>(source);
        services.AddCredProx(Config());

        using var provider = services.BuildServiceProvider();
        Assert.Same(source, provider.GetRequiredService<ISecretSource>());
        Assert.Single(provider.GetServices<ISecretSource>());
    }

    [Fact]
    public void TimeProvider_HostRegisteredBeforeAddCredProx_Resolves()
    {
        var clock = new FakeTimeProvider();
        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(clock);
        services.AddCredProx(Config());

        using var provider = services.BuildServiceProvider();
        Assert.Same(clock, provider.GetRequiredService<TimeProvider>());
    }

    [Fact]
    public void ICallerStore_HostRegisteredBeforeAddCredProxCallerAuthentication_Resolves()
    {
        var store = new HostCallerStore();
        var config = Config(
            ("CredProx:Callers:app-a:Keys:0:KeyId", "k1"),
            ("CredProx:Callers:app-a:Keys:0:KeyHash", "sha256:" + new string('a', 64)));
        var services = new ServiceCollection();
        services.AddSingleton<ICallerStore>(store);
        services.AddCredProxCallerAuthentication(config);

        using var provider = services.BuildServiceProvider();
        Assert.Same(store, provider.GetRequiredService<ICallerStore>());
    }

    [Fact]
    public void ICallerTokenMapper_HostRegisteredBeforeTheTokenCall_Resolves()
    {
        var mapper = new HostCallerTokenMapper();
        var config = Config(
            ("CredProx:CallerToken:Authority", "https://issuer.invalid/"),
            ("CredProx:CallerToken:Audience", "credprox-test"));
        var services = new ServiceCollection();
        services.AddSingleton<ICallerTokenMapper>(mapper);
        services.AddCredProxCallerTokenAuthentication(config);

        using var provider = services.BuildServiceProvider();
        Assert.Same(mapper, provider.GetRequiredService<ICallerTokenMapper>());
        // The built-in mapper is not registered beside it — one mapper, the host's.
        Assert.Single(provider.GetServices<ICallerTokenMapper>());
    }

    // ---- the designed swap point: registerScheme hands the scheme to the host ----

    [Fact]
    public async Task CallerToken_RegisterScheme_HostHandlerOwnsTheScheme()
    {
        var mapper = new HostCallerTokenMapper();
        var services = new ServiceCollection();
        services.AddSingleton<ICallerTokenMapper>(mapper);
        services.AddCredProxCallerTokenAuthentication(
            Config(),
            builder => builder.AddScheme<AuthenticationSchemeOptions, HostTokenHandler>(
                CallerTokenOptions.Scheme, configureOptions: null));

        using var provider = services.BuildServiceProvider();

        // The scheme validates with the host's handler, not the stock JWT bearer one.
        var scheme = await provider
            .GetRequiredService<IAuthenticationSchemeProvider>()
            .GetSchemeAsync(CallerTokenOptions.Scheme);
        Assert.NotNull(scheme);
        Assert.Equal(typeof(HostTokenHandler), scheme.HandlerType);

        // The swap marker rides, so the startup guard still warns on an empty swap;
        // the mapper stays host-first and the options stay the config-bound ones.
        Assert.NotNull(provider.GetRequiredService<CallerTokenSwapRequested>());
        Assert.Same(mapper, provider.GetRequiredService<ICallerTokenMapper>());
        Assert.NotNull(provider.GetRequiredService<CallerTokenOptions>());
    }

    // ---- the forwarder factory: subclass it, Replace after the call ----

    [Fact]
    public void ForwarderFactory_SubclassReplacedAfterAddCredProx_Resolves()
    {
        var config = Config();
        var services = new ServiceCollection();
        services.AddCredProxConfigurationSecrets(config);
        services.AddReverseProxy().AddCredProx(config);

        // CredProx registers its factory with Replace, so the host's hook is its own
        // Replace afterwards (ADR-0006 item 1): the class is public and not sealed.
        services.Replace(ServiceDescriptor.Singleton<IForwarderHttpClientFactory>(
            sp => new HostForwarderFactory(sp)));

        using var provider = services.BuildServiceProvider();
        Assert.IsType<HostForwarderFactory>(provider.GetRequiredService<IForwarderHttpClientFactory>());
    }

    // ---- the AddCredProx factory descriptors: dedupe, host-factory entries, the hosted delegate ----

    [Fact]
    public void RepeatedAddCredProx_FactoryRegistrationsDedupe()
    {
        var config = Config();
        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(config);
        // The default stack the real host calls first (token cache, secrets, credentials).
        services.AddCredProx(config);
        var builder = services.AddReverseProxy();
        builder.AddCredProx(config);
        builder.AddCredProx(config);

        using var provider = services.BuildServiceProvider();

        // Each factory-registered built-in resolves exactly once across the repeated calls:
        // the dedup compares the METHOD behind the factory delegate, not the delegate
        // instance — the same lambda compiles to one method, so even a capturing lambda
        // (a fresh delegate object per call) dedupes. The factory shape therefore keeps the
        // type-activation dedup semantics.
        Assert.Single(provider.GetServices<IRequestFeature>().OfType<DestinationResolutionFeature>());
        Assert.Single(provider.GetServices<Yarp.ReverseProxy.Transforms.Builder.ITransformProvider>()
            .OfType<CredProxTransformProvider>());
        Assert.Single(provider.GetServices<IConfigValidator>().OfType<CredProxConfigValidator>());
        Assert.Single(provider.GetServices<IHostedService>().OfType<CredProxStartupValidator>());
    }

    [Fact]
    public void HostFactoryConfigValidatorBeforeAddCredProx_KeepsBothEntries()
    {
        var config = Config();
        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(config);
        services.AddSingleton<IConfigValidator>(sp => new HostConfigValidator());
        services.AddCredProx(config);
        services.AddReverseProxy().AddCredProx(config);

        using var provider = services.BuildServiceProvider();

        // A factory-registered descriptor only dedupes against the identical registration,
        // so the host's factory entry stands untouched and CredProx's built-in validator
        // still runs beside it — host-first means the host's entry is never replaced, and
        // validators are enumerate services where both run.
        Assert.Single(provider.GetServices<IConfigValidator>().OfType<HostConfigValidator>());
        Assert.Single(provider.GetServices<IConfigValidator>().OfType<CredProxConfigValidator>());
    }

    [Fact]
    public void StartupValidator_HostedEntrySharesTheRegisteredSingleton()
    {
        var config = Config();
        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(config);
        services.AddCredProx(config);
        services.AddReverseProxy().AddCredProx(config);

        using var provider = services.BuildServiceProvider();

        // The hosted-service descriptor delegates: the instance the host starts is the same
        // object registered for direct resolution, so the gate the host runs and the gate
        // anything else resolves are one instance.
        var validator = provider.GetRequiredService<CredProxStartupValidator>();
        Assert.Same(validator,
            Assert.Single(provider.GetServices<IHostedService>().OfType<CredProxStartupValidator>()));
    }

    // ---- stubs ----

    private sealed class HostConfigValidator : IConfigValidator
    {
        public ValueTask<IList<Exception>> ValidateRouteAsync(RouteConfig route) =>
            new(Array.Empty<Exception>());

        public ValueTask<IList<Exception>> ValidateClusterAsync(ClusterConfig cluster) =>
            new(Array.Empty<Exception>());
    }

    private sealed class HostTokenCache : ITokenCache
    {
        public ValueTask<string> GetTokenAsync(
            string credential,
            string? partition,
            Func<CancellationToken, ValueTask<(string Value, DateTimeOffset ExpiresAt)>> acquire,
            CancellationToken cancellationToken) => new("host-token");

        public void Invalidate(string credential, string? partition)
        {
        }
    }

    private sealed class HostSecretSource : ISecretSource
    {
        public string Scheme => "host";

        public ValueTask<string?> GetSecretAsync(string name, CancellationToken cancellationToken) =>
            new((string?)null);

        public IChangeToken GetChangeToken() =>
            new CancellationChangeToken(new CancellationTokenSource().Token);
    }

    private sealed class HostCallerStore : ICallerStore
    {
        public ValueTask<CallerKeyMatch?> ResolveKeyAsync(string keyValue, CancellationToken cancellationToken) =>
            new((CallerKeyMatch?)null);
    }

    private sealed class HostCallerTokenMapper : ICallerTokenMapper
    {
        public CallerTokenMapping? MapToken(ClaimsPrincipal principal) => null;
    }

    private sealed class HostTokenHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        System.Text.Encodings.Web.UrlEncoder encoder)
        : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        protected override Task<AuthenticateResult> HandleAuthenticateAsync() =>
            Task.FromResult(AuthenticateResult.NoResult());
    }

    private sealed class HostForwarderFactory(IServiceProvider services)
        : CredProxForwarderHttpClientFactory(services)
    {
    }
}
