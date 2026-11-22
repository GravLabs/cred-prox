using System.Diagnostics.CodeAnalysis;
using Azure.Core;
using CredProx;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M49 unit 3 (ADR-0007): <c>services.AddCredProx(configuration)</c> is the one place the
/// host passes its configuration and it hands back a <see cref="CredProxBuilder"/>. Each
/// add-on package contributes one chained call; the reverse-proxy leg takes no
/// configuration and refuses to run before the entry. Plugin authors extend the builder.
/// </summary>
public class CredProxBuilderTests
{
    private static IConfiguration Config(params (string Key, string Value)[] values) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(values.ToDictionary(v => v.Key, v => (string?)v.Value, StringComparer.Ordinal))
            .Build();

    private static IEnumerable<CredentialTypeRegistration> Registrations(IServiceCollection services) =>
        services
            .Where(d => d.ServiceType == typeof(CredentialTypeRegistration))
            .Select(d => (CredentialTypeRegistration)d.ImplementationInstance!);

    // ---- the entry hands back the builder ----

    [Fact]
    public void Entry_ReturnsBuilder_CarryingServicesAndConfiguration()
    {
        var services = new ServiceCollection();
        var config = Config();

        var builder = services.AddCredProx(config);

        Assert.Same(services, builder.Services);
        Assert.Same(config, builder.Configuration);
    }

    [Fact]
    public void Entry_SecondCall_ReturnsBuilder_AndRegistersTheStackOnce()
    {
        var services = new ServiceCollection();
        var config = Config();

        services.AddCredProx(config);
        var second = services.AddCredProx(config);

        Assert.NotNull(second);
        Assert.Single(services, d => d.ServiceType == typeof(CoreDefaultsRegistered));
    }

    [Fact]
    public void Entry_MakesItsConfigurationResolvable()
    {
        // The reverse-proxy leg reads the one configuration pass from DI (ADR-0007 item 5),
        // so the entry must leave it resolvable.
        var services = new ServiceCollection();
        var config = Config();

        services.AddCredProx(config);

        Assert.Contains(services, d =>
            d.ServiceType == typeof(IConfiguration) && ReferenceEquals(d.ImplementationInstance, config));
    }

    [Fact]
    public void Entry_MarkerCarriesThePassedConfiguration()
    {
        // The reverse-proxy leg's read-back path: the marker instance, not a collection
        // scan for an IConfiguration instance, carries the exact pass (ADR-0007 item 5).
        var services = new ServiceCollection();
        var config = Config();

        services.AddCredProx(config);

        Assert.Single(services, d =>
            d.ServiceType == typeof(CoreDefaultsRegistered)
            && ReferenceEquals((d.ImplementationInstance as CoreDefaultsRegistered)?.Configuration, config));
    }

    [Fact]
    public void ReverseProxyLeg_HandsThroughEntryConfig_WhenHostPreRegisteredAFactory()
    {
        // The web host shape: WebApplication.CreateBuilder registers IConfiguration by
        // factory, so the entry's TryAdd keeps that registration and no instance
        // descriptor exists. The leg must still get the entry's configuration pass —
        // every web consumer hits this shape (M49 consumer-compat witness).
        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(_ => Config(("CredProx:Host", "host")));
        var config = Config(("CredProx:Destinations:echo:Template", "http://localhost:8088"));

        services.AddCredProx(config);
        var leg = services.AddReverseProxy()
            .LoadFromConfig(config.GetSection("ReverseProxy"))
            .AddCredProx();

        Assert.NotNull(leg);
    }

    [Fact]
    public void ReverseProxyLeg_Refuses_WhenTheEntryHasNotRun()
    {
        var services = new ServiceCollection();
        var config = new ConfigurationBuilder().Build();

        var ex = Assert.Throws<InvalidOperationException>(() =>
            services.AddReverseProxy().LoadFromConfig(config.GetSection("ReverseProxy")).AddCredProx());
        Assert.Contains("requires the services entry first", ex.Message, StringComparison.Ordinal);
    }

    // ---- plugin seams on the builder ----

    private sealed class StubAuthenticator : ICallerAuthenticator
    {
        public string CredentialRequirementHint => "stub credential";

        public ValueTask<CallerAuthenticationResult> AuthenticateAsync(
            HttpContext context, CancellationToken cancellationToken) =>
            ValueTask.FromResult(CallerAuthenticationResult.NoCredential());
    }

    private sealed class PassValidator : ICallerRegistryValidator
    {
        public IReadOnlyList<string> Validate(IReadOnlyList<CallerRegistryEntry> callers) => [];
    }

    private sealed class ConstContributor : ICallerRegistryContributor
    {
        public object Contribute(CallerRegistry registry) => "contributed";
    }

    private sealed class StubOptions
    {
        public string? Name { get; set; }
    }

    private sealed class StubProvider : ICredentialProvider<StubOptions>
    {
        public string Type => "Stub";

        public ValueTask<string> GetCredentialAsync(
            StubOptions options,
            ISecretAccessor secrets,
            CredentialRequestContext context,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult("stub");
    }

    [Fact]
    public void WithCallerAuthenticator_RegistersTheAuthenticator_AndTheCallerStage()
    {
        var services = new ServiceCollection();
        var builder = services.AddCredProx(Config());

        builder.WithCallerAuthenticator<StubAuthenticator>();

        Assert.Single(services, d =>
            d.ServiceType == typeof(ICallerAuthenticator) && d.ImplementationType == typeof(StubAuthenticator));
        Assert.Contains(services, d =>
            d.ServiceType == typeof(IRequestFeature) &&
            d.ImplementationType == typeof(CallerAuthenticationFeature));
    }

    [Fact]
    public void WithCallerRegistryValidator_RegistersTheValidator()
    {
        var services = new ServiceCollection();
        var builder = services.AddCredProx(Config());

        builder.WithCallerRegistryValidator<PassValidator>();

        Assert.Contains(services, d =>
            d.ServiceType == typeof(ICallerRegistryValidator) &&
            d.ImplementationType == typeof(PassValidator));
    }

    [Fact]
    public void WithCallerRegistryContributor_RegistersTheContributor()
    {
        var services = new ServiceCollection();
        var builder = services.AddCredProx(Config());

        builder.WithCallerRegistryContributor<ConstContributor>();

        Assert.Contains(services, d =>
            d.ServiceType == typeof(ICallerRegistryContributor) &&
            d.ImplementationType == typeof(ConstContributor));
    }

    [Fact]
    public void WithCredentialType_BuiltInNameFirst_KeepsTheBuiltInProvider()
    {
        // The unit-2 dedupe rule holds through the builder seam: the built-in registration
        // won first, so a plugin that re-registers the same type name does not replace it.
        var services = new ServiceCollection();
        var builder = services.AddCredProx(Config());

        builder.WithCredentialType<StubProvider, StubOptions>("Hmac");

        var hmac = Assert.Single(
            Registrations(services),
            r => r.TypeName == "Hmac");
        Assert.NotEqual(typeof(StubProvider), hmac.ProviderType);
    }

    [Fact]
    public void WithCredentialType_NewName_RegistersThePluginType()
    {
        var services = new ServiceCollection();
        var builder = services.AddCredProx(Config());

        builder.WithCredentialType<StubProvider, StubOptions>("Stub");

        var registered = Assert.Single(
            Registrations(services),
            r => r.TypeName == "Stub");
        Assert.Equal(typeof(StubProvider), registered.ProviderType);
        Assert.Equal(typeof(StubOptions), registered.OptionsType);
    }

    // ---- .AddIdentity() (CredProx.Identity) ----

    private static IConfiguration CallerTokenConfig() => Config(
        ("CredProx:CallerToken:Authority", "https://issuer.invalid"),
        ("CredProx:CallerToken:Audience", "credprox"));

    [Fact]
    public void AddIdentity_RegistersTheOAuthFamily()
    {
        var services = new ServiceCollection();
        var builder = services.AddCredProx(Config());

        builder.AddIdentity();

        Assert.Contains(Registrations(services), r => r.TypeName == "OAuthClientCredentials");
        Assert.Contains(Registrations(services), r => r.TypeName == "JwtAssertion");
        Assert.Contains(Registrations(services), r => r.TypeName == "TokenExchange");
    }

    [Fact]
    public void AddIdentity_WithoutCallerTokens_RegistersNoCallerTokenSchemeOrPolicy()
    {
        // ADR-0007 item 3, lead amendment: an OAuth-only host carries no authentication
        // scheme and no caller policy — the GitHubApp shape.
        var services = new ServiceCollection();
        var builder = services.AddCredProx(Config());

        builder.AddIdentity();

        using var provider = services.BuildServiceProvider();
        Assert.Null(provider.GetService<IAuthenticationSchemeProvider>());
        Assert.Null(provider.GetRequiredService<IOptions<AuthorizationOptions>>().Value
            .GetPolicy(CredProxAuth.CallerPolicy));
    }

    [Fact]
    public async Task AddIdentity_WithCallerTokens_RegistersTheCallerTokenScheme()
    {
        var services = new ServiceCollection();
        var builder = services.AddCredProx(CallerTokenConfig());

        builder.AddIdentity();

        using var provider = services.BuildServiceProvider();
        var schemes = await provider.GetRequiredService<IAuthenticationSchemeProvider>().GetAllSchemesAsync();
        Assert.Contains(schemes, s => s.Name == CallerTokenOptions.Scheme);
    }

    private sealed class SwapHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        System.Text.Encodings.Web.UrlEncoder encoder)
        : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        protected override Task<AuthenticateResult> HandleAuthenticateAsync() =>
            Task.FromResult(AuthenticateResult.NoResult());
    }

    [Fact]
    public async Task AddIdentity_SwapKeepsTheHostFirstScheme_WithoutAuthority()
    {
        // The M39 host-first swap survives unchanged: with a delegate the stock
        // Authority/Audience requirement does not apply and the host's scheme stands.
        var services = new ServiceCollection();
        var builder = services.AddCredProx(Config(("CredProx:CallerToken:Audience", "credprox")));

        builder.AddIdentity(auth =>
            auth.AddScheme<AuthenticationSchemeOptions, SwapHandler>(CallerTokenOptions.Scheme, "Host swap", _ => { }));

        using var provider = services.BuildServiceProvider();
        var schemes = await provider.GetRequiredService<IAuthenticationSchemeProvider>().GetAllSchemesAsync();
        var swap = Assert.Single(schemes, s => s.Name == CallerTokenOptions.Scheme);
        Assert.Equal(typeof(SwapHandler), swap.HandlerType);
    }

    [Fact]
    public void AddIdentity_SwapWithoutCallerTokens_Refuses()
    {
        // A swap delegate with no caller tokens is machinery for nothing — refuse naming
        // the section that would arm it.
        var services = new ServiceCollection();
        var builder = services.AddCredProx(Config());

        var ex = Assert.Throws<InvalidOperationException>(() =>
            builder.AddIdentity(auth =>
                auth.AddScheme<AuthenticationSchemeOptions, SwapHandler>("x", "x", _ => { })));

        Assert.Contains("CredProx:CallerToken", ex.Message, StringComparison.Ordinal);
    }

    // ---- .AddOperations() (CredProx.Operations) ----

    [Fact]
    public void AddOperations_NoSections_RegistersNoLeg()
    {
        // The new switch: each leg turns on from its own section. With no section the call
        // is cheap and inert (the legs' 0.14 defaults-on fate is a CHANGELOG entry).
        var services = new ServiceCollection();

        services.AddCredProx(Config()).AddOperations();

        Assert.DoesNotContain(services, d =>
            d.ImplementationType?.FullName == "CredProx.CredProxThrottleFeature");
        Assert.DoesNotContain(services, d =>
            d.ImplementationType?.FullName == "CredProx.CredProxResilienceFeature");
        Assert.DoesNotContain(services, d =>
            d.ImplementationType?.FullName == "CredProx.TokenObtainableProbe");
    }

    [Fact]
    public void AddOperations_ThrottlingSection_RegistersTheThrottleLegOnly()
    {
        var services = new ServiceCollection();

        services.AddCredProx(Config(("CredProx:Throttling:PauseOnVendorThrottle", "true"))).AddOperations();

        Assert.Contains(services, d =>
            d.ImplementationType?.FullName == "CredProx.CredProxThrottleFeature");
        Assert.DoesNotContain(services, d =>
            d.ImplementationType?.FullName == "CredProx.CredProxResilienceFeature");
        Assert.DoesNotContain(services, d =>
            d.ImplementationType?.FullName == "CredProx.TokenObtainableProbe");
    }

    [Fact]
    public void AddOperations_ResilienceSection_RegistersTheResilienceLegOnly()
    {
        var services = new ServiceCollection();

        services.AddCredProx(Config(("CredProx:Resilience:MaxRetries", "2"))).AddOperations();

        Assert.Contains(services, d =>
            d.ImplementationType?.FullName == "CredProx.CredProxResilienceFeature");
        Assert.DoesNotContain(services, d =>
            d.ImplementationType?.FullName == "CredProx.CredProxThrottleFeature");
    }

    [Fact]
    public void AddOperations_HealthSection_RegistersTheHealthLegOnly()
    {
        var services = new ServiceCollection();

        services.AddCredProx(Config(("CredProx:Health:Enabled", "true"))).AddOperations();

        Assert.Contains(services, d =>
            d.ImplementationType?.FullName == "CredProx.TokenObtainableProbe");
        Assert.Contains(services, d =>
            d.ImplementationType?.FullName == "CredProx.CertificateExpiryProbe");
        Assert.DoesNotContain(services, d =>
            d.ImplementationType?.FullName == "CredProx.CredProxThrottleFeature");
    }

    // ---- .AddAzure(credential) (CredProx.Azure) ----

    private sealed class StubTokenCredential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            default;

        public override ValueTask<AccessToken> GetTokenAsync(
            TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            ValueTask.FromResult(default(AccessToken));
    }

    [Fact]
    public void AddAzure_RegistersTheTokenCredentialType_AndTheInstance()
    {
        var credential = new StubTokenCredential();
        var services = new ServiceCollection();

        services.AddCredProx(Config()).AddAzure(credential);

        Assert.Contains(Registrations(services), r => r.TypeName == "TokenCredential");
        using var provider = services.BuildServiceProvider();
        Assert.Same(credential, provider.GetRequiredService<TokenCredential>());
    }

    // ---- the reverse-proxy leg: no configuration, entry first ----

    [Fact]
    public void ReverseProxy_AddCredProx_WithoutTheEntry_RefusesNamingTheEntry()
    {
        var services = new ServiceCollection();

        var ex = Assert.Throws<InvalidOperationException>(() => services.AddReverseProxy().AddCredProx());

        Assert.Contains("services.AddCredProx", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ReverseProxy_AddCredProx_AfterTheEntry_RegistersPipelineAndGuard()
    {
        var services = new ServiceCollection();
        services.AddCredProx(Config());

        services.AddReverseProxy().AddCredProx();

        Assert.Contains(services, d => d.ServiceType == typeof(CredProxPipeline));
        Assert.Contains(services, d =>
            d.ServiceType == typeof(Microsoft.Extensions.Hosting.IHostedService) &&
            d.ImplementationType == typeof(CallerAuthenticatorStartupGuard));
    }
}
