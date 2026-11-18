using System.Diagnostics.CodeAnalysis;
using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registration extensions of the CredProx.Operations add-on (ADR-0005): the outbound
/// throttle, the resilience adapter and the health probes, moved out of the core with
/// their names and configuration sections unchanged. Call after
/// <c>AddCredProx(configuration)</c>; configure a section without the add-on registered
/// and the core refuses startup naming this package.
/// </summary>
[Experimental("CREDPROX001")]
public static class CredProxOperationsServiceCollectionExtensions
{
    /// <summary>
    /// Turns on credential health monitoring: binds <c>CredProx:Health</c> (probe interval, certificate warning
    /// window), registers the built-in probes — token obtainable (through the token
    /// cache, so a valid cached token costs no vendor call) and certificate expiry — and
    /// runs them on a background loop that feeds an ASP.NET Core health check
    /// (<c>credprox</c>), metrics on the <c>CredProx</c> meter and transition warnings.
    /// Custom probes are plain <see cref="ICredentialHealthProbe"/> registrations. Call
    /// after <c>AddCredProxCredentials</c> and <c>AddCredProx(configuration)</c> — the
    /// probes read those registries.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The application configuration root.</param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    public static IServiceCollection AddCredProxHealthProbes(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddLogging();
        services.TryAddSingleton(TimeProvider.System);

        // M17 (§3.3): unknown keys under CredProx:Health would bind to nothing — rejected.
        CredProxConfigValidation.RejectUnknownKeysAtStartup(configuration, "CredProx:Health", typeof(CredProxHealthOptions));

        var options = new CredProxHealthOptions();
        configuration.GetSection("CredProx:Health").Bind(options);
        services.TryAddSingleton(options);

        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<ICredentialHealthProbe, TokenObtainableProbe>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<ICredentialHealthProbe, CertificateExpiryProbe>());
        services.TryAddSingleton<CredentialHealthSnapshot>();
        services.AddHostedService<CredentialHealthProbeService>();
        services.AddHealthChecks().AddCheck<CredProxHealthCheck>("credprox");
        return services;
    }

    /// <summary>
    /// Turns on outbound throttling: binds
    /// <c>CredProx:Throttling</c> (per-cluster rate and concurrency limits, bounded queue,
    /// vendor-429 pause) and registers the throttle pipeline feature. Limits are per YARP
    /// cluster; a full queue or an exceeded wait answers 429 with <c>Retry-After</c>
    /// (<c>credprox.throttled</c>), and a vendor 429 pauses its cluster for the advertised
    /// duration. Options are validated eagerly here — a bad limit fails startup. Changing
    /// limits takes a restart.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The application configuration root.</param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    public static IServiceCollection AddCredProxThrottling(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.TryAddSingleton(TimeProvider.System);

        // M17 (§3.3): unknown keys under CredProx:Throttling would bind to nothing —
        // rejected before the value validator runs, same eager startup failure.
        CredProxConfigValidation.RejectUnknownKeysAtStartup(configuration, "CredProx:Throttling", typeof(ThrottleOptions));

        var options = new ThrottleOptions();
        configuration.GetSection("CredProx:Throttling").Bind(options);
        var validation = new ThrottleOptionsValidator().Validate(null, options);
        if (validation.Failed)
        {
            throw new Microsoft.Extensions.Options.OptionsValidationException(
                nameof(ThrottleOptions), typeof(ThrottleOptions), validation.Failures);
        }

        services.TryAddSingleton(options);
        services.TryAddSingleton<ClusterThrottleRegistry>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IPipelineFeature, CredProxThrottleFeature>());
        return services;
    }

    /// <summary>
    /// Turns on the resilience adapter: binds
    /// <c>CredProx:Resilience</c> (attempt timeout, retry, circuit breaker) and registers
    /// the resilience pipeline feature. Per cluster: retry covers idempotent methods only
    /// (POST never, unless <c>RetryNonIdempotent</c> and the body is buffered within the
    /// cap); an open circuit answers 503 (<c>credprox.upstream_unavailable</c>) without
    /// reaching the upstream, and half-opens after the break duration. Options are
    /// validated eagerly here — a bad setting fails startup.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The application configuration root.</param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    public static IServiceCollection AddCredProxResilience(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        // M17 (§3.3): unknown keys under CredProx:Resilience would bind to nothing —
        // rejected before the value validator runs, same eager startup failure.
        CredProxConfigValidation.RejectUnknownKeysAtStartup(configuration, "CredProx:Resilience", typeof(ResilienceOptions));

        var options = new ResilienceOptions();
        configuration.GetSection("CredProx:Resilience").Bind(options);
        var validation = new ResilienceOptionsValidator().Validate(null, options);
        if (validation.Failed)
        {
            throw new Microsoft.Extensions.Options.OptionsValidationException(
                nameof(ResilienceOptions), typeof(ResilienceOptions), validation.Failures);
        }

        services.TryAddSingleton(options);
        services.TryAddSingleton<ClusterResilienceRegistry>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IPipelineFeature, CredProxResilienceFeature>());
        return services;
    }
}
