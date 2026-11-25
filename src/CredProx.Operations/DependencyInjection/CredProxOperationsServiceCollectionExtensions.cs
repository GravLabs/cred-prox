using System.Diagnostics.CodeAnalysis;
using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Yarp.ReverseProxy.Configuration;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registration extensions of the CredProx.Operations add-on (ADR-0005): the outbound
/// throttle, the resilience adapter and the health probes, moved out of the core with
/// their names and configuration sections unchanged. Call after
/// <c>AddCredProx(configuration)</c>; configure a section without the add-on registered
/// and the core refuses startup naming this package.
/// </summary>
[Experimental("CREDPROX001")]
internal static class CredProxOperationsServiceCollectionExtensions
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
    internal static IServiceCollection AddCredProxHealthProbes(
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
        // ADR-0006 item 5: a switch that says off is off. With CredProx:Health:Enabled=false
        // neither the probe loop nor the "credprox" check is registered — a disabled host
        // gets no "credprox" entry reporting Healthy without ever probing. The options, the
        // built-in probes and the snapshot stay registered so a host can still resolve them.
        if (options.Enabled)
        {
            services.AddHostedService<CredentialHealthProbeService>();
            services.AddHealthChecks().AddCheck<CredProxHealthCheck>("credprox");
        }

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
    internal static IServiceCollection AddCredProxThrottling(
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
    internal static IServiceCollection AddCredProxResilience(
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

    /// <summary>
    /// Turns on usage metering (M50, ADR-0008): binds <c>CredProx:Metering</c> (the token
    /// parse window) and registers the metering features — the outbound-body counter, the
    /// per-request record at response completion, and the opt-in usage peek. Instruments
    /// land on the same <c>CredProx</c> meter as the throttle, resilience and health
    /// instruments. LLM token counts are a per-route opt-in through the
    /// <see cref="CredProxMetering.UsageRouteMetadata"/> metadata key, whose value NAMES
    /// the usage format — <c>"anthropic"</c>, <c>"openai"</c>, or a host reader's own
    /// <see cref="IUsageReader.Format"/>. Readers are selected by format first, media type
    /// second, so vendors sharing a media type never compete (M54, ADR-0009). Unknown keys
    /// are refused at startup and on every configuration reload, and so is a route value
    /// that names no registered format — metering config that cannot bind or cannot be
    /// served fails, never sits inert. Options are validated eagerly here — a bad window
    /// fails startup.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The application configuration root.</param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    internal static IServiceCollection AddCredProxMetering(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        services.AddLogging();
        // M17 (§3.3): unknown keys under CredProx:Metering would bind to nothing — rejected.
        CredProxConfigValidation.RejectUnknownKeysAtStartup(configuration, "CredProx:Metering", typeof(CredProxMeteringOptions));
        // Reload protection, on the public one-shot surface: the metering leg keeps its own
        // change-token walk alive (CredProxMeteringReloadGuard, M50 fold LOW-4), so an
        // unknown key introduced by a reload fails closed the same way it does at startup —
        // logged by kind on the M45 F-5 house pattern, never thrown on the reload thread.
        // The guard is resolved by the metering response feature, which the startup
        // validator constructs at host start. (Throttling and resilience bind snapshots and
        // restart to change; metering's window is reload-checked because this leg promises it.)
        services.TryAddSingleton(sp => new CredProxMeteringReloadGuard(
            configuration,
            sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<CredProxMeteringReloadGuard>>()));
        var options = new CredProxMeteringOptions();
        configuration.GetSection("CredProx:Metering").Bind(options);
        var validation = new CredProxMeteringOptionsValidator().Validate(null, options);
        if (validation.Failed)
        {
            throw new Microsoft.Extensions.Options.OptionsValidationException(
                nameof(CredProxMeteringOptions), typeof(CredProxMeteringOptions), validation.Failures);
        }

        services.TryAddSingleton(options);
        // Built-in provider readers first; a host's own transient IUsageReader registrations
        // are considered alongside them. One fresh reader per response. Selection matches
        // Format against the route's named format, so registration order no longer decides
        // which vendor parses a response.
        services.TryAddEnumerable(ServiceDescriptor.Transient<IUsageReader, AnthropicJsonUsageReader>());
        services.TryAddEnumerable(ServiceDescriptor.Transient<IUsageReader, AnthropicSseUsageReader>());
        services.TryAddEnumerable(ServiceDescriptor.Transient<IUsageReader, OpenAiJsonUsageReader>());
        services.TryAddEnumerable(ServiceDescriptor.Transient<IUsageReader, OpenAiSseUsageReader>());
        // Fail-closed usage-format check (M54, ADR-0009): YARP runs every registered
        // IConfigValidator at startup and on every reload, so a route naming a format no
        // reader declares is refused at both moments, naming the route id and the value.
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IConfigValidator, CredProxUsageFormatConfigValidator>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IRequestFeature, CredProxMeteringRequestFeature>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IResponseFeature, CredProxMeteringResponseFeature>());
        return services;
    }
}
