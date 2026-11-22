using System.Diagnostics.CodeAnalysis;
using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Http;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registers CredProx on a YARP reverse proxy builder.
/// </summary>
[Experimental("CREDPROX001")]
public static class CredProxReverseProxyBuilderExtensions
{
    // The fixed CredProx configuration topology (plan §3): each subsection has its own
    // binder, which validates the keys inside it (M14a/M16/M17); the root check trusts
    // these names and rejects everything else. "CallerToken" and "CallerAuth" stay
    // listed even though the core (caller keys) and CredProx.Identity (caller tokens)
    // read (and validate) those sections — the names must bind for a config written
    // against 0.11.0 to start unchanged.
    private static readonly IReadOnlySet<string> CoreSections = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "Audit", "CallerAuth", "CallerToken", "Callers", "Connections", "Credentials",
        "Destinations", "Errors", "Health", "KillSwitch", "Presets", "Resilience", "Scrubbing", "Secrets", "Throttling",
    };

    /// <summary>
    /// Adds the full CredProx reverse-proxy leg with no configuration argument (ADR-0007
    /// item 5): the one configuration pass is the services entry, and this leg reads it
    /// back from DI. It refuses when <c>services.AddCredProx(configuration)</c> has not
    /// run first — a host that skipped the entry has passed no configuration at all.
    /// </summary>
    /// <param name="builder">The YARP reverse proxy builder.</param>
    /// <returns>The same <paramref name="builder"/>, for chaining.</returns>
    /// <exception cref="InvalidOperationException">
    /// The services entry has not run, or its configuration is no longer resolvable.
    /// </exception>
    public static IReverseProxyBuilder AddCredProx(this IReverseProxyBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        // The entry's marker is the proof the host passed its configuration, and the
        // marker instance carries that exact pass (AddCredProx stores it). Reading the
        // collection's IConfiguration instead would miss every web host: the host
        // builder registers IConfiguration by factory, so the entry's TryAdd keeps
        // that registration and no instance descriptor exists.
        var entryRan = false;
        IConfiguration? configuration = null;
        foreach (var descriptor in builder.Services)
        {
            if (descriptor.ServiceType == typeof(CoreDefaultsRegistered)
                && descriptor.ImplementationInstance is CoreDefaultsRegistered marker)
            {
                entryRan = true;
                configuration = marker.Configuration;
            }
            else if (descriptor.ServiceType == typeof(CoreDefaultsRegistered))
            {
                entryRan = true;
            }
        }

        if (!entryRan)
        {
            throw new InvalidOperationException(
                "The reverse-proxy CredProx leg requires the services entry first (ADR-0007): " +
                "call services.AddCredProx(builder.Configuration) before AddCredProx() " +
                "on the reverse-proxy builder.");
        }

        if (configuration is null)
        {
            throw new InvalidOperationException(
                "The reverse-proxy CredProx leg reads the configuration that " +
                "services.AddCredProx(configuration) stored, but the service collection " +
                "no longer resolves it.");
        }

        return builder.AddCredProx(configuration);
    }

    /// <summary>
    /// Adds the full CredProx request path on a YARP reverse proxy builder, taking the
    /// configuration explicitly. From 0.15 hosts use the no-argument leg, which reads the
    /// one configuration pass stored by the services entry (ADR-0007 item 5); this
    /// overload stays for wiring that cannot go through the entry. The registrations are
    /// identical:
    /// <list type="bullet">
    /// <item>binds <c>CredProx:Destinations</c> and <c>CredProx:Connections</c> into their
    /// registries (startup-validated by <see cref="CredProxStartupValidator"/>);</item>
    /// <item>registers the built-in request features — destination resolution, header
    /// hygiene, credential attach — and the single <see cref="Yarp.ReverseProxy.Transforms.Builder.ITransformProvider"/>
    /// that runs the stage-ordered pipeline;</item>
    /// <item>replaces the forwarder client factory with
    /// <see cref="CredProxForwarderHttpClientFactory"/>, which applies per-connection client
    /// certificates and composes the outbound pipeline (refresh-on-401 innermost);</item>
    /// <item>serves the per-connection token client (<c>credprox-token:&lt;name&gt;</c>)
    /// carrying the connection's client certificate, used by a credential's
    /// <c>Connection</c> option — built from the live connection registry, so a connection
    /// added by a configuration reload works without a restart;</item>
    /// <item>registers <see cref="CredProxConfigValidator"/>, so every YARP configuration
    /// load — startup or reload — is checked against the live registries and a bad reload
    /// is refused rather than served.</item>
    /// </list>
    /// Call after <c>AddReverseProxy()</c>: the default forwarder client factory is
    /// replaced, and the startup validator checks every route/cluster
    /// <c>CredProx.*</c> metadata reference before the proxy serves traffic.
    /// </summary>
    /// <param name="builder">The YARP reverse proxy builder.</param>
    /// <param name="configuration">The application configuration root.</param>
    /// <returns>The same <paramref name="builder"/>, for chaining.</returns>
    internal static IReverseProxyBuilder AddCredProx(
        this IReverseProxyBuilder builder,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configuration);

        // The stage-ordered pipeline, independent of any configuration. (This leg must
        // not call the no-configuration overload: that one reads the entry's marker and
        // hands the configuration back here.)
        builder.Services.TryAddSingleton<CredProxPipeline>();

        var services = builder.Services;

        // Logging for the features, factory and startup validator; a no-op when the host
        // has already configured logging.
        services.AddLogging();

        // M17 (§3.3): a misspelled key at this level — an options property or a whole section
        // name ("Throteling", "Credentails") — silently disables the feature it was meant to
        // configure. Everything outside the fixed CredProx topology is rejected; each listed
        // subsection validates its own contents (M14a, M16, this milestone). CredProx's own
        // add-ons (AzureKeyVault, Testing) add no sections — they use Credentials and Secrets.
        ConfigKeyValidator.RejectUnknownKeysAtStartup(
            configuration, "CredProx", typeof(CredProxCoreOptions), CoreSections);

        // Core options (inbound caller-key header name) bound from the CredProx section.
        var coreOptions = new CredProxCoreOptions();
        configuration.GetSection("CredProx").Bind(coreOptions);
        services.TryAddSingleton(coreOptions);

        // M20 (§8.2): response secret scrubbing — on by default (the caller never sees
        // the credential, reflected responses included); CredProx:Scrubbing:Enabled=false
        // opts out. Unknown keys inside the section would bind to nothing — rejected (M17).
        ConfigKeyValidator.RejectUnknownKeysAtStartup(
            configuration, "CredProx:Scrubbing", typeof(CredProxScrubbingOptions));
        var scrubbingOptions = new CredProxScrubbingOptions();
        configuration.GetSection("CredProx:Scrubbing").Bind(scrubbingOptions);
        // M47 F-3 (Low-5): FailClosed without Enabled is a contradiction — with
        // scrubbing off nothing is ever inspected, so the fail-closed knob can refuse
        // nothing. It used to bind silently and forward every echo; refused at startup
        // like the Errors cap below (FailClosed is new in 0.14, no existing host hits
        // this).
        if (scrubbingOptions.FailClosed && !scrubbingOptions.Enabled)
        {
            throw new Microsoft.Extensions.Options.OptionsValidationException(
                "CredProx", typeof(object),
                ["CredProx:Scrubbing:FailClosed=true requires CredProx:Scrubbing:Enabled=true — with scrubbing disabled nothing is inspected, so fail-closed can refuse nothing. Set CredProx:Scrubbing:Enabled=true, or remove the FailClosed setting."]);
        }

        services.TryAddSingleton(scrubbingOptions);

        // M24 (§8.5): vendor error normalisation — on by default, the caller's error
        // payload preserved in the vendor_detail member; CredProx:Errors:Enabled=false
        // opts out globally, route metadata CredProx.ErrorNormalisation="off" per route.
        // Unknown keys inside the section would bind to nothing — rejected (M17). A
        // non-positive cap would mean "normalise nothing" by a confusing route; refused
        // at startup instead.
        ConfigKeyValidator.RejectUnknownKeysAtStartup(
            configuration, "CredProx:Errors", typeof(CredProxErrorsOptions));
        var errorsOptions = new CredProxErrorsOptions();
        configuration.GetSection("CredProx:Errors").Bind(errorsOptions);
        if (errorsOptions.MaxNormalisedBodyBytes <= 0)
        {
            throw new Microsoft.Extensions.Options.OptionsValidationException(
                "CredProx", typeof(object), ["CredProx:Errors:MaxNormalisedBodyBytes must be greater than 0."]);
        }

        services.TryAddSingleton(errorsOptions);

        // The audit recorder (M7, §4 "Audit log"): always resolvable so the transform
        // provider can observe every processed request; a no-op until a sink is
        // registered (AddCredProxAudit adds the built-in ILogger sink).
        services.TryAddSingleton(sp => new CredProxAuditRecorder(
            sp.GetServices<IAuditSink>(),
            sp.GetService<CredProxAuditOptions>() ?? new CredProxAuditOptions(),
            sp.GetService<TimeProvider>() ?? TimeProvider.System,
            sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<CredProxAuditRecorder>>(),
            coreOptions,
            configuration));

        // Partition sources (§3.2): the built-in header scheme; plugins add factories.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IPartitionSourceFactory, HeaderPartitionSourceFactory>());

        // Destination and connection registries: bound eagerly at startup by the provider,
        // then rebound on configuration changes (the config-reload story, M5). Resolving
        // the registry itself yields the live view.
        services.TryAddSingleton(sp => new DestinationBinder(
            configuration, sp.GetServices<IPartitionSourceFactory>()));
        services.TryAddSingleton(sp => new DestinationRegistryProvider(
            sp.GetRequiredService<DestinationBinder>(),
            sp.GetRequiredService<ISecretSource>(),
            sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<DestinationRegistryProvider>>()));
        services.AddTransient(sp => sp.GetRequiredService<DestinationRegistryProvider>().Current);

        services.TryAddSingleton(sp => new ConnectionBinder(
            configuration,
            sp.GetRequiredService<SecretAccessorFactory>(),
            sp.GetRequiredService<Microsoft.Extensions.Logging.ILoggerFactory>()));
        services.TryAddSingleton(sp => new ConnectionRegistryProvider(
            sp.GetRequiredService<ConnectionBinder>(),
            sp.GetRequiredService<ISecretSource>(),
            sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<ConnectionRegistryProvider>>()));
        services.AddTransient(sp => sp.GetRequiredService<ConnectionRegistryProvider>().Current);

        // The kill switch (M18, §8.4): clusters and callers taken out of service by config,
        // live across reloads; a failed rebind keeps the previous switch state guarding.
        // The startup validator resolves the registry eagerly, so a bad KillSwitch section
        // fails startup like every other section.
        services.TryAddSingleton(sp => new KillSwitchBinder(configuration));
        services.TryAddSingleton(sp => new KillSwitchRegistryProvider(
            sp.GetRequiredService<KillSwitchBinder>(),
            sp.GetRequiredService<ISecretSource>(),
            sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<KillSwitchRegistryProvider>>()));
        services.AddTransient(sp => sp.GetRequiredService<KillSwitchRegistryProvider>().Current);

        // Built-in request features; the pipeline orders them by declared stage.
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IRequestFeature, KillSwitchFeature>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IRequestFeature, DestinationResolutionFeature>(
            sp => new DestinationResolutionFeature(sp.GetRequiredService<DestinationRegistryProvider>())));
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IRequestFeature, HeaderHygieneFeature>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IRequestFeature, CredentialAttachFeature>());

        // The built-in response features: secret scrubbing (M20, §8.2), then vendor
        // error normalisation (M24, §8.5). The pipeline orders response features by
        // declared stage and pins the scrubber first inside its stage — so within
        // Stage.ShapeResponse the normaliser runs after the scrubber and can only ever
        // embed already-scrubbed bytes in vendor_detail, whatever order these
        // registrations land in (M45 security finding F-7).
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IResponseFeature, ResponseScrubFeature>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IResponseFeature, ErrorNormalisationFeature>());

        // The single transform adapter that runs the pipeline per request.
        services.TryAddEnumerable(ServiceDescriptor.Singleton<Yarp.ReverseProxy.Transforms.Builder.ITransformProvider, CredProxTransformProvider>(
            sp => new CredProxTransformProvider(
                sp.GetRequiredService<CredProxPipeline>(),
                sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<CredProxTransformProvider>>(),
                sp.GetRequiredService<CredProxAuditRecorder>())));

        // The CredProx forwarder client factory replaces YARP's default (registered by
        // AddReverseProxy before this call, hence Replace).
        services.Replace(ServiceDescriptor.Singleton<IForwarderHttpClientFactory>(
            sp => new CredProxForwarderHttpClientFactory(sp)));

        // Per-connection token clients: a credential's Connection option selects
        // credprox-token:<name>, whose primary handler carries the connection's client
        // certificate. The filter builds it from the live connection registry at
        // handler-creation time (M5 note N2), so a connection added by a configuration
        // reload gets its certificate-carrying client without a restart; IHttpClientFactory
        // recreates primary handlers on their expiry, so a rotated certificate is picked
        // up the same way.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IHttpMessageHandlerBuilderFilter, CredProxTokenClientFilter>());

        // Reload-time validation (M5 note N1): YARP runs registered IConfigValidators on
        // every load and refuses a load that fails, keeping the previous configuration
        // serving. The startup gate below still aggregates everything into one startup
        // failure.
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IConfigValidator, CredProxConfigValidator>(
            sp => new CredProxConfigValidator(
                sp.GetRequiredService<CredentialRegistryProvider>(),
                sp.GetRequiredService<DestinationRegistryProvider>(),
                sp.GetRequiredService<ConnectionRegistryProvider>(),
                sp.GetRequiredService<IConfiguration>())));

        // The startup gate: eager binds, secret-reference validation and metadata
        // cross-checks before the first request is served.
        services.TryAddSingleton(sp => new CredProxStartupValidator(
            sp,
            sp.GetServices<IProxyConfigProvider>(),
            sp.GetRequiredService<IConfiguration>(),
            sp.GetRequiredService<SecretReferenceValidator>(),
            sp.GetServices<IPresetSource>(),
            sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<CredProxStartupValidator>>()));
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, CredProxStartupValidator>(
            sp => sp.GetRequiredService<CredProxStartupValidator>()));

        // ADR-0005 fail-closed pair to the binder's check: callers declared under
        // CredProx:Callers with no caller authenticator registered refuse startup —
        // evaluated at startup, not in an extension, because the authenticator may be
        // registered by any extension in any order.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IHostedService, CallerAuthenticatorStartupGuard>());

        return builder;
    }
}
