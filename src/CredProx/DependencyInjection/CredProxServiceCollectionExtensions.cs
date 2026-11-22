using System.Diagnostics.CodeAnalysis;
using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registers the CredProx core services that are not YARP-bound: the token cache and the
/// secret-source stack. Everything is registered explicitly; nothing is discovered by
/// scanning.
/// </summary>
[Experimental("CREDPROX001")]
public static class CredProxServiceCollectionExtensions
{
    /// <summary>
    /// The one core registration (ADR-0005 item 5, ADR-0007): the core defaults a host
    /// needs before any add-on — the in-memory <see cref="ITokenCache"/>, the
    /// configuration-backed secret stack, the core's credential types (<c>StaticKey</c>,
    /// <c>Hmac</c>, <c>LoginExchange</c>) and the <c>CredProx:Credentials</c> binder — from
    /// one configuration call. Core features work from configuration: a
    /// <c>CredProx:Audit</c> section turns the audit log on, and a caller key hash under
    /// <c>CredProx:Callers</c> registers the caller-key machinery. A host then adds only
    /// its add-on-package calls — <c>.AddIdentity()</c>, <c>.AddAzure(credential)</c>,
    /// <c>.AddOperations()</c> — each one chained on the returned builder and carrying its
    /// own pieces.
    /// Idempotent: a second call is a no-op, and every registration it performs tolerates
    /// an already-registered stack.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The application configuration root.</param>
    /// <returns>
    /// A <see cref="CredProxBuilder"/> carrying the services and this configuration — the
    /// handle each add-on package's chained call extends (ADR-0007 item 5).
    /// </returns>
    public static CredProxBuilder AddCredProx(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        // A host that registered no IConfiguration of its own should resolve the entry's
        // pass. TryAdd keeps a host's own registration — including the web host builder's
        // factory registration; the reverse-proxy leg reads the exact pass from the
        // marker below, not from this registration (ADR-0007 item 5).
        services.TryAddSingleton(configuration);

        // The idempotence guard is this marker, not a per-subsystem probe: exactly one
        // execution of the default stack is what "call it once, call it twice" must mean.
        foreach (var descriptor in services)
        {
            if (descriptor.ServiceType == typeof(CoreDefaultsRegistered))
            {
                return new CredProxBuilder(services, configuration);
            }
        }

        services.AddSingleton(new CoreDefaultsRegistered(configuration));
        services.AddCredProxTokenCache();
        services.AddCredProxConfigurationSecrets(configuration);
        services.AddCredProxBuiltInCredentials();
        services.AddCredProxCredentials(configuration);

        // Features in the core work from configuration (ADR-0007): writing the config is
        // the setup. A configured audit section turns the audit log on — the sink, its
        // key validation and option binding arrive here, and a typo under a configured
        // section refuses startup exactly as the old explicit call did. A caller key hash
        // anywhere under CredProx:Callers registers the whole caller-key machinery; the
        // machinery's marker (CallerKeyMachineryRegistered) keeps an explicit
        // AddCredProxCallerAuthentication call from stacking a second scheme on top.
        if (configuration.GetSection("CredProx:Audit").GetChildren().Any())
        {
            services.AddCredProxAudit(configuration);
        }

        if (configuration.GetSection("CredProx:Callers").GetChildren()
                .Any(caller => caller.GetSection("Keys").GetChildren().Any()))
        {
            services.AddCredProxCallerAuthentication(configuration);
        }

        return new CredProxBuilder(services, configuration);
    }

    /// <summary>
    /// Adds the in-memory <see cref="ITokenCache"/> (single-flight per key, early refresh,
    /// short negative cache).
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Optional configuration of <see cref="TokenCacheOptions"/>.</param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    internal static IServiceCollection AddCredProxTokenCache(
        this IServiceCollection services,
        Action<TokenCacheOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions();
        services.TryAddSingleton(TimeProvider.System);
        if (configure is not null)
        {
            services.Configure(configure);
        }

        services.TryAddSingleton<ITokenCache, InMemoryTokenCache>();
        return services;
    }

    /// <summary>
    /// Adds the configuration-backed <see cref="ISecretSource"/>, the
    /// <see cref="SecretAccessorFactory"/> that scopes it per plugin, and the
    /// <see cref="SecretReferenceValidator"/>.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">
    /// The application configuration root; secret values are read from its
    /// <c>CredProx:Secrets</c> section.
    /// </param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    internal static IServiceCollection AddCredProxConfigurationSecrets(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.TryAddSingleton<ISecretSource>(new ConfigurationSecretSource(configuration));
        services.TryAddSingleton<SecretAccessorFactory>();
        services.TryAddSingleton<SecretReferenceValidator>();
        return services;
    }

    /// <summary>
    /// Explicitly registers one credential type: the configuration <c>Type</c> name mapped to its options and provider.
    /// A credential section naming an unregistered type fails startup — there is no
    /// discovery and no default fallback.
    /// </summary>
    /// <typeparam name="TProvider">The provider implementation.</typeparam>
    /// <typeparam name="TOptions">The options type bound from the credential section.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <param name="typeName">The configuration <c>Type</c> name, for example <c>StaticKey</c>.</param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    internal static IServiceCollection AddCredProxCredentialType<TProvider, TOptions>(
        this IServiceCollection services,
        string typeName)
        where TProvider : class, ICredentialProvider<TOptions>
        where TOptions : class
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrEmpty(typeName);

        // One registration per type name, whoever registers it (M49): the built-in batch
        // now brings the core-resident types, and a host still carrying the old explicit
        // call must not end up with the same type twice — first registration wins.
        foreach (var descriptor in services)
        {
            if (descriptor.ServiceType == typeof(CredentialTypeRegistration)
                && descriptor.ImplementationInstance is CredentialTypeRegistration existing
                && string.Equals(existing.TypeName, typeName, StringComparison.Ordinal))
            {
                services.TryAddSingleton<TProvider>();
                return services;
            }
        }

        services.AddSingleton(new CredentialTypeRegistration(typeName, typeof(TOptions), typeof(TProvider)));
        services.TryAddSingleton<TProvider>();
        return services;
    }

    /// <summary>
    /// Binds every <c>CredProx:Credentials</c> section at startup into the
    /// <see cref="CredentialRegistry"/>: unknown types and failing validators throw
    /// <see cref="Microsoft.Extensions.Options.OptionsValidationException"/> before the
    /// proxy serves traffic.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The application configuration root.</param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    internal static IServiceCollection AddCredProxCredentials(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        // The built-in header partition source so a credential's Partition option binds
        // even in a credentials-only host (no YARP-side AddCredProx call).
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IPartitionSourceFactory, HeaderPartitionSourceFactory>());

        // The preset source (§3 plugin points): presets written under CredProx:Presets.
        // Since 0.4.0 the library ships no built-in vendor presets — vendor setups live in
        // the samples as explicit config. Hosts contribute their own IPresetSource
        // registrations alongside this one.
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IPresetSource, ConfigurationPresetSource>(
            sp => new ConfigurationPresetSource(configuration)));

        services.TryAddSingleton<CredentialBinder>(sp => new CredentialBinder(
            configuration,
            sp.GetRequiredService<SecretAccessorFactory>(),
            sp,
            sp.GetServices<CredentialTypeRegistration>(),
            sp.GetServices<IPartitionSourceFactory>(),
            sp.GetServices<IPresetSource>()));

        // The provider performs the initial bind eagerly and rebinds on secret-source
        // changes; the registry view follows it so later resolutions see the live registry.
        // Logging infrastructure for the registry provider's rebind logging; a no-op when
        // the host has already configured logging.
        services.AddLogging();
        services.TryAddSingleton(sp => new CredentialRegistryProvider(
            sp.GetRequiredService<CredentialBinder>(),
            sp.GetRequiredService<ISecretSource>(),
            sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<CredentialRegistryProvider>>()));
        services.AddTransient(sp => sp.GetRequiredService<CredentialRegistryProvider>().Current);
        return services;
    }

    /// <summary>
    /// Registers the credential types that ship in the core — <c>StaticKey</c>, <c>Hmac</c>
    /// and <c>LoginExchange</c> (ADR-0007: no outside library, so no cost to a host that
    /// does not use them) — with their startup validators and the shared token client the
    /// <c>LoginExchange</c> provider rides. The <c>OAuthClientCredentials</c>,
    /// <c>TokenExchange</c> and <c>JwtAssertion</c> types ride <c>CredProx.Identity</c> and
    /// the <c>TokenCredential</c> type rides <c>CredProx.Azure</c>: a credential naming one
    /// of those without its package setup fails startup naming the package and the call.
    /// Idempotent against the per-type calls hosts still carry from 0.14.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    internal static IServiceCollection AddCredProxBuiltInCredentials(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddCredProxCredentialType<StaticKeyProvider, StaticKeyOptions>("StaticKey");
        services.AddCredProxHmac();
        services.AddCredProxLoginExchange();

        services.TryAddSingleton<Microsoft.Extensions.Options.IValidateOptions<StaticKeyOptions>, StaticKeyOptionsValidator>();
        return services;
    }

    /// <summary>
    /// Registers the <see cref="CredProxAuth.CallerPolicy"/> authorization policy for hosts
    /// that run <c>UseAuthentication</c>/<c>UseAuthorization</c> in front of the proxy; the
    /// built-in pipeline enforcement does not depend on it. The policy names both caller
    /// schemes (ADR-0004): a caller key (the CredProx.CallerKeys add-on) or a caller
    /// token (the CredProx.CallerTokens add-on) authenticates it. Authenticating an
    /// unregistered scheme is no-result, never a throw, so naming a scheme whose add-on
    /// never registered is safe. <c>AddCredProxCallerAuthentication</c> from
    /// CredProx.CallerKeys registers the policy itself; hosts that authenticate through a
    /// third-party <see cref="ICallerAuthenticator"/> and prefer middleware enforcement
    /// call this directly. Ordering: host-first, like ADR-0006 — a policy the host already
    /// registered under this name is kept, and a host definition added later replaces the
    /// CredProx one, so the host definition wins in either registration order.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    internal static IServiceCollection AddCredProxCallerPolicy(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAuthorization(options =>
        {
            // Host-first (ADR-0006 in spirit): a policy the host already registered under
            // this name is kept; a host callback registered later runs later and replaces
            // this one. Either way the host definition wins.
            if (options.GetPolicy(CredProxAuth.CallerPolicy) is null)
            {
                options.AddPolicy(
                    CredProxAuth.CallerPolicy,
                    policy => policy
                        .AddAuthenticationSchemes(CredProxAuth.CallerKeyScheme, CredProxAuth.CallerTokenScheme)
                        .RequireAuthenticatedUser()
                        .RequireClaim(CallerIdentity.CallerClaimType));
            }
        });
        return services;
    }


    /// <summary>
    /// Turns on the audit log: binds
    /// <c>CredProx:Audit</c> (enabled flag, sink timeout, header capture and redaction
    /// lists) and registers the built-in <see cref="LoggerAuditSink"/>. From 0.15 a
    /// configured <c>CredProx:Audit</c> section makes <c>AddCredProx(configuration)</c>
    /// call this itself — hosts that still call it explicitly are idempotent. One record per
    /// CredProx-processed request — forwarded or short-circuited — with caller, key id,
    /// route, vendor, method, path template, status, latency, response bytes, credential
    /// name and trace id; never a secret value. Additional sinks (OTel exporters, files,
    /// queues) are plain <see cref="IAuditSink"/> registrations; redaction happens in the
    /// core before any sink runs, and a sink failure or hang is bounded and never fails
    /// the request.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The application configuration root.</param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    internal static IServiceCollection AddCredProxAudit(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddLogging();

        // M17 (§3.3): keys the options type does not declare are silently dropped by Bind —
        // rejected here, like the value validators below that already fail startup eagerly.
        ConfigKeyValidator.RejectUnknownKeysAtStartup(configuration, "CredProx:Audit", typeof(CredProxAuditOptions));

        var options = new CredProxAuditOptions();
        configuration.GetSection("CredProx:Audit").Bind(options);
        services.TryAddSingleton(options);

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IAuditSink, LoggerAuditSink>());
        return services;
    }

    /// <summary>
    /// Registers a caller authenticator (ADR-0005): the one public path every
    /// <see cref="ICallerAuthenticator"/> takes, built-in or third-party — there is no
    /// internal shortcut. The caller stage consults registered authenticators in
    /// registration order; the first authenticated-or-refused outcome wins. Registering the
    /// same implementation twice is a no-op the second time.
    /// </summary>
    /// <remarks>
    /// An authenticator never stands alone: it also registers the core's caller policy —
    /// the caller registry, the operation allow-list and the scope intersection (ADR-0004).
    /// Admitted identities must be configured callers under <c>CredProx:Callers</c>: one
    /// the registry does not know answers 401, and every admitted caller is narrowed to
    /// its named rules. With callers configured and no authenticator registered at all —
    /// or authenticators registered and no caller configured — the host refuses to start
    /// (fail closed); a configuration that declares neither needs neither.
    /// </remarks>
    /// <typeparam name="TAuthenticator">The authenticator implementation.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The application configuration; it declares the callers
    /// the registered authenticators can admit.</param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    internal static IServiceCollection AddCredProxCallerAuthenticator<TAuthenticator>(
        this IServiceCollection services, IConfiguration configuration)
        where TAuthenticator : class, ICallerAuthenticator
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        // The core's caller policy rides with any authenticator (ADR-0004): an
        // authenticator that admits identities without the registry, allow-list and scope
        // intersection would admit them everywhere. All idempotent, so a host that also
        // runs the CredProx.CallerKeys entry point gets one caller policy, not two.
        services.AddLogging();
        services.AddOptions();
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<SecretAccessorFactory>();
        services.TryAddSingleton<CallerBinder>(sp => new CallerBinder(
            configuration,
            sp.GetRequiredService<SecretAccessorFactory>(),
            sp.GetServices<ICallerRegistryValidator>()));
        services.TryAddSingleton(sp => new CallerRegistryProvider(
            sp.GetRequiredService<CallerBinder>(),
            sp.GetServices<ICallerRegistryContributor>(),
            configuration,
            sp.GetRequiredService<ISecretSource>(),
            sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<CallerRegistryProvider>>()));
        services.AddTransient(sp => sp.GetRequiredService<CallerRegistryProvider>().Current);
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IRequestFeature, OperationAllowListFeature>());

        // The caller: partition scheme and M15 per-caller budgets (§3.7) ride the one
        // public authenticator path — inert unless the host configures either. The budget
        // registry is a singleton so windows survive route/cluster churn; a rebind that
        // changes a caller's limits replaces that caller's window (CallerBudgetRegistry).
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IPartitionSourceFactory, CallerPartitionSourceFactory>());
        services.TryAddSingleton<CallerBudgetRegistry>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IRequestFeature, CallerBudgetFeature>());

        services.TryAddEnumerable(ServiceDescriptor.Singleton<ICallerAuthenticator, TAuthenticator>());

        // The caller stage exists exactly when at least one authenticator does: this is the
        // one path that brings it, so a registered authenticator is never consulted by
        // nothing (ADR-0005).
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IRequestFeature, CallerAuthenticationFeature>());
        return services;
    }

    /// <summary>
    /// Registers a <see cref="ICallerRegistryValidator"/> the core runs over the caller
    /// registry at host start AND on every live configuration rebind — the shared place
    /// where feature packages contribute rules about keys the core itself does not read
    /// (the token client ids, ADR-0004; the caller-key package does the same). A refused
    /// startup stops the host from starting; a refused live rebind keeps the previous
    /// registry serving and logs the reason. A host may also register the validator as a
    /// plain singleton; this extension is the discoverable path.
    /// </summary>
    /// <typeparam name="TValidator">The validator type; registered as a singleton.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <returns>The same service collection.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is null.</exception>
    internal static IServiceCollection AddCredProxCallerRegistryValidator<TValidator>(this IServiceCollection services)
        where TValidator : class, ICallerRegistryValidator
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddSingleton<ICallerRegistryValidator, TValidator>();
        return services;
    }

    /// <summary>
    /// Registers an <see cref="ICallerRegistryContributor"/> the core runs inside every
    /// bind of the caller registry — the write-side twin of
    /// <see cref="AddCredProxCallerRegistryValidator{TValidator}"/>: where a validator
    /// refuses a registry, a contributor builds the feature's derived data against the
    /// accepted one (the caller-key table) and commits it with the registry as one
    /// <see cref="CallerRegistryGeneration"/>. A contributor that fails refuses host
    /// startup; on a live rebind it keeps the previous generation serving and logs the
    /// reason. A host may also register the contributor as a plain singleton; this
    /// extension is the discoverable path.
    /// </summary>
    /// <typeparam name="TContributor">The contributor type; registered as a singleton.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <returns>The same service collection.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is null.</exception>
    internal static IServiceCollection AddCredProxCallerRegistryContributor<TContributor>(this IServiceCollection services)
        where TContributor : class, ICallerRegistryContributor
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddSingleton<ICallerRegistryContributor, TContributor>();
        return services;
    }
}

/// <summary>
/// Registration marker for <see cref="CredProxServiceCollectionExtensions.AddCredProx"/>:
/// its presence means the core defaults are registered, so a repeated call is a no-op.
/// It carries the configuration pass the host handed the entry — the reverse-proxy leg
/// reads it back from here, because a web host's own IConfiguration registration (by
/// factory) gives the leg nothing to read at registration time.
/// Internal: no public surface, and hosts never resolve it.
/// </summary>
internal sealed record CoreDefaultsRegistered(IConfiguration Configuration);

/// <summary>Marker: the caller-key machinery registered itself — either through this
/// assembly's entry scan (ADR-0007) or an explicit <c>AddCredProxCallerAuthentication</c>
/// call; whichever runs first wins, the second is a no-op.</summary>
internal sealed class CallerKeyMachineryRegistered;

/// <summary>Marker: the shared <c>credprox-token</c> named client is configured; a second
/// pass must not stack a second primary-handler chain onto the same client.</summary>
internal sealed class TokenClientConfigured;
