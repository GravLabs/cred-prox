using System.Diagnostics.CodeAnalysis;
using CredProx;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registers the CredProx core services that are not YARP-bound: the token cache and the
/// secret-source stack. Everything is registered explicitly; nothing is discovered by
/// scanning (see <c>docs/credprox-plan.md</c> §3.5 rule 6).
/// </summary>
[Experimental("CREDPROX001")]
public static class CredProxServiceCollectionExtensions
{
    /// <summary>
    /// Adds the in-memory <see cref="ITokenCache"/> (single-flight per key, early refresh,
    /// short negative cache; see <c>docs/credprox-plan.md</c> §3.3).
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Optional configuration of <see cref="TokenCacheOptions"/>.</param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    public static IServiceCollection AddCredProxTokenCache(
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
    /// <see cref="SecretReferenceValidator"/> (see <c>docs/credprox-plan.md</c> §3.3).
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">
    /// The application configuration root; secret values are read from its
    /// <c>CredProx:Secrets</c> section.
    /// </param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    public static IServiceCollection AddCredProxConfigurationSecrets(
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
    /// Explicitly registers one credential type (see <c>docs/credprox-plan.md</c> §3.5
    /// rule 6): the configuration <c>Type</c> name mapped to its options and provider.
    /// A credential section naming an unregistered type fails startup — there is no
    /// discovery and no default fallback.
    /// </summary>
    /// <typeparam name="TProvider">The provider implementation.</typeparam>
    /// <typeparam name="TOptions">The options type bound from the credential section.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <param name="typeName">The configuration <c>Type</c> name, for example <c>StaticKey</c>.</param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    public static IServiceCollection AddCredProxCredentialType<TProvider, TOptions>(
        this IServiceCollection services,
        string typeName)
        where TProvider : class, ICredentialProvider<TOptions>
        where TOptions : class
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrEmpty(typeName);

        services.AddSingleton(new CredentialTypeRegistration(typeName, typeof(TOptions), typeof(TProvider)));
        services.TryAddSingleton<TProvider>();
        return services;
    }

    /// <summary>
    /// Binds every <c>CredProx:Credentials</c> section at startup into the
    /// <see cref="CredentialRegistry"/>: unknown types and failing validators throw
    /// <see cref="Microsoft.Extensions.Options.OptionsValidationException"/> before the
    /// proxy serves traffic (see <c>docs/credprox-plan.md</c> §3.3).
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The application configuration root.</param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    public static IServiceCollection AddCredProxCredentials(
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
    /// Registers the five built-in credential types — <c>OAuthClientCredentials</c>,
    /// <c>LoginExchange</c>, <c>StaticKey</c>, <c>JwtAssertion</c> and <c>Hmac</c> — with
    /// their startup validators and the named HttpClient used for token and login endpoints.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    public static IServiceCollection AddCredProxBuiltInCredentials(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddHttpClient(OAuthClientCredentialsProvider.HttpClientName);

        services
            .AddCredProxCredentialType<OAuthClientCredentialsProvider, OAuthClientCredentialsOptions>("OAuthClientCredentials")
            .AddCredProxCredentialType<LoginExchangeProvider, LoginExchangeOptions>("LoginExchange")
            .AddCredProxCredentialType<StaticKeyProvider, StaticKeyOptions>("StaticKey")
            .AddCredProxCredentialType<JwtAssertionProvider, JwtAssertionOptions>("JwtAssertion")
            .AddCredProxCredentialType<HmacProvider, HmacOptions>("Hmac")
            .AddCredProxCredentialType<TokenExchangeProvider, TokenExchangeOptions>("TokenExchange");

        services.TryAddSingleton<Microsoft.Extensions.Options.IValidateOptions<OAuthClientCredentialsOptions>, OAuthClientCredentialsOptionsValidator>();
        services.TryAddSingleton<Microsoft.Extensions.Options.IValidateOptions<LoginExchangeOptions>, LoginExchangeOptionsValidator>();
        services.TryAddSingleton<Microsoft.Extensions.Options.IValidateOptions<StaticKeyOptions>, StaticKeyOptionsValidator>();
        services.TryAddSingleton<Microsoft.Extensions.Options.IValidateOptions<JwtAssertionOptions>, JwtAssertionOptionsValidator>();
        services.TryAddSingleton<Microsoft.Extensions.Options.IValidateOptions<HmacOptions>, HmacOptionsValidator>();
        services.TryAddSingleton<Microsoft.Extensions.Options.IValidateOptions<TokenExchangeOptions>, TokenExchangeOptionsValidator>();
        return services;
    }

    /// <summary>
    /// Adds caller API-key authentication and the per-caller request path (§4 Phase B,
    /// §5.2 "Caller API keys", "Per-caller credentials", "Operation allow-lists"):
    /// <list type="bullet">
    /// <item>the <see cref="CallerKeyAuthenticationHandler"/> scheme
    /// (<see cref="CredProxAuth.CallerKeyScheme"/>) reading the header named by
    /// <c>CredProx:CallerAuth:HeaderName</c> (default <c>X-CredProx-Key</c>) and resolving
    /// values through <see cref="ICallerStore"/> — replace the store registration to put
    /// keys somewhere other than configuration;</item>
    /// <item>the <c>CredProx:Callers</c> registry, bound eagerly at startup and rebound on
    /// configuration changes, so key rotation and revocation need no restart;</item>
    /// <item>the built-in <see cref="CallerPartitionSourceFactory"/> (<c>caller:</c>) and
    /// the pipeline features that authenticate the caller
    /// (<see cref="CallerAuthenticationFeature"/>) and enforce per-caller operation
    /// allow-lists (<see cref="OperationAllowListFeature"/>);</item>
    /// <item>the <see cref="CredProxAuth.CallerPolicy"/> authorization policy for hosts
    /// that prefer middleware enforcement to the built-in pipeline enforcement.</item>
    /// </list>
    /// Once registered, every proxied route requires an authenticated caller unless its
    /// metadata says <c>"CredProx.Caller": "anonymous"</c>. Call after
    /// <c>AddCredProx(configuration)</c> and after a secret source is registered. The
    /// header name is read once at startup; changing it takes a restart.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The application configuration root.</param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    public static IServiceCollection AddCredProxCallerAuthentication(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddLogging();
        services.AddOptions();
        services.TryAddSingleton(TimeProvider.System);

        // Scheme options and the plain singleton the header-hygiene feature strips by are
        // bound from the same section at startup, so they can never disagree.
        var callerKeyOptions = new CallerKeyOptions();
        var callerAuthSection = configuration.GetSection("CredProx:CallerAuth");
        callerAuthSection.Bind(callerKeyOptions);

        // Fail closed on a typo (M14a): an unknown key here (e.g. "Header" for "HeaderName")
        // would leave the default header configured while the host believes it set another —
        // header hygiene would then strip the wrong header and the caller key could leak.
        foreach (var child in callerAuthSection.GetChildren())
        {
            if (!string.Equals(child.Key, nameof(CallerKeyOptions.HeaderName), StringComparison.OrdinalIgnoreCase))
            {
                throw new OptionsValidationException(
                    "CredProx:CallerAuth",
                    typeof(CallerKeyOptions),
                    [$"The CallerAuth section declares the unknown configuration key '{child.Key}'. "
                        + $"Known keys: {nameof(CallerKeyOptions.HeaderName)}."]);
            }

            // HeaderName must be a scalar: a nested CallerAuth:HeaderName:Foo binds it to
            // null and silently keeps the default header - the same leak shape as a typo.
            if (child.GetChildren().Any())
            {
                throw new OptionsValidationException(
                    "CredProx:CallerAuth",
                    typeof(CallerKeyOptions),
                    [$"The CallerAuth key '{nameof(CallerKeyOptions.HeaderName)}' must be a scalar value, "
                        + "not a section."]);
            }
        }

        services.TryAddSingleton(callerKeyOptions);

        services
            .AddAuthentication()
            .AddScheme<CallerKeyOptions, CallerKeyAuthenticationHandler>(
                CredProxAuth.CallerKeyScheme,
                options => options.HeaderName = callerKeyOptions.HeaderName);

        // The policy for hosts that run UseAuthentication/UseAuthorization in front of the
        // proxy; the built-in pipeline enforcement does not depend on it. It names both
        // caller schemes (M39/ADR-0004): a caller key or a caller token authenticates it.
        // Authenticating an unregistered scheme is no-result, never a throw, so naming the
        // token scheme here is safe when AddCredProxCallerTokenAuthentication never ran.
        services.AddAuthorization(options => options.AddPolicy(
            CredProxAuth.CallerPolicy,
            policy => policy
                .AddAuthenticationSchemes(CredProxAuth.CallerKeyScheme, CredProxAuth.CallerTokenScheme)
                .RequireAuthenticatedUser()
                .RequireClaim(CallerIdentity.CallerClaimType)));

        // Caller registry: bound eagerly at startup by the provider, then rebound on
        // configuration changes (key rotation and revocation without a restart). The
        // registry view follows the provider so later resolutions see the live registry.
        services.TryAddSingleton<SecretAccessorFactory>();
        services.TryAddSingleton<CallerBinder>(sp => new CallerBinder(
            configuration, sp.GetRequiredService<SecretAccessorFactory>()));
        services.TryAddSingleton(sp => new CallerRegistryProvider(
            sp.GetRequiredService<CallerBinder>(),
            sp.GetRequiredService<ISecretSource>(),
            sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<CallerRegistryProvider>>()));
        services.AddTransient(sp => sp.GetRequiredService<CallerRegistryProvider>().Current);

        // The built-in store reads hashed keys from the registry; a host can replace this
        // registration with a store backed by anything else.
        services.TryAddSingleton<ICallerStore>(sp => new ConfigCallerStore(
            sp.GetRequiredService<CallerRegistryProvider>(),
            sp.GetRequiredService<TimeProvider>()));

        // The caller: partition scheme and the two pipeline features. The features are
        // inert unless this extension ran, so AddCredProx stays caller-auth-optional.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IPartitionSourceFactory, CallerPartitionSourceFactory>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IRequestFeature, CallerAuthenticationFeature>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IRequestFeature, OperationAllowListFeature>());

        // M15 per-caller budgets (§3.7): inert for callers without a Limits block. The
        // registry is a singleton so windows survive route/cluster churn; a rebind that
        // changes a caller's limits replaces that caller's window (CallerBudgetRegistry).
        services.TryAddSingleton<CallerBudgetRegistry>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IRequestFeature, CallerBudgetFeature>());

        return services;
    }

    /// <summary>
    /// Registers the caller-token validation layer (ADR-0004): the stock ASP.NET Core JWT
    /// bearer handler under <see cref="CredProxAuth.CallerTokenScheme"/>, configured from
    /// <c>CredProx:CallerToken</c> (<c>Authority</c> and <c>Audience</c> required — like
    /// <c>CredProx:CallerAuth</c>, unknown keys and a missing issuer or audience fail
    /// registration). CredProx mints nothing: Entra — or any OIDC issuer — signs, and the
    /// framework validates signature, issuer, audience and expiry. The caller policy
    /// (<see cref="CredProxAuth.CallerPolicy"/>) accepts this scheme alongside the caller
    /// API-key scheme; mapping a validated principal to a caller is the
    /// <c>ICallerTokenMapper</c> layer. Swapping this scheme for another handler (multi-tenant
    /// Entra, introspection) changes nothing above it: pass <paramref name="registerScheme"/>
    /// and the host's handler replaces the stock one.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The application configuration root.</param>
    /// <param name="registerScheme">
    /// Optional swap point for the validation handler (ADR-0004). When supplied, this
    /// extension calls it <b>instead of</b> adding the stock JWT bearer handler; the host
    /// registers its own handler under <see cref="CredProxAuth.CallerTokenScheme"/>
    /// (<c>Microsoft.Identity.Web</c>, another OIDC issuer, an introspection handler).
    /// <c>Authority</c> and <c>Audience</c> are then the host's business: they are not
    /// required and no JWT bearer configuration is bound. Everything else is unchanged in
    /// both paths — the <see cref="CallerTokenOptions"/> registration, the mapper, the
    /// startup guard, and the <c>MaxTokenAge</c> bound the caller-authentication stage
    /// enforces from those options. The replacement handler must deliver the raw claim
    /// names CredProx reads — <c>roles</c>/<c>scp</c>, <c>azp</c>/<c>appid</c>, and
    /// <c>iat</c> — for example by setting <c>MapInboundClaims = false</c> on a JWT bearer
    /// handler; otherwise configure <c>ScopeClaimNames</c> and <c>ClientClaimNames</c> to
    /// the names it emits. A renamed <c>roles</c> claim fails closed: the token's roles
    /// match no named rule, so every caller token gets a 403. A host that only wants to
    /// adjust the stock handler passes nothing and uses standard
    /// <c>services.PostConfigure&lt;JwtBearerOptions&gt;(CredProxAuth.CallerTokenScheme, …)</c>.
    /// </param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    public static IServiceCollection AddCredProxCallerTokenAuthentication(
        this IServiceCollection services,
        IConfiguration configuration,
        Action<AuthenticationBuilder>? registerScheme = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions();

        var callerTokenOptions = new CallerTokenOptions();
        var callerTokenSection = configuration.GetSection("CredProx:CallerToken");
        callerTokenSection.Bind(callerTokenOptions);

        // Fail closed (the M14a CallerAuth rule): a typo here would silently validate
        // against the wrong issuer or audience — every token in the tenant would pass.
        // Array keys legitimately nest, so only unknown parents are rejected; a nested
        // scalar (Authority:Foo) binds null and is caught by the required-value checks.
        var knownKeys = new[]
        {
            nameof(CallerTokenOptions.Authority),
            nameof(CallerTokenOptions.Audience),
            nameof(CallerTokenOptions.MaxTokenAge),
            nameof(CallerTokenOptions.ClientClaimNames),
            nameof(CallerTokenOptions.ScopeClaimNames),
        };
        foreach (var child in callerTokenSection.GetChildren())
        {
            if (!knownKeys.Contains(child.Key, StringComparer.OrdinalIgnoreCase))
            {
                throw new OptionsValidationException(
                    "CredProx:CallerToken",
                    typeof(CallerTokenOptions),
                    [$"The CallerToken section declares the unknown configuration key '{child.Key}'. "
                        + $"Known keys: {string.Join(", ", knownKeys)}."]);
            }
        }

        // Missing Authority or Audience is not a defaultable choice: without an authority
        // nothing pins who signs, and without an audience a token minted for any other
        // API passes. Refuse registration naming what is missing. These are checks on the
        // DEFAULT handler only: with registerScheme the host validates, so pinning who
        // signs and for which API is the host's own decision (M39, ADR-0004 swap point).
        if (registerScheme is null)
        {
            if (string.IsNullOrWhiteSpace(callerTokenOptions.Authority))
            {
                throw new OptionsValidationException(
                    "CredProx:CallerToken",
                    typeof(CallerTokenOptions),
                    [$"The CallerToken section requires '{nameof(CallerTokenOptions.Authority)}' — "
                        + "the OIDC authority whose published keys validate caller tokens."]);
            }

            if (string.IsNullOrWhiteSpace(callerTokenOptions.Audience))
            {
                throw new OptionsValidationException(
                    "CredProx:CallerToken",
                    typeof(CallerTokenOptions),
                    [$"The CallerToken section requires '{nameof(CallerTokenOptions.Audience)}' — "
                        + "a caller token minted for any other API would otherwise pass."]);
            }
        }

        // A MaxTokenAge the operator cannot have meant is worse than none: the config
        // binder reads a bare "15" as 15 DAYS (~1440x the intended minutes), a zero or
        // negative limit 401s every caller token forever behind a generic detail, and a
        // day-scale limit is not the short-lived bound this knob exists to enforce
        // (M39, ADR-0004). Refused at startup like the unknown-key family above.
        if (callerTokenOptions.MaxTokenAge is { } maxAge
            && (maxAge <= TimeSpan.Zero || maxAge >= TimeSpan.FromDays(1)))
        {
            throw new OptionsValidationException(
                "CredProx:CallerToken",
                typeof(CallerTokenOptions),
                [$"The CallerToken section sets '{nameof(CallerTokenOptions.MaxTokenAge)}' to '{maxAge}', "
                    + "which is not a usable maximum token age — it must be greater than zero and less than 24 h. "
                    + "Write the value as d.HH:mm:ss; a bare number is read as days, so 15 minutes is '00:15:00'."]);
        }

        // AddSingleton, not TryAddSingleton: the config-bound options are what the token
        // path fail-closes on (GetRequiredService), and the last registration wins — a
        // host that registered its own CallerTokenOptions earlier must not silently drop
        // the configured MaxTokenAge bound (M39).
        services.AddSingleton(callerTokenOptions);

        var callerTokenBuilder = services.AddAuthentication();
        if (registerScheme is null)
        {
            // Validation is the framework handler: signature, issuer, audience, expiry
            // and not-before, with OIDC discovery and key rollover from the authority's
            // metadata.
            callerTokenBuilder.AddJwtBearer(
                CredProxAuth.CallerTokenScheme,
                options =>
                {
                    options.Authority = callerTokenOptions.Authority;
                    options.Audience = callerTokenOptions.Audience;

                    // M39: no inbound claim renaming on this scheme. Entra's raw
                    // claim names (roles, scp, azp, appid, uti) reach the mapper and the
                    // host's HttpContext.User unchanged — "claim names are met by
                    // configuration" (ADR-0004) is only true when nothing maps them, and
                    // the stock rename would silently empty CallerTokenMapping.Scopes.
                    options.MapInboundClaims = false;

                    // With mapping off the handler's role claim type must name the raw
                    // claim, or ClaimsPrincipal.IsInRole stops seeing app roles.
                    options.TokenValidationParameters.RoleClaimType = "roles";
                });
        }
        else
        {
            // The swap point (M39, ADR-0004): the host registers its own validation
            // handler under the caller-token scheme — Microsoft.Identity.Web, another
            // OIDC issuer, an introspection handler. Nothing above or below changes,
            // and the stage still enforces MaxTokenAge from the options registered
            // by this extension, so the bound survives the swap.
            registerScheme(callerTokenBuilder);

            // The swap was REQUESTED: mark it so the startup guard can warn when the
            // callback registered no handler under the caller-token scheme (every token
            // would then be refused, silently). A host that never called this extension
            // has no marker, so the guard's scheme-absent path stays silent for it.
            services.AddSingleton<CallerTokenSwapRequested>();
        }

        // The mapping layer only exists with this extension: without it the caller
        // feature never attempts the token scheme at all. A host can replace it with a
        // mapper for another claim layout or caller directory.
        services.TryAddSingleton<ICallerTokenMapper, DefaultCallerTokenMapper>();

        // M39: the scheme without caller authentication is a silent fail-open
        // proxy (no feature runs, hygiene never strips). Evaluated at startup — the two
        // extensions may be registered in any order — not here.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IHostedService, CallerTokenStartupGuard>());

        return services;
    }

    /// <summary>
    /// Turns on the audit log (§4 "Audit log", §5.2 "Audit"): binds
    /// <c>CredProx:Audit</c> (enabled flag, sink timeout, header capture and redaction
    /// lists) and registers the built-in <see cref="LoggerAuditSink"/>. One record per
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
    public static IServiceCollection AddCredProxAudit(
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
    /// Turns on credential health monitoring (§4 "Credential health", §5.2 "Credential
    /// health"): binds <c>CredProx:Health</c> (probe interval, certificate warning
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
        ConfigKeyValidator.RejectUnknownKeysAtStartup(configuration, "CredProx:Health", typeof(CredProxHealthOptions));

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
    /// Turns on outbound throttling (§8.4, §5.2 "Throttling"): binds
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
        ConfigKeyValidator.RejectUnknownKeysAtStartup(configuration, "CredProx:Throttling", typeof(ThrottleOptions));

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
    /// Turns on the resilience adapter (§8.4, §5.2 "Resilience"): binds
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
        ConfigKeyValidator.RejectUnknownKeysAtStartup(configuration, "CredProx:Resilience", typeof(ResilienceOptions));

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
