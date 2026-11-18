using System.Diagnostics.CodeAnalysis;
using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registration extensions of the CredProx.CallerKeys add-on (ADR-0005).
/// </summary>
[Experimental("CREDPROX001")]
public static class CredProxCallerKeyServiceCollectionExtensions
{
    /// <summary>
    /// Adds caller API-key authentication and the per-caller request path:
    /// <list type="bullet">
    /// <item>the <see cref="CallerKeyAuthenticationHandler"/> scheme
    /// (<see cref="CallerKeyOptions.Scheme"/>) reading the header named by
    /// <c>CredProx:CallerAuth:HeaderName</c> (default <c>X-CredProx-Key</c>) and resolving
    /// values through <see cref="ICallerStore"/> — replace the store registration to put
    /// keys somewhere other than configuration;</item>
    /// <item>the key entry rules, contributed to the core's registry validation, so a
    /// malformed key, an unresolvable <c>secret:</c> reference or a duplicated
    /// <c>KeyId</c> fails startup — and a live edit into such a shape is refused with
    /// the previous registry still serving;</item>
    /// <item>the <c>CredProx:Callers</c> registry itself, bound eagerly at startup and
    /// rebound on configuration changes, so key rotation and revocation need no
    /// restart;</item>
    /// <item>the core's caller policy (registry, operation allow-lists, budgets, kill
    /// switch) and its authorization policy for hosts that prefer middleware
    /// enforcement.</item>
    /// </list>
    /// Once registered, every proxied route requires an authenticated caller unless its
    /// metadata says <c>"CredProx.Caller": "anonymous"</c>. Call after
    /// <c>AddCredProx(configuration)</c> and after a secret source is registered. The
    /// header name is read once at startup; changing it takes a restart. A host that
    /// authenticates callers another way never references this package.
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

        // Scheme options and the plain singleton the core's header hygiene reads by name
        // come from the same section at startup, so they can never disagree.
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
                CallerKeyOptions.Scheme,
                options => options.HeaderName = callerKeyOptions.HeaderName);

        // The authorization policy for middleware-enforcing hosts; it names both caller
        // schemes, so a caller token authenticates it too when the token add-on registered.
        services.AddCredProxCallerPolicy();

        // The key entry rules ride the registry-validation seam: they run at host start
        // and on every live rebind, before any registry swap takes effect.
        services.AddCredProxCallerRegistryValidator<CallerKeyRules>();

        // The hashed key table rides the registry-contributor seam: it is built eagerly
        // inside the same bind — at host start and on every accepted rebind — and commits
        // with the registry as one generation. A key whose secret: reference cannot be
        // resolved therefore refuses startup, and refuses the rebind (keeping the
        // previous generation serving) instead of failing silently on the request path.
        // The contributor registers through the package's own public contributor
        // extension, exactly the way a third party registers (ADR-0005); the TryAdd
        // keeps the host's own IConfiguration when the host registered one, and hosts
        // are not required to register IConfiguration itself in the container.
        services.TryAddSingleton(configuration);
        services.AddCredProxCallerRegistryContributor<CallerKeyTableContributor>();

        // The built-in store only reads the table committed in the live generation — it
        // touches no configuration and resolves no secret per request. A host can replace
        // this registration with a store backed by anything else.
        services.TryAddSingleton<SecretAccessorFactory>();
        services.TryAddSingleton<ICallerStore>(sp => new ConfigCallerStore(
            sp.GetRequiredService<CallerRegistryProvider>(),
            sp.GetRequiredService<TimeProvider>()));

        // The caller stage and the core's caller policy arrive through the public
        // authenticator path (ADR-0005): the built-in key authenticator registers exactly
        // like a third-party one, no internal shortcut.
        services.AddCredProxCallerAuthenticator<CallerKeyAuthenticator>(configuration);

        return services;
    }
}
