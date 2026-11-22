using System.Diagnostics.CodeAnalysis;
using CredProx;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registration extensions of the <c>LoginExchange</c> credential layer (ADR-0005);
/// the type ships in the core from 0.15.
/// </summary>
[Experimental("CREDPROX001")]
internal static class CredProxLoginExchangeServiceCollectionExtensions
{
    /// <summary>
    /// Adds the <c>LoginExchange</c> credential type:
    /// <list type="bullet">
    /// <item>the <see cref="LoginExchangeProvider"/> — calls a login endpoint and reads the
    /// credential from the raw body, a JSON path, a response header or a cookie; endpoint
    /// and credentials are templates expanded per request through the core's shared
    /// expander, and the token is cached per <c>(credential, partition)</c>;</item>
    /// <item>the startup validator: a missing endpoint, an unsupported method, both
    /// credential styles at once, a response mode without <c>ResponseField</c>, or an
    /// incoherent cookie placement fails startup.</item>
    /// </list>
    /// Configuration is unchanged from the core era: a credential section with
    /// <c>Type: LoginExchange</c> under <c>CredProx:Credentials</c>. From 0.15 the type
    /// ships in the core and <c>AddCredProxBuiltInCredentials()</c> registers it — this
    /// call is kept for hosts that still carry it and is idempotent. The route metadata
    /// stays <c>CredProx.Credential</c> as for any other type.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    internal static IServiceCollection AddCredProxLoginExchange(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        // The provider creates the shared "credprox-token" clients through
        // IHttpClientFactory. Since M49 the built-in batch calls this registration, so
        // the named client's handler chain is configured exactly once per collection —
        // a second pass must not stack a second primary handler on the same client.
        // Credential acquisition never follows redirects (M45 security finding F-1): the
        // default transport refuses 3xx outright, and the guard refuses the response of a
        // followed redirect even when a host supplies its own redirecting primary handler.
        if (!services.Any(d => d.ServiceType == typeof(TokenClientConfigured)))
        {
            services.AddSingleton<TokenClientConfigured>();
            services.AddHttpClient(CredProxHttpClientNames.TokenClient)
                .ConfigurePrimaryHttpMessageHandler(static () => new SocketsHttpHandler
                {
                    AllowAutoRedirect = false,
                    PooledConnectionLifetime = TimeSpan.FromMinutes(2),
                })
                .AddHttpMessageHandler(static () => new CredProxRedirectGuard());
        }

        services.AddCredProxCredentialType<LoginExchangeProvider, LoginExchangeOptions>("LoginExchange");
        services.TryAddSingleton<IValidateOptions<LoginExchangeOptions>, LoginExchangeOptionsValidator>();
        services.TryAddSingleton(TimeProvider.System);
        return services;
    }
}
