using System.Diagnostics.CodeAnalysis;
using CredProx;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registration extensions of the CredProx.LoginExchange add-on (ADR-0005).
/// </summary>
[Experimental("CREDPROX001")]
public static class CredProxLoginExchangeServiceCollectionExtensions
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
    /// <c>Type: LoginExchange</c> under <c>CredProx:Credentials</c>. Call after
    /// <c>AddCredProx(configuration)</c>; the route metadata stays
    /// <c>CredProx.Credential</c> as for any other type.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    public static IServiceCollection AddCredProxLoginExchange(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        // The provider creates the shared "credprox-token" clients through
        // IHttpClientFactory; the add-on registers it itself rather than borrowing the
        // core built-in batch's AddHttpClient side effect, which no longer exists.
        services.AddHttpClient(CredProxHttpClientNames.TokenClient);

        services.AddCredProxCredentialType<LoginExchangeProvider, LoginExchangeOptions>("LoginExchange");
        services.TryAddSingleton<IValidateOptions<LoginExchangeOptions>, LoginExchangeOptionsValidator>();
        services.TryAddSingleton(TimeProvider.System);
        return services;
    }
}
