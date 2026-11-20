using System.Diagnostics.CodeAnalysis;
using CredProx;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registration extensions of the CredProx.OAuth add-on (ADR-0005).
/// </summary>
[Experimental("CREDPROX001")]
public static class CredProxOAuthServiceCollectionExtensions
{
    /// <summary>
    /// Adds the three OAuth credential types:
    /// <list type="bullet">
    /// <item><c>OAuthClientCredentials</c> — the client-credentials grant against a token
    /// endpoint, with basic or request-body client authentication;</item>
    /// <item><c>TokenExchange</c> — the RFC 8693 token exchange, validating the inbound
    /// bearer token against Authority or Issuer+JwksUri over https
    /// (docs/adr/0002, docs/adr/0003);</item>
    /// <item><c>JwtAssertion</c> — a signed client-assertion grant (HS256/RS256, key or
    /// certificate).</item>
    /// </list>
    /// Each carries its startup validator and the named HttpClient used for token calls.
    /// The token cache, the credential binding and the shared <c>credprox-token</c>
    /// connection transport stay in the core; the token-lifetime policy (accept, cap,
    /// reject rules and the 24 h cap) crosses unchanged. Configuration is unchanged from
    /// the core era — credential sections under <c>CredProx:Credentials</c> naming these
    /// types, plus <c>CredProx:TokenEndpoint</c> and <c>CredProx:Connections</c> where
    /// used. Call after <c>AddCredProx(configuration)</c>; a credential naming one of
    /// these types without this package fails startup naming the package to add.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    public static IServiceCollection AddCredProxOAuth(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        // Credential acquisition never follows redirects (M45 security finding F-1): the
        // default transport refuses 3xx outright, and the guard refuses the response of a
        // followed redirect even when a host supplies its own redirecting primary handler.
        services.AddHttpClient(OAuthClientCredentialsProvider.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(static () => new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            })
            .AddHttpMessageHandler(static () => new CredProxRedirectGuard());

        services
            .AddCredProxCredentialType<OAuthClientCredentialsProvider, OAuthClientCredentialsOptions>("OAuthClientCredentials")
            .AddCredProxCredentialType<JwtAssertionProvider, JwtAssertionOptions>("JwtAssertion")
            .AddCredProxCredentialType<TokenExchangeProvider, TokenExchangeOptions>("TokenExchange");

        services.TryAddSingleton<IValidateOptions<OAuthClientCredentialsOptions>, OAuthClientCredentialsOptionsValidator>();
        services.TryAddSingleton<IValidateOptions<JwtAssertionOptions>, JwtAssertionOptionsValidator>();
        services.TryAddSingleton<IValidateOptions<TokenExchangeOptions>, TokenExchangeOptionsValidator>();
        services.TryAddSingleton(TimeProvider.System);
        return services;
    }
}
