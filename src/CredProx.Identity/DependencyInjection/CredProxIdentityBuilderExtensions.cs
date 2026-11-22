using System.Diagnostics.CodeAnalysis;
using CredProx;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// The identity family's one chained call (ADR-0007): <c>.AddIdentity()</c> brings the
/// OAuth credential types and, when caller tokens are configured, the caller-token
/// machinery. A host with <c>CredProx.CallerTokens</c> or <c>CredProx.OAuth</c> at 0.14
/// replaces both setup calls with this one.
/// </summary>
[Experimental("CREDPROX001")]
public static class CredProxIdentityBuilderExtensions
{
    /// <summary>
    /// Registers the identity family: the OAuth credential types
    /// (<c>OAuthClientCredentials</c>, <c>JwtAssertion</c>, <c>TokenExchange</c>) and the
    /// shared token HttpClient. The caller-token authentication scheme — and with it any
    /// authentication scheme at all — is registered only when the
    /// <c>CredProx:CallerToken</c> section is configured (ADR-0007 item 3): an OAuth-only
    /// host carries no scheme and no policy.
    /// </summary>
    /// <param name="builder">The CredProx builder from <c>AddCredProx(configuration)</c>.</param>
    /// <param name="registerScheme">
    /// The host-first caller-token scheme swap (M39): a delegate that registers the host's
    /// own handler under the caller-token scheme name instead of the stock JWT bearer
    /// validation. Requires a configured <c>CredProx:CallerToken</c> section.
    /// </param>
    /// <returns>The same <paramref name="builder"/>, for chaining.</returns>
    /// <exception cref="InvalidOperationException">
    /// <paramref name="registerScheme"/> was supplied with no configured
    /// <c>CredProx:CallerToken</c> section — a swap for machinery that does not exist.
    /// </exception>
    public static CredProxBuilder AddIdentity(
        this CredProxBuilder builder,
        Action<AuthenticationBuilder>? registerScheme = null)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.AddCredProxOAuth();

        if (builder.Configuration.GetSection("CredProx:CallerToken").GetChildren().Any())
        {
            builder.Services.AddCredProxCallerTokenAuthentication(builder.Configuration, registerScheme);
        }
        else if (registerScheme is not null)
        {
            throw new InvalidOperationException(
                "AddIdentity(registerScheme) swaps the caller-token authentication scheme, " +
                "but no CredProx:CallerToken section is configured — there is no " +
                "caller-token machinery to swap (ADR-0007). Configure caller tokens, or " +
                "drop the delegate.");
        }

        return builder;
    }
}
