using System.Diagnostics.CodeAnalysis;
using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registration extensions of the <c>Hmac</c> credential layer (ADR-0005); the type
/// ships in the core from 0.15.
/// </summary>
[Experimental("CREDPROX001")]
internal static class CredProxHmacServiceCollectionExtensions
{
    /// <summary>
    /// Adds the <c>Hmac</c> credential type and the signing stage:
    /// <list type="bullet">
    /// <item>the <see cref="HmacProvider"/> — a signature-style credential: the resolved
    /// key is never attached to the request, only the computed signature is;</item>
    /// <item>the <see cref="HmacSignFeature"/> at <see cref="Stage.Sign"/>, which builds
    /// the configured canonical string from the FINAL outbound request form, computes the
    /// HMAC over the resolved key, and writes the signature (and optional timestamp)
    /// headers — the <c>bodyHash</c> component reads the body through the core's measured
    /// hand-off (<see cref="CredProxRequestState.MeasureOutgoingBodyAsync"/>), so a body
    /// over <see cref="HmacOptions.MaxBodyBytes"/> answers
    /// <c>413 credprox.body_too_large_to_sign</c> and is not forwarded;</item>
    /// <item>the startup validator: a recipe whose component the signer cannot reproduce,
    /// a missing key or signature header, or <c>bodyHash</c> without <c>BufferBody</c>
    /// fails startup.</item>
    /// </list>
    /// Configuration is unchanged from the core era: a credential section with
    /// <c>Type: Hmac</c> under <c>CredProx:Credentials</c>. From 0.15 the type ships in
    /// the core and <c>AddCredProxBuiltInCredentials()</c> registers it — this call is
    /// kept for hosts that still carry it and is idempotent. The route metadata stays
    /// <c>CredProx.Credential</c> as for any other type.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    internal static IServiceCollection AddCredProxHmac(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddCredProxCredentialType<HmacProvider, HmacOptions>("Hmac");
        services.TryAddSingleton<IValidateOptions<HmacOptions>, HmacOptionsValidator>();
        services.TryAddSingleton(TimeProvider.System);
        // The pipeline orders features by declared stage, so the DI registration is the
        // whole contract — the same way a third-party feature joins (§3.5).
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IRequestFeature, HmacSignFeature>());
        return services;
    }
}
