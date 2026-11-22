using System.Diagnostics.CodeAnalysis;
using CredProx;
using CredProx.Abstractions;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// The plugin-author seams on <see cref="CredProxBuilder"/> (ADR-0007 item 5): a plugin
/// registers its credential type, caller authenticator, registry validator or registry
/// contributor through the builder it was handed, instead of a parallel set of service
/// extensions. Each seam is the same registration the matching <c>AddCredProx*</c>
/// service extension performs.
/// </summary>
[Experimental("CREDPROX001")]
public static class CredProxBuilderExtensions
{
    /// <summary>
    /// Registers one credential type: the configuration <c>Type</c> name mapped to its
    /// options and provider. A configured credential naming an unregistered type fails
    /// startup — and if the name is already registered, first registration wins.
    /// </summary>
    /// <typeparam name="TProvider">The provider implementation.</typeparam>
    /// <typeparam name="TOptions">The options type bound from the credential section.</typeparam>
    /// <param name="builder">The CredProx builder.</param>
    /// <param name="typeName">The configuration <c>Type</c> name, for example <c>StaticKey</c>.</param>
    /// <returns>The same <paramref name="builder"/>, for chaining.</returns>
    public static CredProxBuilder WithCredentialType<TProvider, TOptions>(
        this CredProxBuilder builder,
        string typeName)
        where TProvider : class, ICredentialProvider<TOptions>
        where TOptions : class
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.AddCredProxCredentialType<TProvider, TOptions>(typeName);
        return builder;
    }

    /// <summary>
    /// Registers a caller authenticator (ADR-0005): the one public path every
    /// <see cref="ICallerAuthenticator"/> takes, built-in or third-party.
    /// </summary>
    /// <typeparam name="TAuthenticator">The authenticator type.</typeparam>
    /// <param name="builder">The CredProx builder.</param>
    /// <returns>The same <paramref name="builder"/>, for chaining.</returns>
    public static CredProxBuilder WithCallerAuthenticator<TAuthenticator>(this CredProxBuilder builder)
        where TAuthenticator : class, ICallerAuthenticator
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.AddCredProxCallerAuthenticator<TAuthenticator>(builder.Configuration);
        return builder;
    }

    /// <summary>
    /// Registers an <see cref="ICallerRegistryValidator"/> the core runs over the caller
    /// registry at host start and on every live configuration rebind.
    /// </summary>
    /// <typeparam name="TValidator">The validator type; registered as a singleton.</typeparam>
    /// <param name="builder">The CredProx builder.</param>
    /// <returns>The same <paramref name="builder"/>, for chaining.</returns>
    public static CredProxBuilder WithCallerRegistryValidator<TValidator>(this CredProxBuilder builder)
        where TValidator : class, ICallerRegistryValidator
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.AddCredProxCallerRegistryValidator<TValidator>();
        return builder;
    }

    /// <summary>
    /// Registers an <see cref="ICallerRegistryContributor"/> whose data is committed with
    /// each accepted caller registry generation.
    /// </summary>
    /// <typeparam name="TContributor">The contributor type; registered as a singleton.</typeparam>
    /// <param name="builder">The CredProx builder.</param>
    /// <returns>The same <paramref name="builder"/>, for chaining.</returns>
    public static CredProxBuilder WithCallerRegistryContributor<TContributor>(this CredProxBuilder builder)
        where TContributor : class, ICallerRegistryContributor
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.AddCredProxCallerRegistryContributor<TContributor>();
        return builder;
    }
}
