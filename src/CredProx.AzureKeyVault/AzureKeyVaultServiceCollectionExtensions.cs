using System.Diagnostics.CodeAnalysis;
using Azure.Core;
using CredProx;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registers the Azure add-on credential types. Explicit registration only, like the core
/// (see <c>docs/credprox-plan.md</c> §3.5 rule 6).
/// </summary>
[Experimental("CREDPROX001")]
public static class AzureKeyVaultServiceCollectionExtensions
{
    /// <summary>
    /// Registers the <c>TokenCredential</c> credential type over the given Azure token
    /// credential (for example <c>DefaultAzureCredential</c> or
    /// <c>ManagedIdentityCredential</c> from Azure.Identity — the add-on itself depends only
    /// on Azure.Core and stays agnostic about which one the host supplies).
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="credential">The Azure token credential used for every <c>TokenCredential</c> credential.</param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    public static IServiceCollection AddCredProxAzureTokenCredential(
        this IServiceCollection services,
        TokenCredential credential)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(credential);

        services.TryAddSingleton(credential);
        services.AddCredProxCredentialType<AzureTokenCredentialProvider, TokenCredentialOptions>("TokenCredential");
        services.TryAddSingleton<Microsoft.Extensions.Options.IValidateOptions<TokenCredentialOptions>, TokenCredentialOptionsValidator>();
        return services;
    }
}
