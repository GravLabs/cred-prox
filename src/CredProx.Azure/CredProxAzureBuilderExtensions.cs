using System.Diagnostics.CodeAnalysis;
using Azure.Core;
using CredProx;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// The Azure package's one chained call (ADR-0007): <c>.AddAzure(credential)</c> brings
/// the <c>TokenCredential</c> credential type. The credential is a value only the host
/// can supply, so it stays an argument.
/// </summary>
[Experimental("CREDPROX001")]
public static class CredProxAzureBuilderExtensions
{
    /// <summary>
    /// Registers the <c>TokenCredential</c> credential type with the credential instance
    /// the host chose (for example <c>DefaultAzureCredential</c> or a managed-identity
    /// credential). Key Vault itself is read through the Azure SDK's own configuration
    /// provider — this call never touches Key Vault.
    /// </summary>
    /// <param name="builder">The CredProx builder from <c>AddCredProx(configuration)</c>.</param>
    /// <param name="credential">The credential used to obtain Azure AD tokens.</param>
    /// <returns>The same <paramref name="builder"/>, for chaining.</returns>
    public static CredProxBuilder AddAzure(this CredProxBuilder builder, TokenCredential credential)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(credential);

        builder.Services.AddCredProxAzureTokenCredential(credential);
        return builder;
    }
}
