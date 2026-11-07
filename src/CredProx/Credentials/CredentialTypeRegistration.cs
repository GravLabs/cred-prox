using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// One explicit credential-type registration (see <c>docs/credprox-plan.md</c> §3.5 rule 6:
/// nothing is discovered by scanning): the configuration <c>Type</c> name mapped to its
/// options and provider types.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class CredentialTypeRegistration
{
    /// <summary>Creates the registration.</summary>
    /// <param name="typeName">The configuration <c>Type</c> name, for example <c>OAuthClientCredentials</c>.</param>
    /// <param name="optionsType">The bound options type.</param>
    /// <param name="providerType">The provider implementation type.</param>
    public CredentialTypeRegistration(string typeName, Type optionsType, Type providerType)
    {
        ArgumentException.ThrowIfNullOrEmpty(typeName);
        TypeName = typeName;
        OptionsType = optionsType ?? throw new ArgumentNullException(nameof(optionsType));
        ProviderType = providerType ?? throw new ArgumentNullException(nameof(providerType));
    }

    /// <summary>The configuration <c>Type</c> name.</summary>
    public string TypeName { get; }

    /// <summary>The bound options type.</summary>
    public Type OptionsType { get; }

    /// <summary>The provider implementation type.</summary>
    public Type ProviderType { get; }
}
