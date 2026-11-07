using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// Options for the add-on <c>TokenCredential</c> credential type (see
/// <c>docs/credprox-plan.md</c> §4): an <c>Azure.Core.TokenCredential</c> (for example a
/// managed identity) exchanged for a token scoped to <see cref="Scope"/>, attached as a
/// bearer header.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class TokenCredentialOptions : IHasAttachment
{
    /// <summary>The scope (resource) requested from the token credential. Required.</summary>
    public string Scope { get; set; } = string.Empty;

    /// <summary>The scheme used on the Authorization header. Default <c>Bearer</c>.</summary>
    public string TokenTypeName { get; set; } = "Bearer";

    /// <inheritdoc />
    CredentialLocation IHasAttachment.Location => CredentialLocation.Header;

    /// <inheritdoc />
    string IHasAttachment.Name => "Authorization";

    /// <inheritdoc />
    string? IHasAttachment.Prefix => TokenTypeName.Length > 0 ? TokenTypeName + " " : "";
}
