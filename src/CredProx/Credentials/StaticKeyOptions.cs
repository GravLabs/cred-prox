using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// Options for the <c>StaticKey</c> credential type (see <c>docs/credprox-plan.md</c> §4):
/// a fixed key resolved from a <c>secret:</c> reference (or literal), attached as a header
/// or query parameter, replacing any existing value (§5.2 "Static key" row).
/// </summary>
[Experimental("CREDPROX001")]
public sealed class StaticKeyOptions : IHasAttachment
{
    /// <summary>
    /// The key: a <c>secret:</c> reference or a literal. Required.
    /// </summary>
    public string? Secret { get; set; }

    /// <summary>Attach as a header or query parameter. Default <see cref="CredentialLocation.Header"/>.</summary>
    public CredentialLocation Location { get; set; } = CredentialLocation.Header;

    /// <summary>The header or query parameter name. Required.</summary>
    public string? Name { get; set; }

    /// <summary>
    /// Literal prefix written before the key inside the header/parameter
    /// (for example <c>"Bearer "</c>); default attaches the raw key.
    /// </summary>
    public string? Prefix { get; set; }

    /// <inheritdoc />
    CredentialLocation IHasAttachment.Location => Location;

    /// <inheritdoc />
    string IHasAttachment.Name => Name ?? throw new InvalidOperationException("StaticKey requires a Name.");

    /// <inheritdoc />
    string? IHasAttachment.Prefix => Prefix;
}
