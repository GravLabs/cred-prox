using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// Options for the <c>OAuthClientCredentials</c> credential type
/// (see <c>docs/credprox-plan.md</c> §3.2 and §4): token endpoint, client authentication
/// style, scopes and audience. Bound from a <c>CredProx:Credentials:&lt;name&gt;</c> section.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class OAuthClientCredentialsOptions : IHasAttachment, IHasPartitionConfig, IHasConnection
{
    /// <summary>The token endpoint URL. Required.</summary>
    public string? TokenEndpoint { get; set; }

    /// <summary>How the client authenticates to the token endpoint. Default <see cref="OAuthClientAuthentication.BasicHeader"/>.</summary>
    public OAuthClientAuthentication ClientAuthentication { get; set; } = OAuthClientAuthentication.BasicHeader;

    /// <summary>
    /// The client id: a <c>secret:</c> reference or a literal. Required.
    /// </summary>
    public string? ClientId { get; set; }

    /// <summary>
    /// The client secret: a <c>secret:</c> reference or a literal. Optional (public clients).
    /// </summary>
    public string? ClientSecret { get; set; }

    /// <summary>Optional <c>scope</c> parameter sent to the token endpoint.</summary>
    public string? Scope { get; set; }

    /// <summary>Optional <c>audience</c> parameter sent to the token endpoint.</summary>
    public string? Audience { get; set; }

    /// <summary>
    /// Lifetime assumed when the token response carries no <c>expires_in</c>.
    /// Default one hour.
    /// </summary>
    public TimeSpan DefaultLifetime { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// The partition block (<c>From</c> + <c>Allowed</c>) gating every use of the
    /// partition value for this credential; <see langword="null"/> when unpartitioned.
    /// </summary>
    public PartitionConfigOptions? Partition { get; set; }

    /// <summary>
    /// A <c>CredProx:Connections</c> name whose client certificate the token call also
    /// presents (mTLS vendors like ADP); <see langword="null"/> for the plain token client.
    /// </summary>
    public string? Connection { get; set; }

    /// <summary>
    /// The scheme written before the access token in the Authorization header.
    /// Default <c>"Bearer"</c>; set empty to attach the raw token.
    /// </summary>
    public string TokenTypeName { get; set; } = "Bearer";

    /// <inheritdoc />
    public CredentialLocation Location => CredentialLocation.Header;

    /// <inheritdoc />
    public string Name => "Authorization";

    /// <inheritdoc />
    public string? Prefix => string.IsNullOrEmpty(TokenTypeName) ? null : TokenTypeName + " ";
}

/// <summary>
/// How an OAuth client authenticates to the token endpoint (§4: "body or Basic client auth").
/// </summary>
[Experimental("CREDPROX001")]
public enum OAuthClientAuthentication
{
    /// <summary>HTTP Basic with <c>client_id:client_secret</c>; the body carries no client credentials.</summary>
    BasicHeader,

    /// <summary><c>client_id</c> and <c>client_secret</c> as form-body parameters.</summary>
    FormPost,
}
