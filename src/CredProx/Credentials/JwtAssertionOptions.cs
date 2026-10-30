using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// Options for the <c>JwtAssertion</c> credential type
/// (see <c>docs/credprox-plan.md</c> §4 Phase C "JWT assertion"): signs an assertion with
/// a key or certificate (RS256/ES256/PS256) and exchanges it for an access token at the
/// configured endpoint. The exchanged token — not the assertion — is cached per
/// <c>(credential, partition)</c> and attached to the request.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class JwtAssertionOptions : IHasAttachment, IHasPartitionConfig, IHasConnection
{
    /// <summary>The signing algorithm. Default <see cref="JwtAssertionAlgorithm.RS256"/>.</summary>
    public JwtAssertionAlgorithm Algorithm { get; set; } = JwtAssertionAlgorithm.RS256;

    /// <summary>
    /// The signing key: a <c>secret:</c> reference or a literal holding a PEM-encoded
    /// private key (PKCS#8). Mutually exclusive with <see cref="SigningCertificate"/>;
    /// one of the two is required.
    /// </summary>
    public string? SigningKey { get; set; }

    /// <summary>
    /// The signing certificate: a <c>secret:</c> reference or a literal holding a
    /// base64-encoded PKCS#12 (PFX) blob whose private key signs the assertion.
    /// Mutually exclusive with <see cref="SigningKey"/>.
    /// </summary>
    public string? SigningCertificate { get; set; }

    /// <summary>The <c>iss</c> claim. Required. Accepts the §3.2 template forms.</summary>
    public string? Issuer { get; set; }

    /// <summary>
    /// The <c>sub</c> claim; <see langword="null"/> omits it. Some vendors want the
    /// issuer repeated, some an app/installation id. Accepts the §3.2 template forms.
    /// </summary>
    public string? Subject { get; set; }

    /// <summary>The <c>aud</c> claim. Required. Accepts the §3.2 template forms.</summary>
    public string? Audience { get; set; }

    /// <summary>Assertion lifetime from issuance. Default five minutes (GitHub caps at ten).</summary>
    public TimeSpan Lifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Clock skew tolerance: <c>iat</c> is moved back and <c>exp</c> forward by this
    /// amount. Default zero.
    /// </summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.Zero;

    /// <summary>How the assertion is exchanged for a token. Default <see cref="JwtAssertionExchange.ClientAssertion"/>.</summary>
    public JwtAssertionExchange Exchange { get; set; } = JwtAssertionExchange.ClientAssertion;

    /// <summary>The exchange/token endpoint URL. Required. Accepts the §3.2 template forms.</summary>
    public string? TokenEndpoint { get; set; }

    /// <summary>
    /// The <c>client_id</c> form parameter for <see cref="JwtAssertionExchange.ClientAssertion"/>
    /// mode; a <c>secret:</c> reference or a literal. Optional there, unused elsewhere.
    /// </summary>
    public string? ClientId { get; set; }

    /// <summary>Optional <c>scope</c> form parameter for the exchange.</summary>
    public string? Scope { get; set; }

    /// <summary>
    /// The JSON field carrying the access token in the exchange response.
    /// Default <c>access_token</c>; GitHub App uses <c>token</c>.
    /// </summary>
    public string TokenField { get; set; } = "access_token";

    /// <summary>
    /// The JSON field carrying the lifetime in seconds; <see langword="null"/> skips it.
    /// Default <c>expires_in</c>.
    /// </summary>
    public string? ExpiresInField { get; set; } = "expires_in";

    /// <summary>
    /// The JSON field carrying an ISO 8601 absolute expiry (GitHub App's
    /// <c>expires_at</c>); consulted only when <see cref="ExpiresInField"/> is absent.
    /// <see langword="null"/> skips it.
    /// </summary>
    public string? ExpiresAtField { get; set; }

    /// <summary>
    /// Lifetime assumed when the response carries no expiry field. Default one hour.
    /// </summary>
    public TimeSpan DefaultLifetime { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// The partition block (<c>From</c> + <c>Allowed</c>) gating every use of the
    /// partition value for this credential; <see langword="null"/> when unpartitioned.
    /// </summary>
    public PartitionConfigOptions? Partition { get; set; }

    /// <summary>
    /// A <c>CredProx:Connections</c> name whose client certificate the exchange call also
    /// presents; <see langword="null"/> for the plain token client.
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

/// <summary>Assertion signing algorithms (§4 Phase C "JWT assertion": RS256/ES256/PS256).</summary>
[Experimental("CREDPROX001")]
public enum JwtAssertionAlgorithm
{
    /// <summary>RSASSA-PKCS1-v1_5 with SHA-256.</summary>
    RS256,

    /// <summary>ECDSA with P-256 and SHA-256.</summary>
    ES256,

    /// <summary>RSASSA-PSS with SHA-256.</summary>
    PS256,
}

/// <summary>How the signed assertion is exchanged for an access token.</summary>
[Experimental("CREDPROX001")]
public enum JwtAssertionExchange
{
    /// <summary>
    /// OAuth <c>client_assertion</c> (<c>private_key_jwt</c>, RFC 7523 §2.2):
    /// <c>grant_type=client_credentials</c> plus <c>client_assertion_type</c> and
    /// <c>client_assertion</c> form fields.
    /// </summary>
    ClientAssertion,

    /// <summary>
    /// JWT bearer grant (RFC 7523 §2.1, Salesforce/Google style):
    /// <c>grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer</c> plus the
    /// <c>assertion</c> form field.
    /// </summary>
    JwtBearerGrant,

    /// <summary>
    /// Assertion as <c>Authorization: Bearer</c> against the endpoint (GitHub App style:
    /// the app JWT calls <c>/app/installations/{id}/access_tokens</c>).
    /// </summary>
    BearerExchange,
}
