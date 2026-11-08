using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// Options for the <c>TokenExchange</c> credential type
/// (see <c>docs/credprox-plan.md</c> §3.6): exchanges the caller's inbound user token for a
/// downstream token at the configured identity provider. CredProx validates the inbound
/// token itself (signature, issuer, audience, lifetime) before trusting its subject — the
/// per-user cache key must be non-forgeable. The exchanged token — never the inbound one —
/// is cached per <c>(credential, partition + subject)</c> and attached to the request.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class TokenExchangeOptions : IHasAttachment, IHasPartitionConfig, IHasConnection, IRequiresInboundToken
{
    /// <summary>The exchange wire shape. Default <see cref="TokenExchangeMode.Rfc8693"/>.</summary>
    public TokenExchangeMode Mode { get; set; } = TokenExchangeMode.Rfc8693;

    /// <summary>
    /// The IdP's OIDC authority URL (discovery supplies the JWKS and, unless
    /// <see cref="TokenEndpoint"/> is set, the token endpoint). Mutually exclusive with an
    /// explicit <see cref="JwksUri"/>; one of the two validation sources is required.
    /// Accepts the §3.2 template forms.
    /// </summary>
    public string? Authority { get; set; }

    /// <summary>
    /// The expected token <c>iss</c>. Required with <see cref="JwksUri"/>; when
    /// <see cref="Authority"/> is set it defaults to the discovered issuer.
    /// </summary>
    public string? Issuer { get; set; }

    /// <summary>
    /// The JWKS endpoint, used instead of <see cref="Authority"/> discovery. Accepts the
    /// §3.2 template forms.
    /// </summary>
    public string? JwksUri { get; set; }

    /// <summary>
    /// Requires the key material that validates inbound user tokens — the authority
    /// discovery document and any directly configured <see cref="JwksUri"/> — to be
    /// fetched over https. Default <see langword="true"/>, the ASP.NET Core JwtBearer
    /// contract: over plain http anyone on the network path can swap the signing keys and
    /// forge an inbound token that CredProx then exchanges. Setting <see langword="false"/>
    /// supports a private-network http IdP and is a deliberate security trade (docs/adr/0003).
    /// The startup validator refuses an http <see cref="Authority"/> or <see cref="JwksUri"/>
    /// unless opted out; runtime fetches fail closed on the same rule, including for a
    /// template-expanded http URL.
    /// </summary>
    public bool RequireHttpsMetadata { get; set; } = true;

    /// <summary>
    /// Scheme test for the <see cref="RequireHttpsMetadata"/> rule: a literal
    /// <c>http://</c> prefix (case-insensitive) on the TRIMMED value — the URI parser
    /// strips surrounding whitespace, so <c>" http://…"</c> is still an http URL.
    /// A §3.2 template that hides the scheme cannot be judged at startup; the runtime
    /// fetch judges the expanded value.
    /// </summary>
    internal static bool IsPlainHttp(string? value) =>
        value is not null && value.Trim().StartsWith("http://", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The required inbound token audience — mandatory. Without an audience check any token
    /// the issuer minted for any other client becomes exchangeable (token confusion, §3.6).
    /// Accepts the §3.2 template forms.
    /// </summary>
    public string? Audience { get; set; }

    /// <summary>
    /// The claim carrying the user subject for the per-user cache key and audit.
    /// Default <c>sub</c>; Entra scenarios may prefer <c>oid</c>.
    /// </summary>
    public string SubjectClaim { get; set; } = "sub";

    /// <summary>
    /// Inbound-token clock-skew tolerance. Default five minutes (the JwtBearer convention).
    /// </summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// The exchange/token endpoint. When unset with <see cref="Authority"/>, the discovered
    /// <c>token_endpoint</c> is used. Required when neither discovery nor a default exists.
    /// Accepts the §3.2 template forms.
    /// </summary>
    public string? TokenEndpoint { get; set; }

    /// <summary>
    /// The <c>client_id</c> for the exchange call. Required (a confidential client).
    /// A <c>secret:</c> reference or a literal; accepts the §3.2 template forms.
    /// </summary>
    public string? ClientId { get; set; }

    /// <summary>
    /// The <c>client_secret</c>: a <c>secret:</c> reference or a literal. Optional only for
    /// IdPs that authenticate this client another way. Accepts the §3.2 template forms.
    /// </summary>
    public string? ClientSecret { get; set; }

    /// <summary>Client authentication for the exchange call. Default Basic header.</summary>
    public OAuthClientAuthentication ClientAuthentication { get; set; } = OAuthClientAuthentication.BasicHeader;

    /// <summary>
    /// Optional <c>scope</c> for the exchanged token. Accepts the §3.2 template forms.
    /// </summary>
    public string? Scope { get; set; }

    /// <summary>
    /// RFC 8693 <c>subject_token_type</c>. Default
    /// <c>urn:ietf:params:oauth:token-type:access_token</c>.
    /// </summary>
    public string? SubjectTokenType { get; set; }

    /// <summary>
    /// RFC 8693 <c>requested_token_type</c>; <see langword="null"/> omits it.
    /// </summary>
    public string? RequestedTokenType { get; set; }

    /// <summary>
    /// RFC 8693 <c>issued_token_type</c>; <see langword="null"/> omits it.
    /// </summary>
    public string? IssuedTokenType { get; set; }

    /// <summary>
    /// RFC 8693 <c>aud</c> — the audience of the <em>requested</em> token (distinct from the
    /// inbound <see cref="Audience"/> that is validated); <see langword="null"/> omits it.
    /// </summary>
    public string? RequestedAudience { get; set; }

    /// <summary>
    /// RFC 8693 <c>act</c> (actor claim, JSON); <see langword="null"/> omits it. For
    /// on-behalf-of chains built by CredProx itself, not for caller-supplied actors.
    /// </summary>
    public string? Act { get; set; }

    /// <summary>
    /// The JSON field carrying the access token in the exchange response.
    /// Default <c>access_token</c>.
    /// </summary>
    public string TokenField { get; set; } = "access_token";

    /// <summary>
    /// The JSON field carrying the lifetime in seconds; <see langword="null"/> skips it.
    /// Default <c>expires_in</c>.
    /// </summary>
    public string? ExpiresInField { get; set; } = "expires_in";

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
    /// The scheme written before the exchanged token in the Authorization header.
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
/// The <c>TokenExchange</c> wire shape (§3.6): the RFC 8693 generic exchange. The mode only
/// sets the grant URN and the assertion parameter name; every other parameter stays
/// configurable. Microsoft's Entra on-behalf-of profile was removed in M27 (owner decision
/// 2026-11-03, <c>docs/adr/0002-remove-entra-obo.md</c>): a config still naming the removed
/// mode fails binding at startup — it never degrades to a silent RFC 8693 exchange.
/// </summary>
[Experimental("CREDPROX001")]
public enum TokenExchangeMode
{
    /// <summary>
    /// RFC 8693: <c>grant_type=urn:ietf:params:oauth:grant-type:token-exchange</c>, the
    /// inbound token sent as <c>subject_token</c> with <c>subject_token_type</c>.
    /// </summary>
    Rfc8693,
}
