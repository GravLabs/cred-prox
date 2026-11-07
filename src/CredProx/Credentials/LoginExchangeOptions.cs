using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// Options for the <c>LoginExchange</c> credential type (see <c>docs/credprox-plan.md</c>
/// §3.2 cayuse and §4): a login endpoint that returns the credential value, with Basic or
/// form credentials and the token read from the raw body, a JSON path, a response header or
/// a cookie. Endpoint, user and password may be templates containing <c>{partition}</c> and
/// <c>{secret:...}</c>; per-partition secrets resolve per request (§5.2 "Login exchange" row).
/// The token is attached to the <c>Authorization</c> header by default; with
/// <see cref="Location"/> set to <see cref="CredentialLocation.Cookie"/> it is replayed as a
/// session cookie instead (plan §8.1 "Session cookie login").
/// </summary>
[Experimental("CREDPROX001")]
public sealed class LoginExchangeOptions : IHasAttachment, IHasPartitionConfig, IHasConnection
{
    /// <summary>
    /// The login endpoint; may contain <c>{partition}</c> and <c>{secret:...}</c> templates.
    /// Required.
    /// </summary>
    public string? LoginEndpoint { get; set; }

    /// <summary>The login request method, <c>GET</c> or <c>POST</c>. Default <c>GET</c>.</summary>
    public string Method { get; set; } = "GET";

    /// <summary>
    /// User and password sent as HTTP Basic on the login request; values may be templates.
    /// Mutually exclusive with <see cref="Form"/>.
    /// </summary>
    public LoginExchangeCredentials? Basic { get; set; }

    /// <summary>
    /// User and password sent as form fields on the login request; values may be templates.
    /// Mutually exclusive with <see cref="Basic"/>.
    /// </summary>
    public LoginExchangeCredentials? Form { get; set; }

    /// <summary>Where the token is read from in the login response. Default <see cref="LoginExchangeResponse.RawBody"/>.</summary>
    public LoginExchangeResponse Response { get; set; } = LoginExchangeResponse.RawBody;

    /// <summary>
    /// The JSON property path (<see cref="LoginExchangeResponse.JsonPath"/>), response header
    /// name (<see cref="LoginExchangeResponse.Header"/>) or cookie name
    /// (<see cref="LoginExchangeResponse.Cookie"/>). Required for those modes.
    /// </summary>
    public string? ResponseField { get; set; }

    /// <summary>
    /// Assumed token lifetime; the login response carries no expiry. Default one hour
    /// (the cayuse example configures <c>00:55:00</c>).
    /// </summary>
    public TimeSpan Lifetime { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// The partition block (<c>From</c> + <c>Allowed</c>) gating every use of the
    /// partition value for this credential; <see langword="null"/> when unpartitioned.
    /// </summary>
    public PartitionConfigOptions? Partition { get; set; }

    /// <summary>
    /// A <c>CredProx:Connections</c> name whose client certificate the token call also
    /// presents; <see langword="null"/> for the plain token client.
    /// </summary>
    public string? Connection { get; set; }

    /// <summary>
    /// The scheme written before the token in the Authorization header. Default empty —
    /// the raw token, as the cayuse exchange returns. Not supported when
    /// <see cref="Location"/> is <see cref="CredentialLocation.Cookie"/>: a cookie carries
    /// the raw value.
    /// </summary>
    public string AttachPrefix { get; set; } = string.Empty;

    /// <summary>
    /// Where the token is placed on the vendor request: <see cref="CredentialLocation.Header"/>
    /// (default, the classic exchange) or <see cref="CredentialLocation.Cookie"/> for
    /// session-cookie vendors. <see cref="CredentialLocation.Query"/> is not supported.
    /// </summary>
    public CredentialLocation Location { get; set; } = CredentialLocation.Header;

    /// <summary>
    /// The header name in header mode (default <c>Authorization</c>) or the cookie name in
    /// cookie mode (default: <see cref="ResponseField"/>, the cookie the login returned).
    /// </summary>
    public string? Name { get; set; }

    /// <inheritdoc />
    string IHasAttachment.Name => Location == CredentialLocation.Cookie
        ? Name ?? ResponseField
            ?? throw new InvalidOperationException("Cookie placement needs Name or ResponseField to name the cookie.")
        : Name ?? "Authorization";

    /// <inheritdoc />
    public string? Prefix => Location == CredentialLocation.Cookie
        ? null
        : (string.IsNullOrEmpty(AttachPrefix) ? null : AttachPrefix + " ");
}

/// <summary>
/// User and password pair for the login exchange; each value may be a template
/// (<c>{partition}</c>, <c>{secret:...}</c>) or a literal.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class LoginExchangeCredentials
{
    /// <summary>The user name template or literal.</summary>
    public string? User { get; set; }

    /// <summary>The password template or literal.</summary>
    public string? Password { get; set; }
}

/// <summary>
/// Where the login exchange reads the token from the login response (§4: "token from JSON
/// path / raw body / header / cookie").
/// </summary>
[Experimental("CREDPROX001")]
public enum LoginExchangeResponse
{
    /// <summary>The whole response body is the token.</summary>
    RawBody,

    /// <summary>A string property path (dot-separated) in the JSON response body.</summary>
    JsonPath,

    /// <summary>A response header named by <see cref="LoginExchangeOptions.ResponseField"/>.</summary>
    Header,

    /// <summary>A cookie named by <see cref="LoginExchangeOptions.ResponseField"/> from Set-Cookie.</summary>
    Cookie,
}
