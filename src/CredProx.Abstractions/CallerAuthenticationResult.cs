using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;

namespace CredProx.Abstractions;

/// <summary>
/// The outcome of one <see cref="ICallerAuthenticator"/> pass (ADR-0005). Create through the
/// static factories — the constructors are private so an outcome cannot carry contradictory
/// data (an identity on a refusal, say).
/// </summary>
/// <remarks>
/// A result reports, it does not decide: the core's operation allow-list and the scope
/// intersection still gate the request after an authentication.
/// </remarks>
[Experimental("CREDPROX001")]
public sealed record CallerAuthenticationResult
{
    private CallerAuthenticationResult(
        CallerAuthenticationOutcome outcome,
        CallerIdentity? identity,
        IReadOnlySet<string>? scopes,
        string? presentedCredentialHeader,
        ClaimsPrincipal? principal)
    {
        Outcome = outcome;
        Identity = identity;
        Scopes = scopes;
        PresentedCredentialHeader = presentedCredentialHeader;
        Principal = principal;
    }

    /// <summary>Which of the three outcomes this result carries.</summary>
    public CallerAuthenticationOutcome Outcome { get; }

    /// <summary>
    /// The authenticated caller. Non-null only for
    /// <see cref="CallerAuthenticationOutcome.Authenticated"/>; the stage publishes it as the
    /// request's caller identity.
    /// </summary>
    public CallerIdentity? Identity { get; }

    /// <summary>
    /// The scopes the presented credential carries. <see langword="null"/> means the
    /// credential type has no scope set at all (the API-key path: the operation allow-list
    /// applies unchanged). A non-null set — <em>even an empty one</em> — narrows admission to
    /// the named rules whose name is in the set (ADR-0004 clause 3: scope only narrows).
    /// Implementations must pass a set no one mutates after handing it over; it flows to the
    /// admission check as given.
    /// </summary>
    public IReadOnlySet<string>? Scopes { get; }

    /// <summary>
    /// The inbound request header that carried the winning credential, or
    /// <see langword="null"/> when the credential did not arrive in a request header. The
    /// stage marks that header for removal from the outbound request: on those paths the
    /// header <em>is</em> the caller's credential and the upstream must never see it; the
    /// vendor's own credential is attached afterwards as usual.
    /// </summary>
    public string? PresentedCredentialHeader { get; }

    /// <summary>
    /// The principal the stage publishes as <see cref="Microsoft.AspNetCore.Http.HttpContext.User"/>,
    /// or <see langword="null"/> to let the stage synthesize the caller-claims principal.
    /// Provide one only when the credential itself carries claims the host's middleware must
    /// keep seeing after authentication — a bearer token whose raw claim names and role
    /// membership drive host-side configuration. The stage attaches the caller-claims
    /// identity to it; the principal must not carry that identity yet.
    /// </summary>
    public ClaimsPrincipal? Principal { get; }

    private static readonly CallerAuthenticationResult NoCredentialValue =
        new(CallerAuthenticationOutcome.NoCredential, null, null, null, null);

    /// <summary>
    /// This authenticator's credential type is not on the request: the next registered
    /// authenticator gets its turn.
    /// </summary>
    /// <returns>A shared no-credential result (allocation-free).</returns>
    public static CallerAuthenticationResult NoCredential() => NoCredentialValue;

    /// <summary>
    /// A credential of this authenticator's type was presented and is refused. The request
    /// stops here with 401 — the core owns the response, an authenticator only reports —
    /// and no later authenticator is consulted.
    /// </summary>
    /// <returns>A refusal result.</returns>
    public static CallerAuthenticationResult Refused() =>
        new(CallerAuthenticationOutcome.Refused, null, null, null, null);

    /// <summary>
    /// The credential was validated and names a configured caller.
    /// </summary>
    /// <param name="identity">The caller this credential belongs to.</param>
    /// <param name="scopes">
    /// The credential's scope set, or <see langword="null"/> when the credential type
    /// carries no scopes. Pass an empty set — not <see langword="null"/> — to express "a
    /// scope set that names nothing": it locks out the caller's named rules (fail closed).
    /// </param>
    /// <param name="presentedCredentialHeader">
    /// The inbound request header that carried this credential, when it arrived in one —
    /// it is stripped from the outbound request so the upstream never sees the caller's
    /// credential. It must be a valid HTTP field-name: a malformed name throws here, in
    /// the calling code, where the bug is made. Pass <see langword="null"/> when the
    /// credential is not a header value.
    /// </param>
    /// <param name="principal">
    /// A host-visible principal to publish, when the credential carries claims the host's
    /// middleware must keep seeing; see <see cref="Principal"/>. Pass
    /// <see langword="null"/> for the synthesized caller-claims principal.
    /// </param>
    /// <returns>An authentication result.</returns>
    public static CallerAuthenticationResult Authenticated(
        CallerIdentity identity,
        IReadOnlySet<string>? scopes = null,
        string? presentedCredentialHeader = null,
        ClaimsPrincipal? principal = null)
    {
        ArgumentNullException.ThrowIfNull(identity);
        if (presentedCredentialHeader is { } header && !IsValidHeaderName(header))
        {
            throw new ArgumentException(
                "The presented credential header name is not a valid HTTP field-name (RFC 7230 tchar).",
                nameof(presentedCredentialHeader));
        }

        return new CallerAuthenticationResult(
            CallerAuthenticationOutcome.Authenticated, identity, scopes, presentedCredentialHeader, principal);
    }

    /// <summary>
    /// RFC 7230 field-name = 1*tchar, the token characters HTTP header names are built from.
    /// </summary>
    private static bool IsValidHeaderName(string name)
    {
        if (name.Length == 0)
        {
            return false;
        }

        foreach (var c in name)
        {
            if (c is not (>= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9'
                or '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-' or '.' or '^'
                or '_' or '`' or '|' or '~'))
            {
                return false;
            }
        }

        return true;
    }
}
