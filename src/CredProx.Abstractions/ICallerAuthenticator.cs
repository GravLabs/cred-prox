using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Http;

namespace CredProx.Abstractions;

/// <summary>
/// Authenticates the caller of an inbound request and reports <em>who</em> it is (ADR-0005):
/// a <see cref="CallerIdentity"/>, plus — on a credential type that carries scopes — the scope
/// set the presented credential holds. An authenticator never decides what a caller may do:
/// the operation allow-list and the scope intersection stay in the core.
/// </summary>
/// <remarks>
/// <para>
/// Register through <c>WithCallerAuthenticator&lt;T&gt;()</c> — the one public
/// registration path, used by the built-in authenticators and third-party ones alike. The
/// core's caller stage asks every registered authenticator in registration order; the first
/// <see cref="CallerAuthenticationOutcome.Authenticated"/> or
/// <see cref="CallerAuthenticationOutcome.Refused"/> outcome wins. When every authenticator
/// answers <see cref="CallerAuthenticationOutcome.NoCredential"/>, the caller stage ends as an
/// unauthenticated request does today.
/// </para>
/// <para>
/// An authenticator only inspects the request and reports; publishing the identity is the
/// stage's job. Do not write <see cref="CallerIdentity"/> (or the user principal) into the
/// <see cref="HttpContext"/> from an authenticator — the stage publishes it once, in one
/// shape, so the allow-list, the audit partition and the host's policy all read the same
/// record whichever authenticator won.
/// </para>
/// </remarks>
[Experimental("CREDPROX001")]
public interface ICallerAuthenticator
{
    /// <summary>
    /// A short phrase naming what this authenticator requires — "caller API key", "caller
    /// token". The caller stage composes the 401 detail from the hints of every registered
    /// authenticator, so a refused request names what the host actually accepts without the
    /// stage knowing any credential type. Keep it lowercase and short; it appears in the
    /// sentence "A valid &lt;hint&gt; is required."
    /// </summary>
    string CredentialRequirementHint { get; }

    /// <summary>
    /// Inspects the inbound request for a credential of this authenticator's type and
    /// evaluates it.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> of the inbound request.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>
    /// One of the three outcomes — see <see cref="CallerAuthenticationResult"/>. A missing
    /// credential of this type must answer <see cref="CallerAuthenticationResult.NoCredential"/>,
    /// not a refusal, so a later authenticator still gets its turn.
    /// </returns>
    ValueTask<CallerAuthenticationResult> AuthenticateAsync(HttpContext context, CancellationToken cancellationToken);
}
