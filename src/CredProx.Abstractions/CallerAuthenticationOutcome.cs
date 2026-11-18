using System.Diagnostics.CodeAnalysis;

namespace CredProx.Abstractions;

/// <summary>
/// The three outcomes one <see cref="ICallerAuthenticator"/> pass can report (ADR-0005).
/// </summary>
[Experimental("CREDPROX001")]
public enum CallerAuthenticationOutcome
{
    /// <summary>
    /// No credential of this authenticator's type was presented: the next registered
    /// authenticator is tried. This is not a rejection — rejecting a request that carries
    /// another credential type's token would preempt its owner's evaluation.
    /// </summary>
    NoCredential = 0,

    /// <summary>
    /// A credential of this authenticator's type was presented and is refused (bad, stale
    /// or revoked): the request stops with 401 — the core owns the response — and no later
    /// authenticator is consulted. Fail closed — a presented-but-refused credential never
    /// falls through to another authenticator.
    /// </summary>
    Refused = 1,

    /// <summary>
    /// A credential of this authenticator's type was validated: the identity (and scope
    /// set, when the credential type carries one) is published by the caller stage and the
    /// core's admission policy takes over from there.
    /// </summary>
    Authenticated = 2,
}
