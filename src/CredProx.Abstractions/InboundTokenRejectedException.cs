using System.Diagnostics.CodeAnalysis;

namespace CredProx.Abstractions;

/// <summary>
/// Thrown by a delegated credential provider when the caller's inbound token fails
/// validation (signature, issuer, audience, lifetime — see
/// <c>docs/credprox-plan.md</c> §3.6). The core turns this into
/// <c>401 credprox.inbound_token_invalid</c> and does not forward the request: unlike the
/// generic <c>credential_unavailable</c> 502 (the <em>proxy</em> failed upstream), here the
/// <em>caller's</em> token is the problem.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Reason"/> names only the failure kind (<c>malformed</c>, <c>signature</c>,
/// <c>issuer</c>, <c>audience</c>, <c>expired</c>, <c>not-yet-valid</c>,
/// <c>missing-subject</c>) — never the token value or its claims. The core logs and returns
/// it verbatim.
/// </para>
/// <para>
/// A missing inbound token is not this exception: the core answers
/// <c>401 credprox.inbound_token_missing</c> before the provider runs.
/// </para>
/// </remarks>
[Experimental("CREDPROX001")]
public sealed class InboundTokenRejectedException : InvalidOperationException
{
    /// <summary>Creates the exception naming the failure kind (never a token value).</summary>
    /// <param name="reason">
    /// The failure kind, from the documented set; carried into the problem response.
    /// </param>
    /// <param name="message">
    /// A developer-facing message naming the credential and the kind — no secret values.
    /// </param>
    public InboundTokenRejectedException(string reason, string message)
        : base(message)
    {
        ArgumentException.ThrowIfNullOrEmpty(reason);
        Reason = reason;
    }

    /// <summary>The failure kind; one of the documented set, never a token value.</summary>
    public string Reason { get; }
}
