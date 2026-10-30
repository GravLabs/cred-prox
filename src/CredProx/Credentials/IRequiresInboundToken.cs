using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// Implemented by credential options that need the caller's inbound bearer token — the
/// delegated types (<c>TokenExchange</c>, see <c>docs/credprox-plan.md</c> §3.6). Declaring
/// it is what makes the core populate
/// <see cref="CredProx.Abstractions.CredentialRequestContext.InboundToken"/> for this
/// credential: providers that do not declare the need never see the request's token
/// (the §3.5 rule-4 secret-scoping principle, extended to request-borne secrets).
/// </summary>
/// <remarks>
/// When the route matches but the request carries no inbound token, the core answers
/// <c>401 credprox.inbound_token_missing</c> before the provider runs.
/// </remarks>
[Experimental("CREDPROX001")]
public interface IRequiresInboundToken
{
}
