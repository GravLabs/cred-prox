using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Authentication;

namespace CredProx;

/// <summary>
/// Options for the caller API-key authentication scheme, bound from
/// <c>CredProx:CallerAuth</c> (see <c>docs/credprox-plan.md</c> §4 Phase B).
/// </summary>
[Experimental("CREDPROX001")]
public sealed class CallerKeyOptions : AuthenticationSchemeOptions
{
    /// <summary>
    /// The inbound header carrying the caller API key. Always stripped from the outbound
    /// request by header hygiene (§3.2), whatever the route.
    /// </summary>
    public string HeaderName { get; set; } = "X-CredProx-Key";
}
