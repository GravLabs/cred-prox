using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Authentication;

namespace CredProx;

/// <summary>
/// Options for the caller API-key authentication scheme, bound from
/// <c>CredProx:CallerAuth</c>.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class CallerKeyOptions : AuthenticationSchemeOptions
{
    /// <summary>
    /// The ASP.NET Core authentication scheme name of the caller API-key handler, as
    /// registered when <c>AddCredProx</c> finds caller keys under <c>CredProx:Callers</c>.
    /// Hosts that enforce caller
    /// authentication through middleware set this scheme's authorization policy on their
    /// YARP routes; the in-pipeline enforcement works with or without it.
    /// </summary>
    public const string Scheme = "CredProxCallerKey";

    /// <summary>
    /// The inbound header carrying the caller API key. Always stripped from the outbound
    /// request by header hygiene, whatever the route.
    /// </summary>
    public string HeaderName { get; set; } = "X-CredProx-Key";
}
