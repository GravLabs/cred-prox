using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// Where an obtained credential value is placed on the outbound request
/// (see <c>docs/credprox-plan.md</c> §4, StaticKey "header or query").
/// </summary>
[Experimental("CREDPROX001")]
public enum CredentialLocation
{
    /// <summary>A request header; an existing value is replaced, never merged.</summary>
    Header,

    /// <summary>A query-string parameter; an existing parameter is replaced, never duplicated.</summary>
    Query,

    /// <summary>
    /// A single <c>Cookie</c> header carrying only the <c>name=value</c> pair for this
    /// credential; a caller-supplied <c>Cookie</c> header is replaced wholesale, never
    /// merged — merging would smuggle the caller's own cookies to the vendor.
    /// </summary>
    Cookie,
}
