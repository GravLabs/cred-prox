using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// The bound shape of one <c>CredProx:Destinations:&lt;name&gt;</c> section
/// (see <c>docs/credprox-plan.md</c> §3.2):
/// <code>
/// { "Template": "https://target.{partition}.cayuse.com", "Partition": "header:X-API-Env",
///   "Allowed": ["uat", "app"], "StripHeader": true }
/// </code>
/// </summary>
[Experimental("CREDPROX001")]
public sealed class DestinationDefinition
{
    /// <summary>
    /// The outbound address prefix; may contain one or more <c>{partition}</c>
    /// placeholders. Required.
    /// </summary>
    public string? Template { get; set; }

    /// <summary>
    /// Where the partition comes from (<c>header:X-API-Env</c>). Required when the
    /// template uses <c>{partition}</c>.
    /// </summary>
    public string? Partition { get; set; }

    /// <summary>
    /// The exact partition values admitted (ordinal match). Required non-empty whenever
    /// <see cref="Partition"/> is set — a destination that resolves a partition without an
    /// allow-list fails startup (§5.2 "Validation").
    /// </summary>
    public List<string> Allowed { get; set; } = [];

    /// <summary>
    /// When <see langword="true"/>, the partition header is removed from the outbound
    /// request before forwarding.
    /// </summary>
    public bool StripHeader { get; set; }
}
