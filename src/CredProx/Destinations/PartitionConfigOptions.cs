using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// The credential-side <c>Partition</c> block of <c>docs/credprox-plan.md</c> §3.2:
/// <c>{ "From": "header:X-API-Env", "Allowed": ["uat", "app"] }</c>. A credential that
/// declares it gates <em>every</em> use of the partition value — the token-endpoint
/// template, secret-name expansion and the token-cache key all run only after the value
/// passed the allow-list.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class PartitionConfigOptions
{
    /// <summary>
    /// Where the partition comes from, in spec form (<c>header:X-API-Env</c>). Required
    /// when the block is present.
    /// </summary>
    public string? From { get; set; }

    /// <summary>
    /// The exact partition values admitted (ordinal match). Required non-empty when the
    /// block is present — a partition block without an allow-list would gate nothing.
    /// </summary>
    public List<string> Allowed { get; set; } = [];
}

/// <summary>
/// Implemented by credential options that declare a <c>Partition</c> block
/// (see <see cref="PartitionConfigOptions"/>). The binder resolves and validates the
/// block at startup and stores the bound source on the
/// <see cref="CredentialBinding"/>.
/// </summary>
[Experimental("CREDPROX001")]
public interface IHasPartitionConfig
{
    /// <summary>The declared partition block, or <see langword="null"/> when unpartitioned.</summary>
    PartitionConfigOptions? Partition { get; }
}

/// <summary>
/// Implemented by credential options that reference a named connection
/// (<c>"Connection": "adp"</c>, §3.2) whose client certificate the token call uses.
/// </summary>
[Experimental("CREDPROX001")]
public interface IHasConnection
{
    /// <summary>The referenced <c>CredProx:Connections</c> name, or <see langword="null"/>.</summary>
    string? Connection { get; }
}
