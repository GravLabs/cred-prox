using System.Diagnostics.CodeAnalysis;

namespace CredProx.Abstractions;

/// <summary>
/// How a rejected partition value answers the caller (see <c>docs/credprox-plan.md</c>
/// §3.4). A value the caller <em>requested</em> (a header) that is not allowed is a bad
/// request; a value <em>derived from the caller's identity</em> that has no mapping is an
/// authorization failure — the caller asked nothing wrong, they are simply not admitted.
/// </summary>
[Experimental("CREDPROX001")]
public enum PartitionRejection
{
    /// <summary><c>400 credprox.partition_not_allowed</c> — the requested value is not allowed.</summary>
    BadRequest = 0,

    /// <summary><c>403 credprox.operation_not_allowed</c> — the caller is not admitted.</summary>
    Forbidden = 1,
}
