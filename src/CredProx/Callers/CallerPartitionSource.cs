using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;

namespace CredProx;

/// <summary>
/// The built-in <c>caller:</c> partition source (§3.2, §4 Phase B "Per-caller credentials"):
/// the partition is the authenticated caller's id, so one credential serves every caller
/// with each caller mapped — through the allow-list and the <c>{partition}</c> templates —
/// to its own vendor account. An unauthenticated request (or an anonymous route) has no
/// partition and is rejected like any unmapped value.
/// </summary>
/// <remarks>
/// Rejection is <see cref="PartitionRejection.Forbidden"/>: the caller did not request a
/// bad value — their identity simply has no mapping — so the answer is
/// <c>403 credprox.operation_not_allowed</c>, not <c>400</c> (§3.4, §5.2 "Per-caller
/// credentials").
/// </remarks>
[Experimental("CREDPROX001")]
public sealed class CallerPartitionSource : IPartitionSource
{
    /// <inheritdoc />
    public PartitionRejection Rejection => PartitionRejection.Forbidden;

    /// <inheritdoc />
    public ValueTask<string?> GetPartitionAsync(HttpContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var identity = context.Features.Get<CallerIdentity>() ?? CallerIdentity.FromPrincipal(context.User);
        return new(identity?.CallerId);
    }
}

/// <summary>The <see cref="IPartitionSourceFactory"/> for the <c>caller:</c> scheme.</summary>
[Experimental("CREDPROX001")]
public sealed class CallerPartitionSourceFactory : IPartitionSourceFactory
{
    /// <inheritdoc />
    public string Scheme => "caller";

    /// <inheritdoc />
    public IPartitionSource CreateSource(string argument)
    {
        if (!string.IsNullOrEmpty(argument))
        {
            throw new ArgumentException(
                "The 'caller:' partition source takes no argument; the partition is the authenticated caller id.",
                nameof(argument));
        }

        return new CallerPartitionSource();
    }
}
