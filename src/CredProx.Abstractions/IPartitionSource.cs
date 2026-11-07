using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Http;

namespace CredProx.Abstractions;

/// <summary>
/// Resolves the partition of a request — the vendor environment or caller account a
/// credential or destination is partitioned by. Built-ins read it from a request header,
/// a caller claim, the authenticated caller, or route metadata.
/// </summary>
[Experimental("CREDPROX001")]
public interface IPartitionSource
{
    /// <summary>
    /// Resolves the partition value for this request, or returns <see langword="null"/>
    /// when the request carries no partition. The core validates the value against the
    /// configured allow-list before anything is forwarded.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> of the inbound request.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    ValueTask<string?> GetPartitionAsync(HttpContext context, CancellationToken cancellationToken);

    /// <summary>
    /// How a value this source produces is rejected when it misses the allow-list
    /// (§3.4). Defaults to <see cref="Abstractions.PartitionRejection.BadRequest"/> — the
    /// value was requested and refused. Sources that derive the partition from the
    /// caller's identity (the <c>caller:</c> scheme) override this to
    /// <see cref="Abstractions.PartitionRejection.Forbidden"/>: an unmapped caller is not
    /// admitted, they did not send a bad value.
    /// </summary>
    PartitionRejection Rejection => PartitionRejection.BadRequest;
}
