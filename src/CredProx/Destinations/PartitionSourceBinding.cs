using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;

namespace CredProx;

/// <summary>
/// Thrown when a request's partition value is missing or not in the configured allow-list.
/// The request pipeline turns it into the rejection the source declares (§3.4) without
/// forwarding: <c>400 credprox.partition_not_allowed</c> for a requested value that was
/// refused (the default), <c>403 credprox.operation_not_allowed</c> for a value derived
/// from the caller's identity that has no mapping (the <c>caller:</c> source). The message
/// never contains the rejected value.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class PartitionNotAllowedException : Exception
{
    /// <summary>Creates the exception for one partition source description.</summary>
    /// <param name="sourceDescription">What the partition was read from, for error text; never a secret.</param>
    /// <param name="rejection">How the source's rejections answer the caller (§3.4).</param>
    public PartitionNotAllowedException(
        string sourceDescription, PartitionRejection rejection = PartitionRejection.BadRequest)
        : base($"The request's partition value is missing or not allowed ({sourceDescription}).")
    {
        var forbidden = rejection == PartitionRejection.Forbidden;
        StatusCode = forbidden ? StatusCodes.Status403Forbidden : StatusCodes.Status400BadRequest;
        Code = forbidden ? "credprox.operation_not_allowed" : "credprox.partition_not_allowed";
        Title = forbidden
            ? "The caller is not allowed this operation."
            : "The requested partition is not allowed.";
    }

    /// <summary>The HTTP status the pipeline answers with.</summary>
    public int StatusCode { get; }

    /// <summary>The <c>credprox.*</c> error code (§3.4).</summary>
    public string Code { get; }

    /// <summary>The static, caller-safe problem title.</summary>
    public string Title { get; }
}

/// <summary>
/// A partition source bound to its allow-list: it resolves the request's partition and
/// admits it only by exact ordinal match against the configured <c>Allowed</c> values
/// (see <c>docs/credprox-plan.md</c> §3.2/§3.4). This is the single gate the M2/M3 review
/// carry demands: nothing downstream — destination template, secret-name expansion, token
/// endpoint template, token-cache key — ever sees a partition value that did not pass here.
/// </summary>
/// <remarks>
/// Matching is exact and ordinal: no trimming, no case folding, no unicode normalization.
/// A missing or empty value is rejected like any other disallowed value.
/// </remarks>
[Experimental("CREDPROX001")]
public sealed class PartitionSourceBinding
{
    /// <summary>Creates the binding.</summary>
    /// <param name="source">The source that reads the partition.</param>
    /// <param name="allowed">The exact values admitted; must not be empty.</param>
    /// <param name="description">Where the partition comes from, for error text.</param>
    public PartitionSourceBinding(IPartitionSource source, IReadOnlyCollection<string> allowed, string description)
        : this(source, allowed, description, source?.Rejection ?? PartitionRejection.BadRequest)
    {
    }

    /// <summary>Creates the binding with an explicit rejection shape.</summary>
    /// <param name="source">The source that reads the partition.</param>
    /// <param name="allowed">The exact values admitted; must not be empty.</param>
    /// <param name="description">Where the partition comes from, for error text.</param>
    /// <param name="rejection">How a rejection answers the caller (§3.4).</param>
    public PartitionSourceBinding(
        IPartitionSource source,
        IReadOnlyCollection<string> allowed,
        string description,
        PartitionRejection rejection)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(allowed);

        if (allowed.Count == 0)
        {
            throw new ArgumentException("A partition allow-list must not be empty.", nameof(allowed));
        }

        Source = source;
        Allowed = new HashSet<string>(allowed, StringComparer.Ordinal);
        Description = description;
        Rejection = rejection;
    }

    /// <summary>The source that reads the raw partition value.</summary>
    public IPartitionSource Source { get; }

    /// <summary>The exact values admitted (ordinal comparison).</summary>
    public IReadOnlySet<string> Allowed { get; }

    /// <summary>Where the partition comes from, for error text; never a secret.</summary>
    public string Description { get; }

    /// <summary>How a rejection of this binding's partition answers the caller (§3.4).</summary>
    public PartitionRejection Rejection { get; }

    /// <summary>
    /// Resolves this request's partition and admits it against the allow-list.
    /// </summary>
    /// <param name="context">The inbound request.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The admitted partition value.</returns>
    /// <exception cref="PartitionNotAllowedException">
    /// The value is missing, empty, or not exactly one of the allowed values.
    /// </exception>
    public async ValueTask<string> ResolveAsync(HttpContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var value = await Source.GetPartitionAsync(context, cancellationToken).ConfigureAwait(false);

        if (value is null || !Allowed.Contains(value))
        {
            throw new PartitionNotAllowedException(Description, Rejection);
        }

        return value;
    }
}
