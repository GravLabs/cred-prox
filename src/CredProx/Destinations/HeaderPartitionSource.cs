using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace CredProx;

/// <summary>
/// The built-in <c>header:</c> partition source (see <c>docs/credprox-plan.md</c> §3.2):
/// the partition is the value of one inbound request header, for example
/// <c>"Partition": "header:X-API-Env"</c>. A missing or empty header resolves to
/// <see langword="null"/> — the allow-list then rejects the request (§3.4).
/// </summary>
/// <remarks>
/// The raw header value is returned untrimmed and unmatched: the
/// <see cref="PartitionSourceBinding"/> compares it to the allow-list by exact ordinal
/// match, so no normalization can turn a hostile value into an allowed one.
/// </remarks>
[Experimental("CREDPROX001")]
public sealed class HeaderPartitionSource : IPartitionSource
{
    private readonly string _headerName;

    /// <summary>Creates the source for one header name.</summary>
    /// <param name="headerName">The inbound header to read; must not be empty.</param>
    public HeaderPartitionSource(string headerName)
    {
        ArgumentException.ThrowIfNullOrEmpty(headerName);
        _headerName = headerName;
    }

    /// <inheritdoc />
    public ValueTask<string?> GetPartitionAsync(HttpContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!context.Request.Headers.TryGetValue(_headerName, out var values)
            || StringValues.IsNullOrEmpty(values))
        {
            return new((string?)null);
        }

        return new(values[0]);
    }
}

/// <summary>The <see cref="IPartitionSourceFactory"/> for the <c>header:</c> scheme.</summary>
[Experimental("CREDPROX001")]
public sealed class HeaderPartitionSourceFactory : IPartitionSourceFactory
{
    /// <inheritdoc />
    public string Scheme => "header";

    /// <inheritdoc />
    public IPartitionSource CreateSource(string argument)
    {
        ArgumentException.ThrowIfNullOrEmpty(argument);
        return new HeaderPartitionSource(argument);
    }
}
