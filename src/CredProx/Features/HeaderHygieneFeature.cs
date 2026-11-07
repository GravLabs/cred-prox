using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;

namespace CredProx;

/// <summary>
/// Options bound from the <c>CredProx</c> section root (§3.2).
/// </summary>
[Experimental("CREDPROX001")]
public sealed class CredProxCoreOptions
{
    /// <summary>
    /// The inbound caller-key header. Always stripped from the outbound request before
    /// forwarding, whatever the route (§3.2); <see cref="Abstractions.Stage.ShapeHeaders"/>
    /// hygiene. Set empty to disable stripping.
    /// </summary>
    public string InboundKeyHeader { get; set; } = "X-API-Key";
}

/// <summary>
/// The built-in <see cref="Stage.ShapeHeaders"/> feature implementing the §5.2
/// "Header hygiene" row: the inbound key header never reaches the upstream, and the
/// partition header is removed when the resolved destination declares
/// <c>StripHeader: true</c>. Runs after destination resolution (which reads the partition
/// header) and before credential attachment (which must not be shadowed by caller
/// headers).
/// </summary>
[Experimental("CREDPROX001")]
public sealed class HeaderHygieneFeature : IRequestFeature
{
    private readonly CredProxCoreOptions _options;
    private readonly IReadOnlyList<string> _callerKeyHeaders;

    /// <summary>Creates the feature.</summary>
    /// <param name="options">The core options carrying the inbound key header name.</param>
    /// <param name="callerKeyOptions">
    /// The caller-auth options when caller authentication is registered; its header name is
    /// stripped from the outbound request too (§5.2 "Header hygiene"). Empty otherwise.
    /// </param>
    public HeaderHygieneFeature(CredProxCoreOptions options, IEnumerable<CallerKeyOptions> callerKeyOptions)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        ArgumentNullException.ThrowIfNull(callerKeyOptions);
        _callerKeyHeaders = callerKeyOptions
            .Select(o => o.HeaderName)
            .Where(h => !string.IsNullOrEmpty(h))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <inheritdoc />
    public Stage Stage => Stage.ShapeHeaders;

    /// <inheritdoc />
    public ValueTask ApplyAsync(HttpContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.Features.Get<CredProxRequestState>() is not { } state)
        {
            return ValueTask.CompletedTask;
        }

        if (!string.IsNullOrEmpty(_options.InboundKeyHeader))
        {
            state.ProxyRequest.Headers.Remove(_options.InboundKeyHeader);
        }

        foreach (var header in _callerKeyHeaders)
        {
            state.ProxyRequest.Headers.Remove(header);
        }

        if (state.Destination is { Definition.StripHeader: true } destination
            && PartitionSpec.TryParse(destination.Definition.Partition, out var scheme, out var argument)
            && scheme.Equals("header", StringComparison.OrdinalIgnoreCase)
            && !string.IsNullOrEmpty(argument))
        {
            state.ProxyRequest.Headers.Remove(argument);
        }

        return ValueTask.CompletedTask;
    }
}
