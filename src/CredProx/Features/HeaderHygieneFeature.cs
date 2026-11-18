using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;

namespace CredProx;

/// <summary>
/// Options bound from the <c>CredProx</c> section root.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class CredProxCoreOptions
{
    /// <summary>
    /// The inbound caller-key header. Always stripped from the outbound request before
    /// forwarding, whatever the route; <see cref="Abstractions.Stage.ShapeHeaders"/>
    /// hygiene. Set empty to disable stripping.
    /// </summary>
    public string InboundKeyHeader { get; set; } = "X-API-Key";
}

/// <summary>
/// The built-in <see cref="Stage.ShapeHeaders"/> feature implementing
/// header hygiene: the inbound key header never reaches the upstream, and the
/// partition header is removed when the resolved destination declares
/// <c>StripHeader: true</c>. Runs after destination resolution (which reads the partition
/// header) and before credential attachment (which must not be shadowed by caller
/// headers).
/// </summary>
[Experimental("CREDPROX001")]
public sealed class HeaderHygieneFeature : IRequestFeature
{
    private readonly CredProxCoreOptions _options;
    private readonly string? _callerAuthHeader;

    /// <summary>Creates the feature.</summary>
    /// <param name="options">The core options carrying the inbound key header name.</param>
    /// <param name="configuration">
    /// The application configuration root. <c>CredProx:CallerAuth:HeaderName</c> (default
    /// <c>X-CredProx-Key</c>) names the header the caller-auth add-on authenticates with;
    /// it is stripped from the outbound request too, whether or
    /// not any add-on is registered — a key presented to a host without caller auth must
    /// not ride upstream either. The core reads the configured name, never a key type.
    /// </param>
    public HeaderHygieneFeature(CredProxCoreOptions options, IConfiguration configuration)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        ArgumentNullException.ThrowIfNull(configuration);
        var header = configuration["CredProx:CallerAuth:HeaderName"];
        _callerAuthHeader = string.IsNullOrEmpty(header) ? "X-CredProx-Key" : header;
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

        if (_callerAuthHeader is not null)
        {
            state.ProxyRequest.Headers.Remove(_callerAuthHeader);
        }

        // M39 (ADR-0004), seam view (ADR-0005): when the winning credential arrived in a
        // request header, that header IS the credential — the upstream must never see it.
        // Credential attachment runs after this stage and puts the vendor's own value in
        // its place. Paths whose credential is not a header value set no marker, so their
        // header behaviour is byte-for-byte unchanged.
        if (context.Features.Get<PresentedCredential>() is { } presented)
        {
            state.ProxyRequest.Headers.Remove(presented.HeaderName);
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
