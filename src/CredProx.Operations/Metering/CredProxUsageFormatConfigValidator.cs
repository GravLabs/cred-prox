using Microsoft.Extensions.DependencyInjection;
using Yarp.ReverseProxy.Configuration;

namespace CredProx;

/// <summary>
/// Fail-closed usage-format validation (M54, ADR-0009): a route whose
/// <see cref="CredProxMetering.UsageRouteMetadata"/> metadata names a format that no
/// registered <see cref="IUsageReader"/> declares is refused at startup AND on every
/// configuration reload. YARP runs every registered <see cref="IConfigValidator"/> when it
/// loads the proxy configuration and rejects a load whose validation fails, keeping the
/// previously applied configuration serving — the same mechanism the core
/// <c>CredProxConfigValidator</c> uses for credential and destination references, reached
/// from Operations with zero core lines. Without this gate a mistyped format name would
/// sit inert: the per-request feature degrades to unmetered by design (a metering fault
/// must never refuse the caller's response), so config load is the only moment refusal is
/// both cheap and honest.
/// </summary>
/// <remarks>
/// <para>
/// An absent or empty metadata value means "not opted in", the same gate the credential
/// check uses — absence is not an unknown name; whitespace is a name, and names nothing.
/// The match against the registered <see cref="IUsageReader.Format"/> values is ordinal
/// and case-insensitive, mirroring the feature's selection rule, so a route that passes
/// this check can always be served by a reader that passes selection.
/// </para>
/// <para>
/// A registered reader set that cannot be enumerated — a host reader whose constructor or
/// <see cref="IUsageReader.Format"/> throws — fails the load with the failure kind named
/// rather than waving the value through: refusing a config load keeps the previous one
/// serving, which is the fail-closed direction available here. The message names the route
/// id and the offending value, as ADR-0009 promises.
/// </para>
/// <para>
/// Format uniqueness (M54, ADR-0009): <see cref="IUsageReader.Format"/> documents a name
/// unique to the body shape it parses, and selection takes the FIRST reader whose format
/// and media type match — registration order would otherwise decide silently. The rule this
/// gate enforces is per (Format, media type) over a bounded probe of the media types
/// CredProx meters: two registered readers sharing the name a route names are refused iff
/// both <see cref="IUsageReader.CanRead"/> the same probe media type (<c>application/json</c>
/// or <c>text/event-stream</c>). Sharing a name is legal exactly when the pair splits media
/// types — the built-in quartet does, JSON and SSE implementations per format — and a
/// duplicate is refused only on routes that name the duplicated format. The error names the
/// format and both implementation types.
/// </para>
/// </remarks>
internal sealed class CredProxUsageFormatConfigValidator(IServiceProvider services) : IConfigValidator
{
    /// <summary>
    /// The media types CredProx meters, probed when two readers share the format a route
    /// names: a pair that both accepts one of these leaves selection to registration order.
    /// </summary>
    private static readonly string[] MetersMediaTypes = ["application/json", "text/event-stream"];

    /// <inheritdoc />
    public ValueTask<IList<Exception>> ValidateRouteAsync(RouteConfig route)
    {
        ArgumentNullException.ThrowIfNull(route);

        var errors = new List<Exception>();
        if (route.Metadata is { } metadata
            && metadata.TryGetValue(CredProxMetering.UsageRouteMetadata, out var value)
            && !string.IsNullOrEmpty(value))
        {
            try
            {
                // Fresh transient resolves, the same instances selection would consider.
                // Config load is not a hot path: a handful of readers per route load.
                var readers = services.GetServices<IUsageReader>().ToList();
                var formats = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var reader in readers)
                {
                    formats.Add(reader.Format);
                }

                if (!formats.Contains(value))
                {
                    errors.Add(new InvalidOperationException(
                        $"Route '{route.RouteId}' names unknown usage format '{value}' in {CredProxMetering.UsageRouteMetadata}."));
                }
                else
                {
                    // Format uniqueness over the meters: readers sharing the name the route
                    // names are refused iff both accept the same probed media type, because
                    // selection then has no media-type answer and registration order would
                    // decide silently. Sharing a name is legal exactly when the pair splits
                    // media types, as the built-in JSON/SSE pair per format does. Only the
                    // format this route names is scanned; a duplicate of an unclaimed
                    // format cannot steer this route.
                    var claimants = new List<IUsageReader>();
                    foreach (var reader in readers)
                    {
                        if (string.Equals(reader.Format, value, StringComparison.OrdinalIgnoreCase))
                        {
                            claimants.Add(reader);
                        }
                    }

                    foreach (var probe in MetersMediaTypes)
                    {
                        var accepting = claimants.FindAll(reader => reader.CanRead(probe));
                        if (accepting.Count > 1)
                        {
                            errors.Add(new InvalidOperationException(
                                $"Route '{route.RouteId}' usage format '{value}' in {CredProxMetering.UsageRouteMetadata} is claimed by two readers that both accept '{probe}' ({accepting[0].GetType().Name} and {accepting[1].GetType().Name}); refusing the load."));
                            break;
                        }
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                errors.Add(new InvalidOperationException(
                    $"Route '{route.RouteId}' usage-format check for '{value}' in {CredProxMetering.UsageRouteMetadata} failed ({ex.GetType().Name}); refusing the load.",
                    ex));
            }
        }

        return new ValueTask<IList<Exception>>(errors);
    }

    /// <inheritdoc />
    public ValueTask<IList<Exception>> ValidateClusterAsync(ClusterConfig cluster)
    {
        ArgumentNullException.ThrowIfNull(cluster);

        return new ValueTask<IList<Exception>>([]);
    }
}
