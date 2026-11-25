namespace CredProx;

/// <summary>
/// Per-request metering state, carried on <c>HttpContext.Features</c> between the request
/// feature (which wraps the outbound body) and the response feature (which wraps the
/// caller body, installs the usage peek and records at <c>Response.OnCompleted</c>).
/// Internal to the add-on — like the scrubber's refusal marker, a feature instance is not
/// public surface.
/// </summary>
internal sealed class MeteringRequestState
{
    /// <summary>The outbound-body counter installed by the request feature; null for a bodyless request.</summary>
    public CountingReadStream? RequestBytes { get; init; }

    /// <summary>The caller-body counter installed by the response feature.</summary>
    public CountingWriteStream? ResponseBytes { get; set; }

    /// <summary>The usage reader fed by the peek; null when the route is not opted in or no reader claims the media type.</summary>
    public IUsageReader? Usage { get; set; }
}
