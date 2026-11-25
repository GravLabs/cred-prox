using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// The usage-metering leg's public knobs (M50, ADR-0008); section options are
/// <see cref="CredProxMeteringOptions"/>. Metering emits on the shared <c>CredProx</c>
/// meter with the throttle, resilience and health instruments; a host sees one meter scope.
/// </summary>
[Experimental("CREDPROX001")]
public static class CredProxMetering
{
    /// <summary>
    /// The route metadata key that opts a route into LLM token counting: its value NAMES
    /// the usage format the route's upstream speaks — <c>"anthropic"</c> or
    /// <c>"openai"</c> for the built-in readers, or the <see cref="IUsageReader.Format"/>
    /// name a host reader declares. Token counts are read from the provider's own usage
    /// report through the reader that matches the named format and accepts the response's
    /// media type (Anthropic's non-streaming <c>usage</c> and streaming
    /// <c>message_start</c>/<c>message_delta</c> events; OpenAI chat-completions
    /// <c>usage</c>, which on a stream arrives only when the caller itself asked for
    /// <c>stream_options.include_usage</c>); a response that reports no usage is counted
    /// as unmetered, never guessed. A value that names no registered format is refused at
    /// startup and on every configuration reload (ADR-0009); the M50 preview's boolean
    /// <c>"true"</c> is not accepted. The request counter and the byte counts do not
    /// depend on this key.
    /// </summary>
    public const string UsageRouteMetadata = "CredProx.Metering.Usage";
}
