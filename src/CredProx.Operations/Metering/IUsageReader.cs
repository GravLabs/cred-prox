using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// A provider-specific reader that extracts LLM token usage from a response body while it
/// streams to the caller (M50, ADR-0008). The metering leg hands each chunk — in order,
/// the same bytes the caller receives — to the first registered reader whose
/// <see cref="Format"/> equals the usage format the route names and whose
/// <see cref="CanRead"/> accepted the response's content type.
/// </summary>
/// <remarks>
/// <para>
/// A reader is constructed fresh per response (transient <see cref="IUsageReader"/>
/// registration) and observed from one thread. It never holds the caller's stream: bytes
/// are forwarded whether or not the reader likes them, a throwing or stalling reader
/// degrades to unmetered, and usage past the leg's parse window (<see
/// cref="CredProxMeteringOptions.MaxUsageParseBytes"/>; the peek stops feeding chunks past
/// it) is unmetered. A reader must leave the counters <see langword="null"/> until its
/// provider has actually reported a value — usage that is not reported is unmetered,
/// never guessed.
/// </para>
/// <para>
/// The built-in Anthropic readers (<see cref="Format"/> <c>"anthropic"</c>) cover the
/// non-streaming JSON <c>usage</c> object and the streaming
/// <c>message_start</c>/<c>message_delta</c> events; the built-in OpenAI pair
/// (<c>"openai"</c>) covers the chat-completions <c>usage</c> object and its streamed
/// usage-only event. Another vendor adds its own reader behind this interface under its
/// own format name; the core is not involved.
/// </para>
/// </remarks>
[Experimental("CREDPROX001")]
public interface IUsageReader
{
    /// <summary>
    /// The body format this reader parses — <c>"anthropic"</c> and <c>"openai"</c> for the
    /// built-ins, or the host's own name (M54, ADR-0009). A route selects readers by naming
    /// its format in <see cref="CredProxMetering.UsageRouteMetadata"/> metadata; only a
    /// reader whose <see cref="Format"/> equals that value (ordinal, case-insensitive) is
    /// considered, so two vendors answering the same media type never compete. The name
    /// must be unique to the body shape it parses — a shared spelling is the union-reader
    /// mistake ADR-0009 rejects.
    /// </summary>
    string Format { get; }

    /// <summary>
    /// Whether this reader extracts usage from a response of this media type
    /// (parameters excluded, e.g. <c>application/json</c>, <c>text/event-stream</c>).
    /// </summary>
    bool CanRead(string? mediaType);

    /// <summary>
    /// Observes the next body chunk. Chunks arrive in order; <paramref name="endOfStream"/>
    /// marks that no further chunk will come. Implementations must return quickly and must
    /// not request more bytes themselves — the peek never buffers for a reader.
    /// </summary>
    void Observe(ReadOnlySpan<byte> utf8Chunk, bool endOfStream);

    /// <summary>Input tokens the provider reported, or <see langword="null"/> when none was reported.</summary>
    long? InputTokens { get; }

    /// <summary>Output tokens the provider reported, or <see langword="null"/> when none was reported.</summary>
    long? OutputTokens { get; }
}
