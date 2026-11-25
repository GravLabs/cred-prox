using System.Text.Json;

namespace CredProx;

/// <summary>
/// Anthropic non-streaming reader (M50): picks the root <c>usage</c> object out of a JSON
/// response as its bytes arrive. Parsing walks the bytes held so far on each chunk — the
/// response is never buffered for the caller, and an incomplete trailing token simply ends
/// this pass (the walk resumes from the same point when more bytes arrive). Once
/// <c>usage</c> has closed, parsing stops; the bytes keep flowing. A response that never
/// reports <c>usage</c> stays unmetered, and JSON malformed past its last complete token
/// ends the attempt: unmetered, never guessed. Cache-accounting fields the provider
/// reports inside <c>usage</c> (<c>cache_read_input_tokens</c>,
/// <c>cache_creation_input_tokens</c>) are part of the provider's input accounting but are
/// not metered as separate instruments in M50.
/// </summary>
internal sealed class AnthropicJsonUsageReader : IUsageReader
{
    private static ReadOnlySpan<byte> UsageName => "usage"u8;
    private static ReadOnlySpan<byte> InputName => "input_tokens"u8;
    private static ReadOnlySpan<byte> OutputName => "output_tokens"u8;

    // Lazy like the SSE frame: the usage opt-in constructs every registered reader per
    // response to probe CanRead, so construction itself must not allocate a working
    // window that a non-JSON response would never use.
    private byte[] _buffer = [];
    private int _length;
    private bool _inUsage;
    private bool _awaitingInput;
    private bool _awaitingOutput;
    private bool _usageClosed;
    private bool _malformedTail;

    public long? InputTokens { get; private set; }

    public long? OutputTokens { get; private set; }

    public string Format => "anthropic";

    public bool CanRead(string? mediaType) =>
        mediaType is not null
        && (mediaType.Equals("application/json", StringComparison.OrdinalIgnoreCase)
            || mediaType.EndsWith("+json", StringComparison.OrdinalIgnoreCase));

    public void Observe(ReadOnlySpan<byte> utf8Chunk, bool endOfStream)
    {
        if (_usageClosed || _malformedTail)
        {
            return;
        }

        var required = _length + utf8Chunk.Length;
        if (required > _buffer.Length)
        {
            var size = Math.Max(8192, _buffer.Length);
            while (size < required)
            {
                size *= 2;
            }

            Array.Resize(ref _buffer, size);
        }

        utf8Chunk.CopyTo(_buffer.AsSpan(_length));
        _length += utf8Chunk.Length;

        // The options ctor walks what it is given as the whole document: a truncated tail
        // throws (caught below) and the pass simply ends there, so the flag decides only
        // whether a throw finalizes the attempt or leaves it open for the next chunk.
        var reader = new Utf8JsonReader(_buffer.AsSpan(0, _length), new JsonReaderOptions());
        try
        {
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.PropertyName when reader.CurrentDepth == 1:
                        _inUsage = reader.ValueTextEquals(UsageName);
                        _awaitingInput = false;
                        _awaitingOutput = false;
                        break;

                    case JsonTokenType.PropertyName when _inUsage && reader.CurrentDepth == 2:
                        _awaitingInput = reader.ValueTextEquals(InputName);
                        _awaitingOutput = reader.ValueTextEquals(OutputName);
                        break;

                    case JsonTokenType.Number when _inUsage && reader.CurrentDepth == 2:
                        // A non-positive count is not a report (the field stays null): a
                        // hostile or buggy body must never drive a monotonic counter down.
                        // A number outside the long range is not a report either: TryGetInt64
                        // declines instead of throwing, so the parse window stays open and a
                        // good field later in the same body is still counted (fold INFO-a —
                        // the SSE reader degrades the same way; GetInt64 here threw and the
                        // peek's catch ended the whole window with it).
                        if (_awaitingInput)
                        {
                            if (reader.TryGetInt64(out var inputTokens) && inputTokens > 0)
                            {
                                InputTokens = inputTokens;
                            }
                        }
                        else if (_awaitingOutput)
                        {
                            if (reader.TryGetInt64(out var outputTokens) && outputTokens > 0)
                            {
                                OutputTokens = outputTokens;
                            }
                        }

                        _awaitingInput = false;
                        _awaitingOutput = false;
                        break;

                    case JsonTokenType.StartObject when _inUsage && reader.CurrentDepth == 2:
                    case JsonTokenType.StartArray when _inUsage && reader.CurrentDepth == 2:
                        // A nested structure inside usage (its value object shares the depth
                        // of the "usage" property name, so members sit at 2 and containers
                        // start at 2 as well): any number it holds deeper down is not a
                        // top-level usage field; un-pair until the next field.
                        _awaitingInput = false;
                        _awaitingOutput = false;
                        break;

                    case JsonTokenType.EndObject when _inUsage && reader.CurrentDepth == 1:
                        // Closes the usage object itself; a nested object closing at depth 2
                        // is not the end of usage.
                        _usageClosed = true;
                        _inUsage = false;
                        break;
                }

                if (_usageClosed)
                {
                    _buffer = [];
                    _length = 0;
                    return;
                }
            }
        }
        catch (JsonException)
        {
            if (endOfStream)
            {
                // The stream ends here: the attempt is final, and what was read stands.
                // (A token that only looked complete at this point is exactly as final as
                // the provider's bytes make it; nothing is guessed beyond them.)
                _malformedTail = true;
            }

            // Otherwise: an incomplete trailing token. Keep every byte; the next pass
            // re-walks the whole prefix — assignments are idempotent, so re-walking a
            // settled token changes nothing, and the walk bounds by the leg's parse window.
            return;
        }

        // Fully consumed without a usage close.
        _length = 0;
    }
}
