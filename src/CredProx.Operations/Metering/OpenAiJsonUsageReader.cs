using System.Text.Json;

namespace CredProx;

/// <summary>
/// OpenAI non-streaming reader (M54, ADR-0009): picks the root <c>usage</c> object out of a
/// JSON response as its bytes arrive, reading <c>prompt_tokens</c> as the input count and
/// <c>completion_tokens</c> as the output count. The detail nesting
/// (<c>completion_tokens_details.reasoning_tokens</c>, <c>prompt_tokens_details.cached_tokens</c>)
/// is deliberately not read: an OpenAI-format provider already counts reasoning tokens
/// inside <c>completion_tokens</c> (measured on a Foundry Local CPU server), so adding the
/// detail would double-count it; detail objects sit deeper than the walked field depth and
/// report nothing. The walk itself is the Anthropic JSON reader's discipline exactly — the
/// response is never buffered for the caller, an incomplete trailing token simply ends this
/// pass (the walk resumes from the same point when more bytes arrive), once <c>usage</c>
/// has closed parsing stops while the bytes keep flowing, a response that never reports
/// <c>usage</c> stays unmetered, and JSON malformed past its last complete token ends the
/// attempt: unmetered, never guessed.
/// </summary>
internal sealed class OpenAiJsonUsageReader : IUsageReader
{
    private static ReadOnlySpan<byte> UsageName => "usage"u8;
    private static ReadOnlySpan<byte> InputName => "prompt_tokens"u8;
    private static ReadOnlySpan<byte> OutputName => "completion_tokens"u8;

    // Lazy like the SSE frame: the usage opt-in constructs every registered reader per
    // response to probe selection, so construction itself must not allocate a working
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

    public string Format => "openai";

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
                        // A number outside the long range is not a report either:
                        // TryGetInt64 declines instead of throwing, so the parse window
                        // stays open and a good field later in the same body is still
                        // counted (the decline-is-not-failure stance the Anthropic readers share).
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
                        // The *_tokens_details objects (and any other nested value inside
                        // usage): any number deeper down is not a top-level usage field —
                        // reasoning_tokens lives here and is already counted by the
                        // provider inside completion_tokens. Un-pair until the next field.
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
