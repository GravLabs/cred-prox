using System.Text.Json;

namespace CredProx;

/// <summary>
/// Anthropic streaming (SSE) reader (M50): frames the event stream into events as their
/// bytes arrive and takes token counts from the usage objects the provider itself reports
/// — <c>message_start</c> carries the input usage, <c>message_delta</c> carries the
/// running output usage (values are cumulative, so the last one seen stands). Framing
/// never withholds caller bytes: the peek forwards every byte and this reader only
/// observes copies. An event larger than <see cref="MaxEventBytes"/> (the framing cap
/// <see cref="EventScrubbingStream"/> uses for the same reason) is skipped — and skipped
/// cleanly, so the events after it are still metered; the cross-chunk edge of a skipped
/// event's terminator is held for exactly that. Events whose <c>data</c> payload is not
/// valid JSON, or holds no usage, are unmetered.
/// </summary>
internal sealed class AnthropicSseUsageReader : IUsageReader
{
    internal const int MaxEventBytes = 64 * 1024;

    // The frame is materialised on the first chunk that really carries bytes, not at
    // construction: the usage opt-in resolves every registered reader per response to
    // probe CanRead, and a JSON answer on a busy AI route must not pay for this buffer
    // (measured in M50: 64 KB per request on usage-opted JSON routes before the fix).
    private byte[]? _frameBuffer;
    private byte[] Frame => _frameBuffer ??= new byte[MaxEventBytes];
    private int _length;
    private int _scanStart;

    // While an oversized event is being skipped, the last three bytes are kept: an event
    // terminator (longest spelling \r\n\r\n is four bytes, so three held plus one new is
    // enough to recognise one split across any chunk edge).
    private readonly byte[] _tail = new byte[3];
    private int _tailLength;
    private bool _skipEvent;

    public long? InputTokens { get; private set; }

    public long? OutputTokens { get; private set; }

    public string Format => "anthropic";

    public bool CanRead(string? mediaType) =>
        mediaType is not null && mediaType.Equals("text/event-stream", StringComparison.OrdinalIgnoreCase);

    public void Observe(ReadOnlySpan<byte> utf8Chunk, bool endOfStream)
    {
        var position = 0;
        while (position < utf8Chunk.Length)
        {
            var rest = utf8Chunk[position..];
            if (_skipEvent)
            {
                var tailLength = _tailLength;
                if (!TryFindBoundary(_tail.AsSpan(0, tailLength), rest, out var boundaryStart, out var boundaryLength))
                {
                    // The skipped event keeps running past this chunk; the last three
                    // bytes of held-tail ++ chunk are kept so its terminator is still
                    // recognised when it splits across chunks. Stack copy first: the held
                    // tail aliases the destination.
                    Span<byte> before = stackalloc byte[3];
                    _tail.AsSpan(0, tailLength).CopyTo(before);
                    KeepTailConcat(before[..tailLength], rest);
                    return;
                }

                // Bytes of the chunk before the terminator belong to the skipped event;
                // what follows it starts the next event, which this reader reads normally.
                _skipEvent = false;
                _tailLength = 0;
                _length = 0;
                _scanStart = 0;
                position += Math.Max(boundaryStart + boundaryLength - tailLength, 0);
                continue;
            }

            var room = MaxEventBytes - _length;
            var take = Math.Min(room, rest.Length);
            rest[..take].CopyTo(Frame.AsSpan(_length));
            _length += take;
            position += take;
            DrainFrame();
        }

        if (endOfStream && !_skipEvent && _length > 0)
        {
            // A trailing incomplete event: parse attempt anyway — a provider that ends the
            // stream after a final event without its blank line still gets that event read.
            ObserveEvent(Frame.AsSpan(0, _length));
            _length = 0;
        }
    }

    /// <summary>
    /// Consumes whole events from the frame, scanning from the last resume point (the
    /// pattern is at most four bytes, so a boundary split across chunks resumes at
    /// <c>length-3</c>). Returns whether any event was consumed.
    /// </summary>
    private bool DrainFrame()
    {
        var consumedAny = false;
        while (true)
        {
            // Scan only the valid window: bytes beyond _length are stale frame memory
            // (down-shifted copies leave their predecessor behind) and must never read as
            // a boundary.
            var index = IndexOfBoundary(Frame.AsSpan(_scanStart, _length - _scanStart));
            if (index < 0)
            {
                _scanStart = Math.Max(0, _length - 3);
                break;
            }

            index += _scanStart;
            var frame = Frame;
            var boundaryLength = BoundaryLength(frame.AsSpan(index), _length - index);
            ObserveEvent(frame.AsSpan(0, index));
            frame.AsSpan(index + boundaryLength, _length - index - boundaryLength)
                .CopyTo(frame);
            _length -= index + boundaryLength;
            _scanStart = 0;
            consumedAny = true;
        }

        if (_length == MaxEventBytes)
        {
            // The event outgrew the cap: skip it. The last bytes are kept so the
            // terminator is still recognised while skipping.
            _skipEvent = true;
            _tailLength = 0;
            KeepTail(Frame.AsSpan(_length - 3, 3));
            _length = 0;
            _scanStart = 0;
        }

        return consumedAny;
    }

    private void KeepTail(ReadOnlySpan<byte> data) => KeepTailConcat([], data);

    /// <summary>
    /// Holds the last (at most) three bytes of the logical concatenation of
    /// <paramref name="held"/> and <paramref name="fresh"/> — the cross-chunk memory of a
    /// skipped event. Callers pass a stack copy when <paramref name="held"/> aliases
    /// <see cref="_tail"/>.
    /// </summary>
    private void KeepTailConcat(ReadOnlySpan<byte> held, ReadOnlySpan<byte> fresh)
    {
        var total = held.Length + fresh.Length;
        var take = Math.Min(3, total);
        for (var i = 0; i < take; i++)
        {
            var at = total - take + i;
            _tail[i] = at < held.Length ? held[at] : fresh[at - held.Length];
        }

        _tailLength = take;
    }

    /// <summary>
    /// Finds the first event terminator in the concatenation of <paramref name="tail"/>
    /// and <paramref name="rest"/>, without materialising the concatenation.
    /// <paramref name="boundaryStart"/> is its offset in that concatenation and
    /// <paramref name="boundaryLength"/> its length.
    /// </summary>
    private static bool TryFindBoundary(
        ReadOnlySpan<byte> tail,
        ReadOnlySpan<byte> rest,
        out int boundaryStart,
        out int boundaryLength)
    {
        var total = tail.Length + rest.Length;
        for (var i = 0; i + 1 < total; i++)
        {
            var length = BoundaryLengthAt(i, tail, rest, total);
            if (length > 0)
            {
                boundaryStart = i;
                boundaryLength = length;
                return true;
            }
        }

        boundaryStart = 0;
        boundaryLength = 0;
        return false;
    }

    private static byte ByteAt(int i, ReadOnlySpan<byte> tail, ReadOnlySpan<byte> rest) =>
        i < tail.Length ? tail[i] : rest[i - tail.Length];

    private static int BoundaryLengthAt(int i, ReadOnlySpan<byte> tail, ReadOnlySpan<byte> rest, int total)
    {
        // Line terminators: \n, \r\n, \r. An event boundary is two consecutive terminators.
        // (No local named b, nor any identifier one byte before a quote: `x'…'` would lex
        // as identifier + char, not byte literal.)
        var first = ByteAt(i, tail, rest);
        var second = ByteAt(i + 1, tail, rest);
        if (first == (byte)'\n')
        {
            if (second == (byte)'\n')
            {
                return 2;
            }

            if (second == (byte)'\r' && i + 2 < total && ByteAt(i + 2, tail, rest) == (byte)'\n')
            {
                return 3;
            }
        }
        else if (first == (byte)'\r')
        {
            if (second == (byte)'\r')
            {
                return 2;
            }

            if (second == (byte)'\n' && i + 2 < total)
            {
                if (ByteAt(i + 2, tail, rest) == (byte)'\n')
                {
                    return 3; // \r\n then \n
                }

                if (ByteAt(i + 2, tail, rest) == (byte)'\r' && i + 3 < total && ByteAt(i + 3, tail, rest) == (byte)'\n')
                {
                    return 4; // \r\n then \r\n
                }
            }
        }

        return 0;
    }

    private static int IndexOfBoundary(ReadOnlySpan<byte> data)
    {
        for (var i = 0; i + 1 < data.Length; i++)
        {
            if (BoundaryLengthAt(i, [], data, data.Length) > 0)
            {
                return i;
            }
        }

        return -1;
    }

    private static int BoundaryLength(ReadOnlySpan<byte> at, int available) =>
        BoundaryLengthAt(0, [], at, Math.Min(available, at.Length));

    private void ObserveEvent(ReadOnlySpan<byte> eventBytes)
    {
        var position = 0;
        while (position < eventBytes.Length)
        {
            var lineEnd = eventBytes[position..].IndexOf((byte)'\n');
            var line = lineEnd < 0 ? eventBytes[position..] : eventBytes.Slice(position, lineEnd);
            position += lineEnd < 0 ? eventBytes.Length : lineEnd + 1;
            if (line.Length == 0 || line[0] == (byte)'#')
            {
                continue;
            }

            if (line[^1] == (byte)'\r')
            {
                line = line[..^1];
            }

            var colon = line.IndexOf((byte)':');
            if (colon < 0 || !line[..colon].SequenceEqual("data"u8))
            {
                continue;
            }

            var payload = line[(colon + 1)..];
            if (payload.Length > 0 && payload[0] == (byte)' ')
            {
                payload = payload[1..];
            }

            if (payload.Length > 0)
            {
                TryReadUsage(payload);
            }
        }
    }

    private void TryReadUsage(ReadOnlySpan<byte> payload)
    {
        JsonDocument document;
        try
        {
            // byte[] binding: this surface's Parse takes sequences, not spans. The event is
            // copied once here; bounded by the leg's per-event cap.
            document = JsonDocument.Parse(payload.ToArray());
        }
        catch (JsonException)
        {
            return; // not JSON (or malformed): unmetered, forward-only
        }

        using (document)
        {
            // M50 fold LOW-2: only the documented shape is trusted — usage is top-level on
            // message_delta and nested under "message" on message_start. A "usage" object
            // anywhere else (a tool result, a nested content block, an unrelated event type)
            // is not the provider's report and is ignored, the same stance the JSON reader
            // takes by gating on root depth.
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("type", out var type)
                || type.ValueKind != JsonValueKind.String)
            {
                return;
            }

            JsonElement usage;
            if (type.ValueEquals("message_delta"u8))
            {
                if (!root.TryGetProperty("usage", out usage))
                {
                    return;
                }
            }
            else if (type.ValueEquals("message_start"u8))
            {
                if (!root.TryGetProperty("message", out var message)
                    || message.ValueKind != JsonValueKind.Object
                    || !message.TryGetProperty("usage", out usage))
                {
                    return;
                }
            }
            else
            {
                return; // any other event type carries no usage the proxy may trust
            }

            if (usage.ValueKind == JsonValueKind.Object)
            {
                ApplyUsage(usage);
            }
        }
    }

    private void ApplyUsage(JsonElement usage)
    {
        // A non-positive count is not a report: the field stays as it was (null when never
        // reported), the stance the counter descriptions advertise. A hostile or buggy
        // vendor body must never drive a monotonic counter down.
        if (usage.TryGetProperty("input_tokens", out var input)
            && input.TryGetInt64(out var inputTokens)
            && inputTokens > 0)
        {
            InputTokens = inputTokens;
        }

        // message_delta reports output usage cumulatively: the last positive value seen is
        // final, and a zero or negative that arrives later does not overwrite one.
        if (usage.TryGetProperty("output_tokens", out var output)
            && output.TryGetInt64(out var outputTokens)
            && outputTokens > 0)
        {
            OutputTokens = outputTokens;
        }
    }
}
