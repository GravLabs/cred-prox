namespace CredProx;

/// <summary>
/// The <c>text/event-stream</c> framing of response scrubbing (M22, plan §8.2): bytes
/// flow out as each complete SSE event (<c>␊␊</c> / <c>␍␊␍␊</c> and the other
/// spec line-terminator spellings) is available, with every registered secret inside
/// the event replaced by <c>[redacted]</c>. This keeps streaming latency — the matcher
/// never holds an event back waiting for bytes that will only arrive with the next one
/// (the E13 SSE timing guarantee) — while still removing credentials an upstream
/// reflects inside an event.
/// </summary>
/// <remarks>
/// <para>
/// The price of the framing is documented: a secret split <em>across an event
/// boundary</em> is not caught — each event is matched on its own bytes, so the
/// half-patterns in neighbouring events stay byte-identical. Within one event the
/// matching is exact bytes over the UTF-8 encodings of the registered values, longest
/// match first, exactly like <see cref="ScrubbingStream"/>.
/// </para>
/// <para>
/// A single event larger than <see cref="MaxEventBufferBytes"/> (a pathological
/// upstream that never terminates an event) degrades safely to byte-stream semantics:
/// everything up to the hold-back tail — bytes that can no longer begin a match — is
/// scrubbed and emitted, and buffering continues. Memory is therefore bounded by the
/// cap plus one chunk, never by the stream.
/// </para>
/// </remarks>
internal sealed class EventScrubbingStream : Stream
{
    internal const int MaxEventBufferBytes = 64 * 1024;

    private const int ChunkSize = 16 * 1024;

    private readonly Stream _inner;
    private readonly byte[][] _patterns; // UTF-8 bytes, non-empty, longest first
    private readonly byte[] _replacement;
    private readonly int _maxPatternLength;

    private byte[] _pending = new byte[2 * ChunkSize];
    private int _pendingLength;
    private int _searchStart; // delimiter search may resume here; earlier bytes hold no new boundary
    private byte[]? _output;
    private int _outputPosition;
    private int _outputLength;
    private bool _innerEof;

    public EventScrubbingStream(Stream inner, IReadOnlyList<string> secrets)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(secrets);

        _inner = inner;
        _patterns = SecretScrubber.CompilePatterns(secrets);
        _replacement = SecretScrubber.Replacement;
        _maxPatternLength = _patterns.Length == 0 ? 0 : _patterns[0].Length;
    }

    public override bool CanRead => _inner.CanRead;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count) =>
        Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> destination)
    {
        // The sync path exists for Stream consumers that never go async; the copy is
        // its cost (Span cannot alias the Memory the produce loop needs).
        var buffer = new byte[destination.Length];
        var read = ProduceAsync(buffer, CancellationToken.None).AsTask().GetAwaiter().GetResult();
        buffer.AsSpan(0, read).CopyTo(destination);
        return read;
    }

    public override ValueTask<int> ReadAsync(Memory<byte> destination, CancellationToken cancellationToken = default) =>
        ProduceAsync(destination, cancellationToken);

    public override void Flush()
    {
        // A read view over the upstream stream: nothing to flush.
    }

    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override void Write(ReadOnlySpan<byte> buffer) => throw new NotSupportedException();

    public override void WriteByte(byte value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _inner.Dispose();
        }

        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        await _inner.DisposeAsync().ConfigureAwait(false);
        await base.DisposeAsync().ConfigureAwait(false);
    }

    private async ValueTask<int> ProduceAsync(Memory<byte> destination, CancellationToken cancellationToken)
    {
        if (destination.IsEmpty)
        {
            return 0;
        }

        // Defensive: with nothing to remove, pass bytes straight through. The pipeline
        // gates on a non-empty registry, so this path should never run.
        if (_patterns.Length == 0)
        {
            return await _inner.ReadAsync(destination, cancellationToken).ConfigureAwait(false);
        }

        while (true)
        {
            if (_outputPosition < _outputLength)
            {
                return CopyOutput(destination.Span);
            }

            if (_pendingLength == 0 && _innerEof)
            {
                return 0; // everything read, everything emitted
            }

            // Complete event at the head of the buffer? The event bytes — boundary
            // included — are scrubbed as a unit and emitted as soon as they are whole.
            var eventEnd = FindEventBoundary(_pending.AsSpan(0, _pendingLength), _searchStart);
            if (eventEnd > 0)
            {
                EmitBatch(eventEnd, eventEnd);
                continue;
            }

            if (_innerEof)
            {
                // No boundary is coming: the remainder is the final (unterminated)
                // event — scrub and flush it.
                EmitBatch(_pendingLength, _pendingLength);
                continue;
            }

            var before = _pendingLength;
            await FillPendingAsync(cancellationToken).ConfigureAwait(false);

            // A boundary's last byte may have landed in this fill while its first bytes
            // are already buffered — resume the search from the previous fill's tail.
            _searchStart = Math.Max(0, before - 3);

            // Pathological upstream: an event that never terminates. Emit what can no
            // longer begin a match (byte-stream hold-back semantics) and keep going —
            // memory stays bounded by the cap plus one chunk.
            if (!_innerEof && _pendingLength > MaxEventBufferBytes)
            {
                var safeEmit = _pendingLength - Math.Max(0, _maxPatternLength - 1);
                if (safeEmit > 0)
                {
                    EmitBatch(safeEmit, _pendingLength);
                }
            }
        }
    }

    private async ValueTask FillPendingAsync(CancellationToken cancellationToken)
    {
        if (_innerEof)
        {
            return;
        }

        if (_pending.Length - _pendingLength < ChunkSize)
        {
            Array.Resize(ref _pending, _pendingLength + (2 * ChunkSize));
        }

        var read = await _inner
            .ReadAsync(_pending.AsMemory(_pendingLength, _pending.Length - _pendingLength), cancellationToken)
            .ConfigureAwait(false);
        if (read == 0)
        {
            _innerEof = true;
        }
        else
        {
            _pendingLength += read;
        }
    }

    /// <summary>
    /// Scrubs <c>pending[0..emitLength]</c> into the output buffer — matches that are
    /// fully present in <c>pending[0..lookAheadTo]</c> and start before the boundary
    /// consume their tail (the cap-degradation case). The pending buffer keeps
    /// everything past the consumed offset.
    /// </summary>
    private void EmitBatch(int emitLength, int lookAheadTo)
    {
        var (batch, batchLength, consumedThrough) = SecretScrubber.ScrubBatch(
            _pending.AsSpan(0, lookAheadTo), emitLength, _patterns, _replacement);

        _output = batch;
        _outputPosition = 0;
        _outputLength = batchLength;

        var remaining = _pendingLength - consumedThrough;
        if (remaining > 0)
        {
            _pending.AsSpan(consumedThrough, remaining).CopyTo(_pending);
        }

        _pendingLength = remaining;
        _searchStart = 0;
    }

    /// <summary>
    /// Offset just past a blank-line event boundary at or after <paramref name="start"/>,
    /// or <c>-1</c> when none is complete yet. <c>␊</c> and <c>␍</c> never occur inside a
    /// multi-byte UTF-8 sequence, so scanning raw bytes is safe across read boundaries.
    /// Recognised spellings: <c>␊␊</c>, <c>␊␍␊</c>, <c>␍␊␍␊</c>, <c>␍␍␊</c>.
    /// </summary>
    private static int FindEventBoundary(ReadOnlySpan<byte> buffer, int start)
    {
        for (var i = Math.Max(0, start); i < buffer.Length; i++)
        {
            switch (buffer[i])
            {
                case (byte)'\n':
                    if (i + 1 < buffer.Length && buffer[i + 1] == (byte)'\n')
                    {
                        return i + 2;
                    }

                    if (i + 2 < buffer.Length && buffer[i + 1] == (byte)'\r' && buffer[i + 2] == (byte)'\n')
                    {
                        return i + 3;
                    }

                    break;

                case (byte)'\r':
                    if (i + 3 < buffer.Length
                        && buffer[i + 1] == (byte)'\n' && buffer[i + 2] == (byte)'\r' && buffer[i + 3] == (byte)'\n')
                    {
                        return i + 4;
                    }

                    if (i + 2 < buffer.Length && buffer[i + 1] == (byte)'\r' && buffer[i + 2] == (byte)'\n')
                    {
                        return i + 3;
                    }

                    break;
            }
        }

        return -1;
    }

    private int CopyOutput(Span<byte> destination)
    {
        var count = Math.Min(_outputLength - _outputPosition, destination.Length);
        _output!.AsSpan(_outputPosition, count).CopyTo(destination);
        _outputPosition += count;
        if (_outputPosition == _outputLength)
        {
            _output = null;
            _outputPosition = 0;
            _outputLength = 0;
        }

        return count;
    }
}
