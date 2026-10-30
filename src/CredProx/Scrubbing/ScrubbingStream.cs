namespace CredProx;

/// <summary>
/// A read stream that removes every occurrence of the request's injected secret values
/// from the bytes flowing through it, replacing each with <c>[redacted]</c>
/// (<see cref="AuditRedactor.Masked"/>; M20, plan §8.2).
/// </summary>
/// <remarks>
/// <para>
/// Streaming-aware by construction: at most one read chunk plus the longest secret and
/// the current output batch are held — never the whole body. A match split across read
/// boundaries is still found: the last (longest secret − 1) bytes are held back until
/// the next fill, because no complete match can end before them.
/// </para>
/// <para>
/// Matching is exact bytes over UTF-8 encodings of the registered values — the registry
/// stores the raw and the URL-encoded form, nothing else is transformed here. Where two
/// patterns start at the same position the longest wins (patterns are tried longest
/// first); matches never overlap.
/// </para>
/// </remarks>
internal sealed class ScrubbingStream : Stream
{
    private const int ChunkSize = 16 * 1024;

    private readonly Stream _inner;
    private readonly byte[][] _patterns; // UTF-8 bytes, non-empty, longest first
    private readonly byte[] _replacement;
    private readonly int _maxPatternLength;

    private byte[] _pending = new byte[2 * ChunkSize];
    private int _pendingLength;
    private byte[]? _output;
    private int _outputPosition;
    private int _outputLength;
    private bool _innerEof;

    public ScrubbingStream(Stream inner, IReadOnlyList<string> secrets)
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

            await FillPendingAsync(cancellationToken).ConfigureAwait(false);

            // Hold back the tail that could still complete a match started before the
            // emit boundary; at EOF there is nothing more coming, so emit it all.
            var holdback = _innerEof ? 0 : _maxPatternLength - 1;
            var emitLength = _pendingLength - holdback;
            if (emitLength <= 0)
            {
                continue;
            }

            BuildOutputBatch(emitLength);
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

    private void BuildOutputBatch(int emitLength)
    {
        var (batch, batchLength, consumedThrough) =
            SecretScrubber.ScrubBatch(_pending.AsSpan(0, _pendingLength), emitLength, _patterns, _replacement);

        _output = batch;
        _outputPosition = 0;
        _outputLength = batchLength;

        // Keep only the still-held tail in the pending buffer.
        var remaining = _pendingLength - consumedThrough;
        if (remaining > 0)
        {
            _pending.AsSpan(consumedThrough, remaining).CopyTo(_pending);
        }

        _pendingLength = remaining;
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
