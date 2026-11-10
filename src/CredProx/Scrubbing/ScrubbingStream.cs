using System.Buffers;

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
    private readonly ArrayPool<byte> _pool;
    private readonly byte[][] _patterns; // UTF-8 bytes, non-empty, longest first
    private readonly byte[] _replacement;
    private readonly int _maxPatternLength;

    // Pooled; ever-held RAW (unscrubbed) response bytes — must return clearArray: true.
    private byte[] _pending;
    private int _pendingCapacity; // logical capacity: the pool bucket may be larger
    private int _pendingLength;
    private int _pendingReturned; // Interlocked once-claim: the pending pool.Return runs at most once
    private int _disposed; // set once at dispose; fail-closed for new and resumed reads
    private int _readersInFlight; // reservations covering reads whose destination is _pending
    private byte[]? _output;
    private int _outputPosition;
    private int _outputLength;
    private bool _innerEof;

    public ScrubbingStream(Stream inner, IReadOnlyList<string> secrets, ArrayPool<byte>? pool = null)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(secrets);

        _inner = inner;
        _pool = pool ?? ArrayPool<byte>.Shared;
        _patterns = SecretScrubber.CompilePatterns(secrets);
        _replacement = SecretScrubber.Replacement;
        _maxPatternLength = _patterns.Length == 0 ? 0 : _patterns[0].Length;
        _pending = _pool.Rent(2 * ChunkSize);
        _pendingCapacity = 2 * ChunkSize;
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
            ReturnLiveBatch();
            _inner.Dispose();
        }

        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        ReturnLiveBatch();
        await _inner.DisposeAsync().ConfigureAwait(false);
        await base.DisposeAsync().ConfigureAwait(false);
    }

    /// <summary>
    /// Returns the live buffers — the never-fully-drained batch (abort, cancellation,
    /// early dispose) and the pending buffer — to the pool. Exchange guards make the
    /// returns happen exactly once even if both Dispose overloads run; a drained batch
    /// is already gone via <see cref="CopyOutput"/>. Both clear on return: either may
    /// have held secret bytes. The pending return transfers ownership instead of
    /// racing a parked read: see <see cref="ReturnPendingIfIdle"/>.
    /// </summary>
    private void ReturnLiveBatch()
    {
        // Publish dispose before reading the counter. The increment-then-check in
        // ProduceAsync and this set-then-read form an exclusion handshake: either a
        // reader sees the dispose and abandons its reservation untouched, or dispose
        // sees the reader and defers the pending return to that reader's finally.
        Interlocked.Exchange(ref _disposed, 1);

        ReturnOutputIfIdle();
        ReturnPendingIfIdle();

        _outputPosition = 0;
        _outputLength = 0;
    }

    /// <summary>
    /// R1: the batch slot gets the same ownership transfer as the pending buffer.
    /// A reader inside <see cref="CopyOutput"/> holds a reservation and is indexing
    /// the live batch; returning it now would let a re-rent hand this request's
    /// (redacted) bytes to another owner mid-copy. Dispose takes the batch only
    /// while idle; otherwise the last reader's finally does. The winning
    /// <c>Exchange</c> is itself the once-claim for the batch instance — mirrors
    /// <see cref="CopyOutput"/>'s drain return, so no second flag — and a disposed
    /// stream never refills the slot.
    /// </summary>
    private void ReturnOutputIfIdle()
    {
        if (Interlocked.CompareExchange(ref _readersInFlight, 0, 0) == 0)
        {
            var batch = Interlocked.Exchange(ref _output, null);
            if (batch != null)
            {
                _pool.Return(batch, clearArray: true);
            }
        }
    }

    /// <summary>
    /// Returns the pending buffer once, and only while no read is in flight: a
    /// parked <c>_inner.ReadAsync</c> is still free to write RAW response bytes into
    /// it, and a pool-owned array must never have a second writer (hazard 2). When a
    /// reader holds a reservation, the return transfers to its finally — the last
    /// reader out performs the single cleared return.
    /// </summary>
    private void ReturnPendingIfIdle()
    {
        if (Interlocked.CompareExchange(ref _readersInFlight, 0, 0) == 0
            && Interlocked.Exchange(ref _pendingReturned, 1) == 0)
        {
            _pool.Return(_pending, clearArray: true);
        }
    }

    private async ValueTask<int> ProduceAsync(Memory<byte> destination, CancellationToken cancellationToken)
    {
        // Take the read reservation first, then check disposed — the Interlocked
        // pair with ReturnLiveBatch excludes the interleaving where this read is
        // issued into _pending after dispose already returned it. A read after
        // dispose must not touch the buffers: they are back in a pool that may
        // already hand them to another request. Fail as the base Stream does,
        // before any probe or pass-through semantics.
        Interlocked.Increment(ref _readersInFlight);
        try
        {
            if (Interlocked.CompareExchange(ref _disposed, 0, 0) != 0)
            {
                throw new ObjectDisposedException(nameof(ScrubbingStream));
            }

            if (destination.IsEmpty)
            {
                return 0;
            }

            // Defensive: with nothing to remove, pass bytes straight through. The
            // pipeline gates on a non-empty registry, so this path should never run.
            if (_patterns.Length == 0)
            {
                return await _inner.ReadAsync(destination, cancellationToken).ConfigureAwait(false);
            }

            while (true)
            {
                ThrowIfDisposed();

                if (_outputPosition < _outputLength)
                {
                    return CopyOutput(destination.Span);
                }

                if (_pendingLength == 0 && _innerEof)
                {
                    return 0; // everything read, everything emitted
                }

                await FillPendingAsync(cancellationToken).ConfigureAwait(false);

                // Dispose landed while the fill was parked: the bytes this inner read
                // wrote live in a buffer whose return dispose deferred to this
                // reader's finally. Never emit them — fail closed instead.
                ThrowIfDisposed();

                // Hold back the tail that could still complete a match started before
                // the emit boundary; at EOF there is nothing more coming, so emit it
                // all.
                var holdback = _innerEof ? 0 : _maxPatternLength - 1;
                var emitLength = _pendingLength - holdback;
                if (emitLength <= 0)
                {
                    continue;
                }

                BuildOutputBatch(emitLength);
            }
        }
        finally
        {
            // Last reader out after dispose performs the deferred, single, cleared
            // returns (ownership transfer — hazard 2 and R1). Both buffers are
            // cleared on the way out, which is the discard.
            if (Interlocked.Decrement(ref _readersInFlight) == 0
                && Interlocked.CompareExchange(ref _disposed, 0, 0) != 0)
            {
                if (Interlocked.Exchange(ref _pendingReturned, 1) == 0)
                {
                    _pool.Return(_pending, clearArray: true);
                }

                var batch = Interlocked.Exchange(ref _output, null);
                if (batch != null)
                {
                    _pool.Return(batch, clearArray: true);
                }
            }
        }
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(ScrubbingStream));
        }
    }

    private async ValueTask FillPendingAsync(CancellationToken cancellationToken)
    {
        if (_innerEof)
        {
            return;
        }

        if (_pendingCapacity - _pendingLength < ChunkSize)
        {
            GrowPending();
        }

        var read = await _inner
            .ReadAsync(_pending.AsMemory(_pendingLength, _pendingCapacity - _pendingLength), cancellationToken)
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
    /// Grows pending by rent-copy: the new logical capacity equals what
    /// <c>Array.Resize</c> used to set, so fill pacing and holdback timing are
    /// unchanged even though the pool bucket may be larger. The old buffer held
    /// RAW bytes — cleared on return (hazard: pooled secrets cross requests).
    /// Runs only while this caller's read reservation is held, so a racing
    /// dispose defers its pending return: the old-buffer return below can never
    /// double-return against dispose.
    /// </summary>
    private void GrowPending()
    {
        var newCapacity = _pendingLength + (2 * ChunkSize);
        var grown = _pool.Rent(newCapacity);
        Buffer.BlockCopy(_pending, 0, grown, 0, _pendingLength);
        _pool.Return(_pending, clearArray: true);
        _pending = grown;
        _pendingCapacity = newCapacity;
    }

    private void BuildOutputBatch(int emitLength)
    {
        var (batch, batchLength, consumedThrough) =
            SecretScrubber.ScrubBatch(_pending.AsSpan(0, _pendingLength), emitLength, _patterns, _replacement, _pool);

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
        // R1: snapshot the slot under this reader's reservation. Dispose may land
        // mid-call and reset position/length while deferring the batch return to
        // us — the copy must never index with values reset under it, and a reader
        // resuming into a disposed stream copies nothing.
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(ScrubbingStream));
        }

        var output = Volatile.Read(ref _output);
        if (output == null)
        {
            // Only a concurrent dispose can null the live batch here; the contract
            // says ObjectDisposedException, not NullReferenceException.
            throw new ObjectDisposedException(nameof(ScrubbingStream));
        }

        var position = Volatile.Read(ref _outputPosition);
        var length = Volatile.Read(ref _outputLength);
        if (position > length)
        {
            // Inverted only by a dispose reset landing between the two reads:
            // fail closed rather than index with a negative count.
            throw new ObjectDisposedException(nameof(ScrubbingStream));
        }

        var count = Math.Min(length - position, destination.Length);
        output.AsSpan(position, count).CopyTo(destination);
        _outputPosition = position + count;
        if (_outputPosition == length)
        {
            // Batch fully copied out: returned cleared (it carried response bytes).
            // Exchange-first so a racing dispose cannot double-return.
            var finished = Interlocked.Exchange(ref _output, null);
            if (finished != null)
            {
                _pool.Return(finished, clearArray: true);
            }

            _outputPosition = 0;
            _outputLength = 0;
        }

        return count;
    }
}
