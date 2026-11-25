namespace CredProx;

/// <summary>
/// Byte-preserving usage peek over the upstream content stream (M50, ADR-0008): every byte
/// is handed to the reader exactly once, in order, while a copy of the same chunk is fed to
/// an <see cref="IUsageReader"/> within the leg's parse window. The reader never holds the
/// caller's bytes — the wrapper withholds nothing for parsing — and a reader failure or an
/// exhausted window degrades to unmetered, never to a refusal or a stall. Content framing
/// survives too: the forwarded byte count is unchanged, so the headers copied onto the
/// replacement content (including <c>Content-Length</c>) stay honest — unlike the
/// scrubber's replacement, which changes bytes and drops the framing.
/// </summary>
/// <remarks>
/// The wrapper owns and disposes the inner stream (the replaced <c>StreamContent</c> is
/// dropped without disposal, the scrubber's ownership rule). A zero-length read with a
/// non-empty destination is EOF; a zero-length destination (a probe read) is not.
/// </remarks>
internal sealed class UsagePeekStream(Stream inner, IUsageReader reader, long maxParseBytes) : Stream
{
    private readonly Stream _inner = inner ?? throw new ArgumentNullException(nameof(inner));
    private readonly IUsageReader _reader = reader ?? throw new ArgumentNullException(nameof(reader));
    private long _parseBudget = maxParseBytes;
    private bool _feeding = true;
    private bool _completed;

    public override bool CanRead => _inner.CanRead;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => _inner.Length;
    public override long Position
    {
        get => _inner.Position;
        set => _inner.Position = value;
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        var read = _inner.Read(buffer, offset, count);
        Feed(buffer.AsSpan(offset, count).Slice(0, read), endOfStream: read == 0 && count > 0);
        return read;
    }

    public override int Read(Span<byte> destination)
    {
        var read = _inner.Read(destination);
        Feed(destination.Slice(0, read), endOfStream: read == 0 && !destination.IsEmpty);
        return read;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> destination, CancellationToken cancellationToken = default)
    {
        var read = await _inner.ReadAsync(destination, cancellationToken).ConfigureAwait(false);
        Feed(destination.Span.Slice(0, read), endOfStream: read == 0 && !destination.IsEmpty);
        return read;
    }

    public override void Flush() => _inner.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

    public override long Seek(long offset, SeekOrigin origin) => _inner.Seek(offset, origin);

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override void Write(ReadOnlySpan<byte> buffer) => throw new NotSupportedException();

    public override void WriteByte(byte value) => throw new NotSupportedException();

    /// <summary>
    /// Hands the chunk (or its in-window prefix) to the reader. The caller's bytes were
    /// already delivered before this runs; every reader failure ends feeding quietly.
    /// </summary>
    private void Feed(ReadOnlySpan<byte> chunk, bool endOfStream)
    {
        if (!_feeding)
        {
            return;
        }

        try
        {
            if (_parseBudget <= 0)
            {
                // The window is exhausted: usage past it is unmetered. Forwarding never depends on this.
                _feeding = false;
                return;
            }

            if (chunk.Length == 0)
            {
                if (endOfStream && !_completed)
                {
                    _completed = true;
                    _feeding = false;
                    _reader.Observe([], endOfStream: true);
                }

                return;
            }

            var fed = chunk.Length <= _parseBudget ? chunk : chunk[..(int)_parseBudget];
            _parseBudget -= fed.Length;
            _reader.Observe(fed, endOfStream: false);
            if (fed.Length < chunk.Length)
            {
                // Truncated at the window edge: no further chunks are parsed, whatever the
                // reader holds so far stays as it is (a partially-read token never completes).
                _feeding = false;
            }
        }
        catch (Exception)
        {
            // Metering failure never changes the caller's bytes; the response counts unmetered.
            _feeding = false;
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_completed)
        {
            // An early dispose (abort, cancellation, client disconnect) is still the reader's
            // last observation: what it read so far stands, what it did not read is unmetered.
            _completed = true;
            SafeComplete();
        }

        if (disposing)
        {
            try
            {
                _inner.Dispose();
            }
            catch (Exception)
            {
                // LOW-1 on the M50 follow-ups verdict: the shipped wrapper (StreamContent over
                // this stream, CredProxMeteringResponseFeature) tears the vendor stream down
                // through THIS arm, so an unguarded throw here reaches the caller as a
                // content-copy failure. The record was already made above (SafeComplete) and
                // the caller already has its bytes — same swallow discipline as DisposeAsync:
                // a metering fault never reaches the caller, and base disposal still runs.
            }
        }

        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        if (!_completed)
        {
            _completed = true;
            SafeComplete();
        }

        try
        {
            await _inner.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception)
        {
            // M50 live-verdict OPEN: the record was already made above (SafeComplete) and
            // the caller already has its bytes — a vendor-stream disposal failure must not
            // escape into the response-completion path, and must not skip the base
            // disposal. Same swallow discipline as SafeComplete: a metering fault never
            // reaches the caller.
        }

        await base.DisposeAsync().ConfigureAwait(false);
    }

    private void SafeComplete()
    {
        try
        {
            if (_feeding)
            {
                _feeding = false;
                _reader.Observe([], endOfStream: true);
            }
        }
        catch (Exception)
        {
            // As in Feed: a reader that fails at completion changes nothing on the wire.
        }
    }
}
