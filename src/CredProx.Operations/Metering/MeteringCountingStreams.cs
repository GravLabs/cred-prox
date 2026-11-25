namespace CredProx;

/// <summary>
/// Counts the bytes a read-view stream hands out (M50): the metering request feature wraps
/// the outbound content with this so the counter observes exactly what the forwarder sends
/// upstream. Every byte is forwarded as-is; counting is the only addition. Disposal owns
/// the inner stream (the replaced <c>StreamContent</c> nobody else disposes).
/// </summary>
internal sealed class CountingReadStream(Stream inner) : Stream
{
    private readonly Stream _inner = inner ?? throw new ArgumentNullException(nameof(inner));

    /// <summary>Bytes handed to the reader so far.</summary>
    public long BytesRead { get; private set; }

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
        BytesRead += read;
        return read;
    }

    public override int Read(Span<byte> destination)
    {
        var read = _inner.Read(destination);
        BytesRead += read;
        return read;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> destination, CancellationToken cancellationToken = default)
    {
        var read = await _inner.ReadAsync(destination, cancellationToken).ConfigureAwait(false);
        BytesRead += read;
        return read;
    }

    public override void Flush() => _inner.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

    public override long Seek(long offset, SeekOrigin origin) => _inner.Seek(offset, origin);

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override void Write(ReadOnlySpan<byte> buffer) => throw new NotSupportedException();

    public override void WriteByte(byte value) => throw new NotSupportedException();

    // The inner disposal is deliberately UNGUARDED here, unlike the UsagePeekStream
    // swallows (m50-low1 finding 3, lead ruling): this counter wraps the response body in
    // the REQUEST direction - the forwarder owns that stream's disposal, and a throw
    // arrives while the response pipeline is still completing, where it is the
    // pipeline's real error to see. A swallow would only hide an egress bug. The
    // vendor-side (response-reading) teardown is the opposite case and does swallow.
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
        // Same ruling as the sync arm above: unguarded on purpose.
        await _inner.DisposeAsync().ConfigureAwait(false);
        await base.DisposeAsync().ConfigureAwait(false);
    }
}

/// <summary>
/// Counts the bytes written into it (M50): the metering response feature installs this as
/// <c>context.Response.Body</c>, so the counter observes exactly what reached the caller.
/// Every byte is forwarded to the original body as-is. The original body stays
/// server-owned: this wrapper never disposes it (the audit recorder's body wrap follows the
/// same ownership).
/// </summary>
internal sealed class CountingWriteStream(Stream inner) : Stream
{
    private readonly Stream _inner = inner ?? throw new ArgumentNullException(nameof(inner));

    /// <summary>Bytes accepted for the caller so far.</summary>
    public long BytesWritten { get; private set; }

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => _inner.CanWrite;
    public override long Length => throw new NotSupportedException();
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        _inner.Write(buffer, offset, count);
        BytesWritten += count;
    }

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        _inner.Write(buffer);
        BytesWritten += buffer.Length;
    }

    public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        await _inner.WriteAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
        BytesWritten += count;
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        await _inner.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
        BytesWritten += buffer.Length;
    }

    public override void Flush() => _inner.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();
}
