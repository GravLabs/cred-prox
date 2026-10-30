namespace CredProx;

/// <summary>
/// A write-only passthrough over the real response body stream that counts the bytes
/// written through it — the audit record's <c>bytes</c> field. Installed by
/// <see cref="CredProxAuditRecorder"/> via <c>HttpResponse.Body</c> so both response
/// writers (the problem-response path and YARP's forwarder copy) flow through it.
/// Disposal is a no-op: the inner stream belongs to ASP.NET Core.
/// </summary>
internal sealed class CountingResponseBodyStream(Stream inner) : Stream
{
    private long _bytesWritten;

    /// <summary>Bytes written so far.</summary>
    public long BytesWritten => Interlocked.Read(ref _bytesWritten);

    public override bool CanRead => false;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush() => inner.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) =>
        inner.FlushAsync(cancellationToken);

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count)
    {
        inner.Write(buffer, offset, count);
        Interlocked.Add(ref _bytesWritten, count);
    }

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        inner.Write(buffer);
        Interlocked.Add(ref _bytesWritten, buffer.Length);
    }

    public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        await inner.WriteAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
        Interlocked.Add(ref _bytesWritten, count);
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        await inner.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
        Interlocked.Add(ref _bytesWritten, buffer.Length);
    }

    public override void WriteByte(byte value)
    {
        inner.WriteByte(value);
        Interlocked.Add(ref _bytesWritten, 1);
    }

    // The inner stream belongs to ASP.NET Core; this wrapper is not its owner.
    protected override void Dispose(bool disposing)
    {
    }

    public override ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
