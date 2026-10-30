namespace CredProx;

/// <summary>
/// Replays a buffered prefix, then reads through the remainder of the underlying
/// stream. The error normaliser (M24) buffers a vendor error body up to its cap; when
/// the body turns out larger than declared, the untouched bytes are handed to the
/// caller through this stream so the "forward byte-identical" promise survives a
/// partially-read response.
/// </summary>
internal sealed class PrefixThenRestStream(byte[] prefix, Stream rest) : Stream
{
    private readonly MemoryStream _prefix = new(prefix, writable: false);
    private bool _prefixDrained;

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        // A zero-length read is a probe, not a consumption: it must return 0 without
        // advancing any state. (The forwarder's copy loop opens with one — treating it
        // as "prefix drained" would silently drop the buffered bytes.)
        if (count == 0)
        {
            return 0;
        }

        if (!_prefixDrained)
        {
            var read = _prefix.Read(buffer, offset, count);
            if (read > 0)
            {
                return read;
            }

            _prefixDrained = true;
        }

        return rest.Read(buffer, offset, count);
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        // Zero-length probe: 0 bytes, no state change (see the sync Read).
        if (buffer.IsEmpty)
        {
            return 0;
        }

        if (!_prefixDrained)
        {
            var read = await _prefix.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read > 0)
            {
                return read;
            }

            _prefixDrained = true;
        }

        return await rest.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
    }

    public override void Flush() => rest.Flush();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _prefix.Dispose();
            rest.Dispose();
        }

        base.Dispose(disposing);
    }
}
