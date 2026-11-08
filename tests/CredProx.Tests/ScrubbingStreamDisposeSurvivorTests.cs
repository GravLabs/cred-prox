using System.Text;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage of the scrubbing streams' dispose wiring and the emit-window
/// boundary: <c>DisposeAsync</c> must hand the async dispose to the inner stream (the
/// pipeline disposes the view asynchronously, and the vendor response stream behind it is
/// async-only), and a first read that lands exactly on the hold-back boundary must keep
/// pulling upstream rather than reporting the body as finished.
/// </summary>
public sealed class ScrubbingStreamDisposeSurvivorTests
{
    /// <summary>Serves the queued chunks verbatim (one per read), then EOF, and records
    /// how it was disposed.</summary>
    private sealed class ChunkedInnerStream : Stream
    {
        private readonly Queue<byte[]> _chunks;

        public ChunkedInnerStream(params string[] chunks) =>
            _chunks = new Queue<byte[]>(chunks.Select(Encoding.UTF8.GetBytes).ToArray());

        public bool SyncDisposed { get; private set; }

        public bool AsyncDisposed { get; private set; }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> destination)
        {
            if (_chunks.Count == 0)
            {
                return 0;
            }

            var chunk = _chunks.Dequeue();
            var n = Math.Min(chunk.Length, destination.Length);
            chunk.AsSpan(0, n).CopyTo(destination);
            if (n < chunk.Length)
            {
                _chunks.Enqueue(chunk.AsMemory(n).ToArray());
            }

            return n;
        }

        public override ValueTask<int> ReadAsync(Memory<byte> destination, CancellationToken cancellationToken = default) =>
            new(Read(destination.Span));

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            SyncDisposed = true;
            base.Dispose(disposing);
        }

        public override ValueTask DisposeAsync()
        {
            AsyncDisposed = true;
            return ValueTask.CompletedTask;
        }
    }

    [Fact]
    public async Task ScrubbingStream_DisposeAsync_DisposesTheInnerStream()
    {
        var inner = new ChunkedInnerStream();
        await using var view = new ScrubbingStream(inner, ["s3cret"]);

        Assert.False(inner.AsyncDisposed); // not before the view is disposed
        await view.DisposeAsync();

        Assert.True(inner.AsyncDisposed); // the vendor stream behind the view is closed too
    }

    [Fact]
    public async Task EventScrubbingStream_DisposeAsync_DisposesTheInnerStream()
    {
        var inner = new ChunkedInnerStream();
        await using var view = new EventScrubbingStream(inner, ["s3cret"]);

        Assert.False(inner.AsyncDisposed);
        await view.DisposeAsync();

        Assert.True(inner.AsyncDisposed);
    }

    [Fact]
    public async Task ScrubbingStream_FirstChunkExactlyAtTheHoldbackBoundary_KeepsReading()
    {
        // "Xs3cr" is exactly maxPatternLength-1 hold-back long against the 6-byte secret:
        // there is nothing safe to emit yet, so the view must pull the rest rather than
        // end the body here. A secret split across the boundary still comes out redacted.
        var inner = new ChunkedInnerStream("Xs3cr", "et-end");
        await using var view = new ScrubbingStream(inner, ["s3cret"]);

        var buffer = new byte[64];
        var emitted = new MemoryStream();
        int n;
        while ((n = await view.ReadAsync(buffer.AsMemory())) > 0)
        {
            emitted.Write(buffer, 0, n);
        }

        Assert.Equal("X[redacted]-end", Encoding.UTF8.GetString(emitted.ToArray()));
    }
}
