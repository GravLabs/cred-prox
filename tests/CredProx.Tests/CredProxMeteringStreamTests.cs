using System.Net.Http;
using System.Text;
using CredProx;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// §5.2 (M50 row): the counting and peek stream units. Byte identity is the first
/// property of every one of these wrappers (a metering failure may change counts, never
/// caller bytes); the rest pins the ownership rules (read views own and dispose the
/// dropped content, the write view never disposes the server-owned body) and the peek's
/// EOF/finalization contract (zero-length probe is not EOF; one final observation, also
/// on an early dispose; failures degrade to unmetered).
/// </summary>
public sealed class CredProxMeteringStreamTests
{
    private static byte[] Bytes(string text) => Encoding.UTF8.GetBytes(text);

    /// <summary>Read-only inner stream that records disposal (the views' ownership witness).</summary>
    private sealed class RecordingReadStream : Stream
    {
        private readonly MemoryStream _inner;

        public RecordingReadStream(byte[] data) => _inner = new MemoryStream(data);

        public bool Disposed { get; private set; }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => _inner.Length;
        public override long Position { get => _inner.Position; set => _inner.Position = value; }
        public override void Flush() => _inner.Flush();
        public override long Seek(long offset, SeekOrigin origin) => _inner.Seek(offset, origin);
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
        public override int Read(Span<byte> destination) => _inner.Read(destination);

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                Disposed = true;
                _inner.Dispose();
            }

            base.Dispose(disposing);
        }

        public override ValueTask DisposeAsync()
        {
            Disposed = true;
            return _inner.DisposeAsync();
        }
    }

    /// <summary>Records what the peek hands it: every chunk, in order, plus the final flag.</summary>
    private sealed class RecordingUsageReader : IUsageReader
    {
        // These cells drive UsagePeekStream directly — selection never runs, so the
        // format name only has to be the reader's own honest one.
        public string Format => "recording";

        private readonly List<byte> _seen = [];
        private readonly Func<int, bool>? _throwAt;

        public RecordingUsageReader(Func<int, bool>? throwAt = null) => _throwAt = throwAt;

        public List<byte> Seen => _seen;
        public int Observations { get; private set; }
        public int FinalObservations { get; private set; }

        public long? InputTokens => null;
        public long? OutputTokens => null;

        public bool CanRead(string? mediaType) => true;

        public void Observe(ReadOnlySpan<byte> utf8Chunk, bool endOfStream)
        {
            var n = ++Observations;
            if (_throwAt is not null && _throwAt(n))
            {
                throw new InvalidOperationException("reader failure witness");
            }

            foreach (var b in utf8Chunk)
            {
                _seen.Add(b);
            }

            if (endOfStream)
            {
                FinalObservations++;
            }
        }
    }

    private static string Text(byte[] bytes) => Encoding.UTF8.GetString(bytes);

    // ---- CountingReadStream (request direction) ----

    [Fact]
    public void CountingRead_ByteIdentity_AndCountsOnlyActualBytes()
    {
        var payload = Bytes("The quick brown fox jumps over the lazy dog.");
        using var counting = new CountingReadStream(new MemoryStream(payload));
        var buffer = new byte[1024];
        var got = new List<byte>();
        int read;
        while ((read = counting.Read(buffer, 0, buffer.Length)) > 0)
        {
            got.AddRange(buffer[..read]);
        }

        Assert.Equal(payload, got.ToArray());
        Assert.Equal(payload.Length, counting.BytesRead); // not buffer.Length per read
    }

    [Fact]
    public async Task CountingRead_SpanAndAsyncPaths_BothCount()
    {
        var payload = Bytes("0123456789ABCDEFGH");
        await using var counting = new CountingReadStream(new MemoryStream(payload));
        var spanBuffer = new byte[10];
        var spanRead = counting.Read(spanBuffer.AsSpan());
        var asyncBuffer = new byte[100];
        var asyncRead = await counting.ReadAsync(asyncBuffer);

        Assert.Equal(10, spanRead);
        Assert.Equal(payload.Length - 10, asyncRead);
        Assert.Equal(payload.Length, counting.BytesRead);
        Assert.Equal("0123456789", Text(spanBuffer));
        Assert.Equal("ABCDEFGH", Text(asyncBuffer[..asyncRead]));
    }

    [Fact]
    public void CountingRead_ZeroLengthReadsAfterEnd_AddNothing()
    {
        var payload = Bytes("small");
        using var counting = new CountingReadStream(new MemoryStream(payload));
        var buffer = new byte[64];
        Assert.Equal(payload.Length, counting.Read(buffer, 0, buffer.Length));
        Assert.Equal(0, counting.Read(buffer, 0, buffer.Length));
        Assert.Equal(0, counting.Read(buffer, 0, 0));
        Assert.Equal(payload.Length, counting.BytesRead);
    }

    [Fact]
    public void CountingRead_Dispose_DisposesInner_DroppedContentHasNoOtherOwner()
    {
        var inner = new RecordingReadStream(Bytes("abc"));
        var counting = new CountingReadStream(inner);
        counting.Dispose();
        Assert.True(inner.Disposed);
    }

    [Fact]
    public async Task CountingRead_DisposeAsync_DisposesInner()
    {
        var inner = new RecordingReadStream(Bytes("abc"));
        var counting = new CountingReadStream(inner);
        await counting.DisposeAsync();
        Assert.True(inner.Disposed);
    }

    [Fact]
    public void CountingRead_WriteThrows_ServingBytesOnly()
    {
        using var counting = new CountingReadStream(new MemoryStream(Bytes("abc")));
        Assert.Throws<NotSupportedException>(() => counting.Write(new byte[1], 0, 1));
        Assert.Throws<NotSupportedException>(() => counting.WriteByte(1));
        Assert.Throws<NotSupportedException>(() => counting.SetLength(0));
    }

    // ---- CountingWriteStream (response direction) ----

    [Fact]
    public async Task CountingWrite_ByteIdentity_CountsIncludeArraySlices()
    {
        var inner = new MemoryStream();
        using (var counting = new CountingWriteStream(inner))
        {
            var padded = Bytes("XXXXhello");
            counting.Write(padded, 4, 5); // counts 5, not padded.Length
            counting.Write((ReadOnlySpan<byte>)Bytes(" world"));
            await counting.WriteAsync(Bytes("!!").AsMemory());
            counting.Flush();
            Assert.Equal(13, counting.BytesWritten); // 5 + 6 + 2
        }

        Assert.Equal("hello world!!", Text(inner.ToArray()));
    }

    [Fact]
    public void CountingWrite_Dispose_NeverDisposesServerOwnedBody()
    {
        var inner = new MemoryStream();
        var counting = new CountingWriteStream(inner);
        counting.Write(Bytes("final-chunk"), 0, 11);
        counting.Dispose();

        // The original body stays server-owned: writing after the wrapper's dispose works.
        inner.Write(Bytes(" more"), 0, 5);
        Assert.Equal("final-chunk more", Text(inner.ToArray()));
    }

    [Fact]
    public void CountingWrite_ReadAndLengthThrow()
    {
        using var counting = new CountingWriteStream(new MemoryStream());
        Assert.False(counting.CanRead);
        Assert.Throws<NotSupportedException>(() => counting.Read(new byte[4], 0, 4));
        Assert.Throws<NotSupportedException>(() => _ = counting.Length);
        Assert.Throws<NotSupportedException>(() => _ = counting.Position);
    }

    // ---- UsagePeekStream ----

    private const string Payload = "event: message_start\ndata: {\"usage\":{\"input_tokens\":100}}\n\nevent: done\ndata: {}";

    [Fact]
    public void Peek_ByteIdentity_ChunkedAndSpanReads()
    {
        using var peek = new UsagePeekStream(new MemoryStream(Bytes(Payload)), new RecordingUsageReader(), long.MaxValue);
        var got = new List<byte>();
        var buffer = new byte[7];
        int read;
        while ((read = peek.Read(buffer, 0, buffer.Length)) > 0)
        {
            got.AddRange(buffer[..read]);
        }

        Assert.Equal(Bytes(Payload), got.ToArray());
    }

    [Fact]
    public void Peek_ReaderSeesEveryByteOnce_InOrder_SingleFinalAtEof()
    {
        var reader = new RecordingUsageReader();
        using (var peek = new UsagePeekStream(new MemoryStream(Bytes(Payload)), reader, long.MaxValue))
        {
            var buffer = new byte[40];
            while (peek.Read(buffer, 0, buffer.Length) > 0)
            {
            }
        }

        Assert.Equal(Payload, Text(reader.Seen.ToArray()));
        Assert.Equal(1, reader.FinalObservations);
    }

    [Fact]
    public void Peek_ZeroLengthProbeRead_IsNotEof_AndNoDataIsLostAroundIt()
    {
        var reader = new RecordingUsageReader();
        using var peek = new UsagePeekStream(new MemoryStream(Bytes(Payload)), reader, long.MaxValue);
        var buffer = new byte[10];
        Assert.Equal(10, peek.Read(buffer, 0, 10));
        Assert.Equal(0, peek.Read(buffer, 0, 0)); // probe read: destination empty
        var rest = new byte[1024];
        Assert.Equal(Payload.Length - 10, peek.Read(rest, 0, rest.Length));
        Assert.Equal(0, peek.Read(rest, 0, rest.Length)); // real EOF

        Assert.Equal(Payload, Text(reader.Seen.ToArray()));
        Assert.Equal(1, reader.FinalObservations);
    }

    [Fact]
    public void Peek_RepeatedReadsAfterEof_FinalObservationStandsOnce()
    {
        var reader = new RecordingUsageReader();
        using var peek = new UsagePeekStream(new MemoryStream(Bytes("tiny")), reader, long.MaxValue);
        var buffer = new byte[64];
        while (peek.Read(buffer, 0, buffer.Length) > 0)
        {
        }

        Assert.Equal(0, peek.Read(buffer, 0, buffer.Length));
        Assert.Equal(0, peek.Read(buffer, 0, buffer.Length));
        Assert.Equal("tiny", Text(reader.Seen.ToArray()));
        Assert.Equal(1, reader.FinalObservations);
    }

    [Fact]
    public void Peek_EarlyDispose_StillGivesTheReaderOneFinal_Observation_AndOwnsInner()
    {
        var reader = new RecordingUsageReader();
        var inner = new RecordingReadStream(Bytes(Payload));
        var peek = new UsagePeekStream(inner, reader, long.MaxValue);
        var buffer = new byte[20];
        Assert.Equal(20, peek.Read(buffer, 0, buffer.Length));
        peek.Dispose(); // abort/disconnect path: half the stream delivered

        Assert.Equal(1, reader.FinalObservations);
        Assert.Equal(Payload[..20], Text(reader.Seen.ToArray())); // what was read stands
        Assert.True(inner.Disposed); // the replaced StreamContent has no other owner
    }

    [Fact]
    public void Peek_DisposeWhenFinalObservationThrows_CompletesQuietlyAndOwnsInner()
    {
        // M50 fold LOW-3: the SafeComplete catch — a reader that fails at the disposal-time
        // final observation changes nothing on the wire (witness for the uncovered catch).
        var reader = new RecordingUsageReader(n => n == 1); // the final observation throws
        var inner = new RecordingReadStream(Bytes("abc"));
        var peek = new UsagePeekStream(inner, reader, long.MaxValue);

        var error = Record.Exception(() => peek.Dispose()); // nothing read; dispose completes

        Assert.Null(error);
        Assert.True(inner.Disposed);
        Assert.Equal(1, reader.Observations);
    }

    [Fact]
    public async Task Peek_DisposeAsyncClean_CompletesOnceAndDisposesInner()
    {
        // m50-low1 finding 2: the non-throwing DisposeAsync arm was cold — the only
        // async-disposal witness threw inside its try. The clean arm is what every
        // successfully-completed metered response actually takes: the record is
        // already complete, the inner stream is owned, and nothing is thrown at the
        // response-completion path.
        var reader = new RecordingUsageReader();
        var inner = new RecordingReadStream(Bytes(Payload));
        var peek = new UsagePeekStream(inner, reader, long.MaxValue);
        var buffer = new byte[20];
        Assert.Equal(20, peek.Read(buffer, 0, buffer.Length));
        await peek.DisposeAsync();
        Assert.Equal(1, reader.FinalObservations);
        Assert.Equal(Payload[..20], Text(reader.Seen.ToArray())); // what was read stands
        Assert.True(inner.Disposed); // the replaced StreamContent has no other owner
    }

    [Fact]
    public void Peek_ReaderFailure_StopsFeeding_AndCallerBytesAreUntouched()
    {
        // The reader throws on its second observation.
        var reader = new RecordingUsageReader(n => n == 2);
        using var peek = new UsagePeekStream(new MemoryStream(Bytes(Payload)), reader, long.MaxValue);
        var got = new List<byte>();
        var buffer = new byte[30];
        int read;
        while ((read = peek.Read(buffer, 0, buffer.Length)) > 0)
        {
            got.AddRange(buffer[..read]);
        }

        Assert.Equal(Bytes(Payload), got.ToArray()); // every byte still reached the caller
        Assert.Equal(Payload[..30], Text(reader.Seen.ToArray())); // only the first chunk fed
        Assert.Equal(2, reader.Observations); // the throwing one; feeding stopped after it
        Assert.Equal(0, reader.FinalObservations); // window closed by failure, no final claim
    }

    [Fact]
    public void Peek_ParseWindowCutsAtEdge_ReaderSeesPrefixOnly_CallerSeesEverything()
    {
        var reader = new RecordingUsageReader();
        using var peek = new UsagePeekStream(new MemoryStream(Bytes(Payload)), reader, 50);
        var got = new List<byte>();
        var buffer = new byte[40];
        int read;
        while ((read = peek.Read(buffer, 0, buffer.Length)) > 0)
        {
            got.AddRange(buffer[..read]);
        }

        Assert.Equal(Bytes(Payload), got.ToArray());
        Assert.Equal(Payload[..50], Text(reader.Seen.ToArray())); // cut mid-chunk at the window edge
        Assert.Equal(0, reader.FinalObservations); // feeding stopped with the window; no final claim
    }

    [Fact]
    public void Peek_ZeroWindow_ReadsAreUnmeteredButUnchanged()
    {
        var reader = new RecordingUsageReader();
        using var peek = new UsagePeekStream(new MemoryStream(Bytes(Payload)), reader, 0);
        var buffer = new byte[1024];
        var read = peek.Read(buffer, 0, buffer.Length);

        Assert.Equal(Payload.Length, read);
        Assert.Equal(Payload, Text(buffer[..read]));
        Assert.Equal(0, reader.Observations);
    }

    [Fact]
    public void Peek_WriteThrows_ReadViewOnly()
    {
        using var peek = new UsagePeekStream(new MemoryStream(Bytes("abc")), new RecordingUsageReader(), 1024);
        Assert.False(peek.CanWrite);
        Assert.Throws<NotSupportedException>(() => peek.Write(new byte[1], 0, 1));
    }

    /// <summary>An inner stream whose async disposal throws, and says so loudly.</summary>
    private sealed class ThrowingDisposeAsyncStream : Stream
    {
        private readonly MemoryStream _inner = new(Bytes("abc"));

        public bool Disposed { get; private set; }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => _inner.Length;
        public override long Position { get => _inner.Position; set => _inner.Position = value; }
        public override void Flush() => _inner.Flush();
        public override long Seek(long offset, SeekOrigin origin) => _inner.Seek(offset, origin);
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
        public override int Read(Span<byte> destination) => _inner.Read(destination);

        public override ValueTask DisposeAsync()
        {
            Disposed = true;
            throw new InvalidOperationException("inner disposal witness");
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                Disposed = true;
                _inner.Dispose();
            }

            base.Dispose(disposing);
        }
    }

    [Fact]
    public async Task Peek_DisposeAsync_InnerDisposalThrowCannotEscape()
    {
        // M50 live verdict OPEN (the only offline-visible escape route, UsagePeekStream.cs:146):
        // at this point the record is already made — SafeComplete's final observation ran
        // before the inner disposal — and the caller already has its bytes. A vendor stream
        // whose DisposeAsync throws must not carry that failure out of the peek into the
        // response-completion path; pre-guard, this threw out of await DisposeAsync.
        var inner = new ThrowingDisposeAsyncStream();
        var reader = new RecordingUsageReader();
        var peek = new UsagePeekStream(inner, reader, long.MaxValue);
        var buffer = new byte[2];
        Assert.Equal(2, peek.Read(buffer, 0, buffer.Length)); // bytes flow, reader watches

        await peek.DisposeAsync();

        Assert.Equal(1, reader.FinalObservations); // the record was made, throw or not
        Assert.True(inner.Disposed); // disposal was attempted, not skipped
    }

    /// <summary>An inner stream whose SYNC disposal throws, and says so loudly.</summary>
    private sealed class ThrowingSyncDisposeStream : Stream
    {
        private readonly MemoryStream _inner = new(Bytes(Payload));

        public bool Disposed { get; private set; }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => _inner.Length;
        public override long Position { get => _inner.Position; set => _inner.Position = value; }
        public override void Flush() => _inner.Flush();
        public override long Seek(long offset, SeekOrigin origin) => _inner.Seek(offset, origin);
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
        public override int Read(Span<byte> destination) => _inner.Read(destination);

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                Disposed = true;
                _inner.Dispose();
                throw new InvalidOperationException("inner sync disposal witness");
            }

            base.Dispose(disposing);
        }
    }

    [Fact]
    public async Task Peek_StreamContentWrapper_SyncDisposalThrowCannotReachCaller()
    {
        // LOW-1 on the M50 follow-ups verdict: the shipped wrapper — StreamContent over the peek,
        // installed as response.Content by CredProxMeteringResponseFeature — tears the vendor
        // stream down through the SYNC arm (UsagePeekStream.Dispose(bool)), not DisposeAsync:
        // the checker's M10/M11b differential showed a sync-arm throw reaching the caller while
        // the async-arm throw stayed invisible. Pre-guard, this escape surfaced at the caller
        // through StreamContent.Dispose. The record is already made by the full read, and the
        // caller already holds its bytes — a vendor-stream disposal failure must change neither.
        var inner = new ThrowingSyncDisposeStream();
        var reader = new RecordingUsageReader();
        var peeked = new UsagePeekStream(inner, reader, long.MaxValue);
        using var response = new HttpResponseMessage
        {
            Content = new StreamContent(peeked),
        };
        response.Content.Headers.TryAddWithoutValidation("Content-Type", "application/json");

        var got = await response.Content.ReadAsByteArrayAsync();
        var escape = Record.Exception(() => response.Content.Dispose());

        Assert.Null(escape); // the vendor throw stays inside the peek, never at the caller
        Assert.Equal(Bytes(Payload), got); // the caller got its full bytes
        Assert.Equal(Payload, Text(reader.Seen.ToArray()));
        Assert.Equal(1, reader.FinalObservations); // the record stands
        Assert.True(inner.Disposed); // disposal was attempted, not skipped
    }
}
