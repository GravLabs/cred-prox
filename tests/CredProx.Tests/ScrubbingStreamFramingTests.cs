using System.Text;
using CredProx;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage for <see cref="ScrubbingStream">: the byte-stream hold-back
/// buffer's growth paths (the sweep's resize mutants survived because no existing
/// payload ever exceeded the initial 32 KiB pending buffer), zero-length probe,
/// dispose wiring, ctor guards, and the capability surface — the stream-level
/// siblings of the <c>SecretScrubber</c> batch contract.
/// </summary>
public sealed class ScrubbingStreamFramingTests
{
    private const string Secret = "tok-abc";
    private const string Redacted = "[redacted]";

    [Fact]
    public void Ctor_NullInner_Throws_NamingInner()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => new ScrubbingStream(null!, [Secret]));

        Assert.Equal("inner", ex.ParamName);
    }

    [Fact]
    public void Ctor_NullSecrets_Throws_NamingSecrets()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => new ScrubbingStream(new MemoryStream(), null!));

        Assert.Equal("secrets", ex.ParamName);
    }

    // The YARP copy loop opens with a zero-byte Read; answering it must consume nothing.
    [Fact]
    public void ZeroLengthProbe_ReturnsZero_BytesIntact()
    {
        using var stream = new ScrubbingStream(new MemoryStream("hello"u8.ToArray()), [Secret]);

        Assert.Equal(0, stream.Read(Span<byte>.Empty));

        var buffer = new byte[64];
        var read = stream.Read(buffer, 0, buffer.Length);
        Assert.Equal("hello", Encoding.UTF8.GetString(buffer, 0, read));
    }

    [Fact]
    public void Dispose_DisposesInner_AndMarksStreamDisposed()
    {
        var inner = new TrackingStream("x"u8.ToArray());
        var stream = new ScrubbingStream(inner, [Secret]);

        stream.Dispose();

        Assert.True(inner.InnerDisposed);
        Assert.Throws<ObjectDisposedException>(() => stream.Read(new byte[8], 0, 8));
    }

    [Fact]
    public void CapabilityFlags_AndUnsupportedMembers()
    {
        using var stream = new ScrubbingStream(new MemoryStream("x"u8.ToArray()), [Secret]);

        Assert.True(stream.CanRead);
        Assert.False(stream.CanSeek);
        Assert.False(stream.CanWrite);
        Assert.Throws<NotSupportedException>(() => _ = stream.Length);
        Assert.Throws<NotSupportedException>(() => _ = stream.Position);
        Assert.Throws<NotSupportedException>(() => stream.Position = 0);
        Assert.Throws<NotSupportedException>(() => stream.Seek(0, SeekOrigin.Begin));
        Assert.Throws<NotSupportedException>(() => stream.SetLength(1));
        Assert.Throws<NotSupportedException>(() => stream.Write(new byte[1], 0, 1));
        Assert.Throws<NotSupportedException>(() => stream.Write(new byte[1]));
        Assert.Throws<NotSupportedException>(() => stream.WriteByte(1));
    }

    // 100 KiB payload through 16 KiB chunks: the pending buffer must grow twice, and
    // a secret straddling a chunk boundary in the grown region must still be redacted
    // (hold-back across fills, no byte loss across resizes).
    [Fact]
    public void PayloadBeyondPendingGrowth_ResizesAndScrubsAcrossBoundary()
    {
        const int Total = 100 * 1024;
        var data = NonLineBytes(Total);
        var secretBytes = Encoding.UTF8.GetBytes(Secret);
        var at = 65_530; // straddles the second 16 KiB chunk edge inside the grown buffer
        for (var i = 0; i < secretBytes.Length; i++)
        {
            data[at + i] = secretBytes[i];
        }

        using var stream = new ScrubbingStream(new ChunkedStream(data, 16 * 1024), [Secret]);
        using var output = new MemoryStream();
        stream.CopyTo(output);

        Assert.Equal(ExpectedWithRedaction(data, at, secretBytes.Length), output.ToArray());
        Assert.Contains(Redacted, Encoding.UTF8.GetString(output.ToArray()));
    }

    // A secret sitting at the very end of the stream: only the EOF flush (hold-back 0)
    // can emit it redacted — a leftover hold-back would drop the tail entirely.
    [Fact]
    public void SecretAtStreamEnd_FlushedRedactedAtEof()
    {
        var input = "prefix " + Secret;
        using var stream = new ScrubbingStream(
            new MemoryStream(Encoding.UTF8.GetBytes(input)), [Secret]);
        using var output = new MemoryStream();
        stream.CopyTo(output);

        Assert.Equal($"prefix {Redacted}", Encoding.UTF8.GetString(output.ToArray()));
    }

    // The hold-back must never split a secret across two emitted batches: place the
    // secret at the first fill edge so the tail-hold is what keeps it whole.
    [Fact]
    public void SecretStraddlingFirstFillEdge_IsNeverSplit()
    {
        const int Fill = 32 * 1024; // initial pending size: first fill lands exactly here
        var data = NonLineBytes(Fill + 64);
        var secretBytes = Encoding.UTF8.GetBytes(Secret);
        var at = Fill - 3; // "tok" before the edge, "-abc" after it
        for (var i = 0; i < secretBytes.Length; i++)
        {
            data[at + i] = secretBytes[i];
        }

        using var stream = new ScrubbingStream(new MemoryStream(data), [Secret]);
        using var output = new MemoryStream();
        stream.CopyTo(output);

        Assert.Equal(ExpectedWithRedaction(data, at, secretBytes.Length), output.ToArray());
    }

    // The stream's contract: every byte verbatim except the secret region, which
    // becomes the redaction marker exactly once.
    private static byte[] ExpectedWithRedaction(byte[] data, int at, int secretLength)
    {
        using var expected = new MemoryStream();
        expected.Write(data, 0, at);
        expected.Write(Encoding.UTF8.GetBytes(Redacted));
        expected.Write(data, at + secretLength, data.Length - at - secretLength);
        return expected.ToArray();
    }

    private static byte[] NonLineBytes(int length)
    {
        var data = new byte[length];
        for (var i = 0; i < length; i++)
        {
            byte b;
            do
            {
                b = (byte)Random.Shared.Next(256);
            }
            while (b is (byte)'\n' or (byte)'\r');

            data[i] = b;
        }

        return data;
    }

    /// <summary>Answers at most <paramref name="maxChunk"/> bytes per read.</summary>
    private sealed class ChunkedStream(byte[] data, int maxChunk) : MemoryStream(data)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> destination, CancellationToken cancellationToken = default)
        {
            var slice = destination.Length > maxChunk ? destination[..maxChunk] : destination;
            return base.ReadAsync(slice, cancellationToken);
        }
    }

    private sealed class TrackingStream(byte[] data) : MemoryStream(data)
    {
        public bool InnerDisposed { get; private set; }

        protected override void Dispose(bool disposing)
        {
            InnerDisposed = true;
            base.Dispose(disposing);
        }
    }

    // ---- M31 batch-4b survivors: probe consumption, async dispose, the hold-back and
    // ---- resize laws at their exact boundaries ----------------------------------------------

    private sealed class CountingStream(byte[] data) : MemoryStream(data)
    {
        public int Reads { get; private set; }

        public override int Read(Span<byte> destination)
        {
            Reads++;
            return base.Read(destination);
        }

        public override ValueTask<int> ReadAsync(Memory<byte> destination, CancellationToken cancellationToken = default)
        {
            Reads++;
            return base.ReadAsync(destination, cancellationToken);
        }
    }

    private sealed class DestinationRecordingStream(byte[] data) : MemoryStream(data)
    {
        public List<int> Destinations { get; } = [];

        public override ValueTask<int> ReadAsync(Memory<byte> destination, CancellationToken cancellationToken = default)
        {
            Destinations.Add(destination.Length);
            return base.ReadAsync(destination, cancellationToken);
        }
    }

    [Fact]
    public async Task ZeroLengthProbe_ConsumesNoInnerRead()
    {
        // The probe must not even ask the inner for bytes — a consumed fill that
        // returns 0 through the output path keeps the content but burns a round trip
        // the forwarder never sees (M31 triage).
        var inner = new CountingStream("hello"u8.ToArray());
        await using var stream = new ScrubbingStream(inner, [Secret]);

        Assert.Equal(0, stream.Read(Span<byte>.Empty));
        Assert.Equal(0, await stream.ReadAsync(Memory<byte>.Empty));
        Assert.Equal(0, inner.Reads);
    }

    [Fact]
    public async Task DisposeAsync_DisposesInner()
    {
        // The async path must reach the inner's own DisposeAsync; the base's sync
        // fallback runs Dispose(false), which the wrapper deliberately ignores.
        var inner = new TrackingStream("x"u8.ToArray());
        var stream = new ScrubbingStream(inner, [Secret]);

        await stream.DisposeAsync();

        Assert.True(inner.InnerDisposed);
    }

    [Fact]
    public void FirstBatch_HoldsBackExactlyMaxPatternMinusOne()
    {
        // "prefix tok-abc": the emit boundary (14 - 6 = 8) starts a scan that completes
        // the straddling match inside the first batch — 17 bytes out at once. A two-byte
        // larger hold-back pushes the match start past the scan limit and delays the
        // redaction a full round trip (M31 :142 triage).
        using var stream = new ScrubbingStream(
            new MemoryStream("prefix tok-abc"u8.ToArray()), [Secret]);
        var buffer = new byte[64];

        var first = stream.Read(buffer, 0, buffer.Length);
        var firstText = Encoding.UTF8.GetString(buffer, 0, first);

        Assert.Equal("prefix [redacted]", firstText);
        using var rest = new MemoryStream();
        stream.CopyTo(rest);
        Assert.Equal(0, rest.Length);
    }

    [Fact]
    public void SteadyStateBatches_KeepTheHeldTailOutOfReadSizes()
    {
        // Steady law on an unpaced body: each read hands over one full destination
        // minus the held tail — never a resized-larger batch (M31 :160 family).
        var body = new string('x', 200000);
        using var stream = new ScrubbingStream(
            new MemoryStream(Encoding.UTF8.GetBytes(body)), [Secret]);
        var buffer = new byte[64 * 1024];

        var first = stream.Read(buffer, 0, buffer.Length);
        var second = stream.Read(buffer, 0, buffer.Length);

        Assert.Equal(32768 - (Secret.Length - 1), first);
        Assert.Equal(32768 - (Secret.Length - 1), second);
    }

    [Fact]
    public void FillAtExactChunkBoundary_UsesFreeSpaceNotAResize()
    {
        // A secret of exactly 16,385 bytes leaves the steady free space at exactly one
        // chunk: the fill must read 16,384 into the existing buffer, not resize for
        // 32,768 (M31 :160 '<=' triage). The straddling secret still redacts.
        var secret = new string('S', 16385);
        var body = new string('x', 30000) + secret + new string('y', 30000);
        var inner = new DestinationRecordingStream(Encoding.UTF8.GetBytes(body));
        using var stream = new ScrubbingStream(inner, [secret]);
        using var output = new MemoryStream();

        stream.CopyTo(output);

        Assert.Equal(
            new string('x', 30000) + "[redacted]" + new string('y', 30000),
            Encoding.UTF8.GetString(output.ToArray()));
        Assert.Equal(32768, inner.Destinations[0]);
        Assert.Equal(16384, inner.Destinations[1]);
    }

    [Fact]
    public void SecondResize_ReadsIntoExactlyOneMoreChunk()
    {
        // With the hold-back past a full chunk the pending buffer exhausts and resizes:
        // the resized destination is the old buffer's free law — one chunk (32,768),
        // not the old array length's worth (65,536) (M31 :160 '+ _pendingLength' triage).
        var secret = new string('S', 50000);
        var body = new string('x', 150000);
        using var stream = new ScrubbingStream(
            new MemoryStream(Encoding.UTF8.GetBytes(body)), [secret]);
        var buffer = new byte[70 * 1024];

        var first = stream.Read(buffer, 0, buffer.Length); // fills twice before it can emit
        var second = stream.Read(buffer, 0, buffer.Length); // third fill rides the resize

        Assert.Equal(65536 - (50000 - 1), first);
        Assert.Equal(32768, second);
    }
}
