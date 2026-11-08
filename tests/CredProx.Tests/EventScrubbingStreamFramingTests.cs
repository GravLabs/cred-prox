using System.Text;
using CredProx;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage for <see cref="EventScrubbingStream">: the framing and buffer
/// mutants that the example-level SSE tests could not see — the zero-length probe,
/// dispose wiring, every recognised event-boundary spelling, boundary detection when a
/// fill splits the boundary bytes, and the never-terminating-event overflow path
/// (progress, hold-back, huge-secret edge).
/// </summary>
public sealed class EventScrubbingStreamFramingTests
{
    private const string Secret = "tok-abc";
    private const string Redacted = "[redacted]";

    // --- guards and lifecycle ---------------------------------------------------------

    [Fact]
    public void Ctor_NullInner_Throws_NamingInner()
    {
        var ex = Assert.Throws<ArgumentNullException>(() =>
            new EventScrubbingStream(null!, [Secret]));

        Assert.Equal("inner", ex.ParamName);
    }

    [Fact]
    public void Ctor_NullSecrets_Throws_NamingSecrets()
    {
        var ex = Assert.Throws<ArgumentNullException>(() =>
            new EventScrubbingStream(new MemoryStream(), null!));

        Assert.Equal("secrets", ex.ParamName);
    }

    // The YARP copy loop opens with a zero-byte Read; answering it must consume
    // nothing or the first event's bytes vanish.
    [Fact]
    public void ZeroLengthProbe_ReturnsZero_BytesIntact()
    {
        using var stream = new EventScrubbingStream(
            new MemoryStream("data: hi\n\n"u8.ToArray()), [Secret]);

        Assert.Equal(0, stream.Read(Span<byte>.Empty));

        var buffer = new byte[64];
        var read = stream.Read(buffer, 0, buffer.Length);
        Assert.Equal("data: hi\n\n", Encoding.UTF8.GetString(buffer, 0, read));
    }

    [Fact]
    public void Dispose_DisposesInner_AndMarksStreamDisposed()
    {
        var inner = new TrackingStream("x\n\n"u8.ToArray());
        var stream = new EventScrubbingStream(inner, [Secret]);

        stream.Dispose();

        Assert.True(inner.InnerDisposed);
        Assert.Throws<ObjectDisposedException>(() => stream.Read(new byte[8], 0, 8));
    }

    // --- boundary spellings (all four recognised, one-terminator never) ---------------

    [Theory]
    [InlineData("a\n\n")]            // ␊␊
    [InlineData("a\n\r\n")]          // ␊␍␊
    [InlineData("a\r\n\r\n")]        // ␍␊␍␊
    [InlineData("a\r\r\n")]          // ␍␍␊
    public void FirstBoundarySpellings_EndTheFirstEvent(string ending)
    {
        var input = $"event: 1{ending}event: 2{ending}";
        using var stream = new EventScrubbingStream(
            new MemoryStream(Encoding.UTF8.GetBytes(input)), [Secret]);
        using var output = new MemoryStream();
        stream.CopyTo(output);

        Assert.Equal(input, Encoding.UTF8.GetString(output.ToArray()));
    }

    [Fact]
    public void BoundarySpellings_ScrubWithinEvent_VerbatimOtherwise()
    {
        var input = $"data: {Secret}\r\n\r\ndata: clean\r\n\r\n";
        using var stream = new EventScrubbingStream(
            new MemoryStream(Encoding.UTF8.GetBytes(input)), [Secret]);
        using var output = new MemoryStream();
        stream.CopyTo(output);

        Assert.Equal($"data: {Redacted}\r\n\r\ndata: clean\r\n\r\n", Encoding.UTF8.GetString(output.ToArray()));
    }

    // A single line terminator is an event line break, not an event boundary: the
    // stream's whole framing turns on this distinction.
    [Fact]
    public void SingleTerminator_IsNotABoundary()
    {
        var input = "data: one\ndata: two\n\n";
        using var stream = new EventScrubbingStream(
            new MemoryStream(Encoding.UTF8.GetBytes(input)), [Secret]);
        using var output = new MemoryStream();
        stream.CopyTo(output);

        Assert.Equal(input, Encoding.UTF8.GetString(output.ToArray()));
    }

    // --- boundary detection across fills ----------------------------------------------

    // A chunked upstream can split the two bytes of a boundary across fills. The resume
    // offset (previous fill's tail) must catch it: the first event completes and emits,
    // and the cross-boundary secret keeps its documented survival (each event is
    // matched on its own bytes).
    [Fact]
    public void BoundarySplitAcrossFills_EventStillEnds_AndCrossBoundarySecretSurvives()
    {
        const int Fill = 16 * 1024;
        // 'X' pads event 1 so the ␊␊ straddles the first fill boundary exactly:
        // first ␊ at Fill-1, second ␊ at Fill.
        // 'data: pre-' + 'tok' = 13 chars, then X padding, so the first ␊ is the very
        // last byte of the first fill; event 2 opens with the second ␊ of the boundary.
        var event1 = $"data: pre-{Secret[..3]}{new string('X', Fill - 14)}\n";
        var event2 = $"\n{Secret[3..]}-post\n\n";
        var input = event1 + event2;
        Assert.Equal(Fill, input.IndexOf("\n\n", StringComparison.Ordinal) + 1);

        var secretBytes = Encoding.UTF8.GetBytes(Secret);
        using var stream = new EventScrubbingStream(
            new ChunkedStream(Encoding.UTF8.GetBytes(input), Fill), [Secret]);
        using var output = new MemoryStream();
        stream.CopyTo(output);
        var written = output.ToArray();

        // Documented residue: the split secret is not contiguous, so it survives split.
        Assert.True(new ReadOnlySpan<byte>(written).IndexOf(secretBytes) < 0); // split, never whole
        Assert.Contains("pre-tok", Encoding.UTF8.GetString(written));
        Assert.Contains("-abc-post", Encoding.UTF8.GetString(written));
        Assert.Equal(input, Encoding.UTF8.GetString(written)); // framing bytes verbatim
    }

    // --- overflow: an event that never terminates --------------------------------------

    // The pathological upstream from the remarks: bytes must keep flowing before any
    // EOF (latency and memory are bounded), so a reader sees data while the inner
    // stream is still blocked mid-event.
    [Fact]
    public async Task Overflow_EmitsBeforeEof_ProgressWitness()
    {
        var filler = NonLineBytes(70 * 1024); // > MaxEventBufferBytes, no boundary anywhere
        var inner = new BlockingAfterCapPassed(filler);
        await using var stream = new EventScrubbingStream(inner, [Secret]);

        var buffer = new byte[4096];
        var readTask = stream.ReadAsync(buffer, 0, buffer.Length);
        var winner = await Task.WhenAny(readTask, Task.Delay(10_000));
        Assert.Same(readTask, winner); // the inner is still open: bytes must have flowed
        var first = await readTask;
        Assert.True(first > 0, "no bytes emitted although the buffer passed the overflow cap");

        using var output = new MemoryStream();
        output.Write(buffer, 0, first); // the bytes the first read already took
        inner.Release();
        await stream.CopyToAsync(output);
        Assert.Equal(filler.Length, output.Length);
        Assert.Equal(filler, output.ToArray());
    }

    // The hold-back tail is what makes overflow still scrub: a secret that straddles
    // the current pending edge must be held, not emitted, so the next fill can complete
    // and remove it.
    [Fact]
    public async Task Overflow_SecretStraddlingFlushEdge_IsStillRedacted()
    {
        const int Fill = 16 * 1024;
        const int FirstOverflowPending = 80 * 1024; // first pending > 64 KiB at 16 KiB fills
        var secretBytes = Encoding.UTF8.GetBytes(Secret);
        // The secret starts 10 bytes before the first overflow flush's pending edge:
        // no hold-back emits its head, and the halves then survive forever.
        var head = FirstOverflowPending - 10;
        var data = NonLineBytes(FirstOverflowPending + 4 * Fill);
        for (var i = 0; i < secretBytes.Length; i++)
        {
            data[head + i] = secretBytes[i];
        }

        await using var stream = new EventScrubbingStream(new ChunkedStream(data, Fill), [Secret]);
        using var output = new MemoryStream();
        await stream.CopyToAsync(output);
        var written = output.ToArray();

        Assert.True(
            new ReadOnlySpan<byte>(written).IndexOf(secretBytes) < 0,
            "secret split by the overflow flush edge survived — hold-back tail lost");
        Assert.Contains(Redacted, Encoding.UTF8.GetString(written));
    }

    // A registered secret longer than the event cap makes safeEmit negative on the
    // first overflow check: the guard must skip the flush, not feed a negative span
    // into the scrubber.
    [Fact]
    public async Task Overflow_HugeSecret_NeverCompleting_FlushesNothingNegative()
    {
        var huge = new string('S', 70 * 1024);
        var data = NonLineBytes(65 * 1024); // > cap, < huge.Length + 1: safeEmit would be negative

        var inner = new BlockingAfterCapPassed(data);
        await using var stream = new EventScrubbingStream(inner, [huge]);

        var buffer = new byte[1024];
        // With the safeEmit guard broken this read faults immediately with an
        // out-of-range span instead of waiting quietly for more bytes.
        var readTask = stream.ReadAsync(buffer, 0, buffer.Length);
        var winner = await Task.WhenAny(readTask, Task.Delay(3_000));
        Assert.False(readTask.IsFaulted, "overflow flush fed a negative span to the scrubber");
        Assert.NotSame(readTask, winner); // nothing may be emitted: the whole pending set is hold-back

        inner.Release();
        var first = await readTask;
        using var output = new MemoryStream();
        output.Write(buffer, 0, first);
        await stream.CopyToAsync(output);
        Assert.Equal(data, output.ToArray());
    }

    // --- capability surface --------------------------------------------------------------

    [Fact]
    public void CapabilityFlags_AndUnsupportedMembers()
    {
        using var stream = new EventScrubbingStream(new MemoryStream("x\n\n"u8.ToArray()), [Secret]);

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

    // --- EOF flush of an unterminated tail ------------------------------------------------

    // The final-event flush at EOF is the only path that emits bytes with no boundary
    // anywhere after them; without it a tail event would sit in the buffer forever.
    [Fact]
    public void UnterminatedFinalEvent_FlushedAtEof_Scrubbed()
    {
        var input = $"data: one\n\ndata: partial-{Secret}"; // no trailing boundary
        using var stream = new EventScrubbingStream(
            new MemoryStream(Encoding.UTF8.GetBytes(input)), [Secret]);
        using var output = new MemoryStream();
        stream.CopyTo(output);

        Assert.Equal($"data: one\n\ndata: partial-{Redacted}", Encoding.UTF8.GetString(output.ToArray()));
    }

    // A lone terminator stranded after the last boundary must flush verbatim at EOF —
    // the boundary matcher must not dereference past the buffer on it.
    [Theory]
    [InlineData("x\n\n\n")]      // lone ␊ tail
    [InlineData("x\r\n\r\n\r")]  // lone ␍ tail after ␍␊␍␊
    [InlineData("x\r\r\n\r")]    // lone ␍ tail after ␍␍␊
    public void TrailingLoneTerminator_FlushesVerbatim_NoOverread(string input)
    {
        using var stream = new EventScrubbingStream(
            new MemoryStream(Encoding.UTF8.GetBytes(input)), [Secret]);
        using var output = new MemoryStream();
        stream.CopyTo(output);

        Assert.Equal(input, Encoding.UTF8.GetString(output.ToArray()));
    }

    // --- boundary spelling discrimination ------------------------------------------------

    // Each row's secret contains the byte run that a negated boundary-clause mutant
    // reads as a false event boundary. Cutting there splits the secret across two
    // batches and it survives; the real code cuts only at true boundaries, so the
    // contiguous secret is redacted. This is what pins every spelling clause.
    [Theory]
    [InlineData("data: a\nb\nc\r\n\r\n", "a\nb\nc")]          // ␊X␊ is not ␊␍␊
    [InlineData("data: a\r\rXb\n\n", "a\r\rXb")]              // ␍␍X is not ␊␍␊-tail / ␍␍␊
    [InlineData("data: a\r\rXb\r\n\r\n", "a\r\rXb")]          // ␍␍X before a true ␍␊␍␊
    [InlineData("data: a\rX\r\nb\r\n\r\n", "a\rX\r\nb")]      // ␍X␍␊ is not ␍␊␍␊
    [InlineData("data: a\r\nX\r\nb\n\n", "a\r\nX\r\nb")]      // ␍␊X␊ is not ␍␊␍␊
    [InlineData("data: a\rX\nb\r\n\r\n", "a\rX\nb")]          // ␍X␊ is not ␍␍␊
    [InlineData("data: a\n\rXb\n\n", "a\n\rXb")]              // ␊␍X is not ␊␍␊
    [InlineData("data: a\r\n\rXb\n\n", "a\r\n\rXb")]          // ␍␊␍X is not ␍␊␍␊
    public void MultiLineSecret_SplitOnlyByFalseBoundarySpelling_IsStillRedacted(string input, string secret)
    {
        using var stream = new EventScrubbingStream(
            new MemoryStream(Encoding.UTF8.GetBytes(input)), [secret]);
        using var output = new MemoryStream();
        stream.CopyTo(output);

        Assert.Equal(input.Replace(secret, Redacted), Encoding.UTF8.GetString(output.ToArray()));
    }

    // --- overflow boundary conditions ------------------------------------------------------

    // Exactly at the cap nothing may flush: only a pending strictly over the cap has
    // provably passed the point where a match could still start and complete earlier.
    [Fact]
    public async Task PendingExactlyAtCap_EmitsNothing()
    {
        var filler = NonLineBytes(EventScrubbingStream.MaxEventBufferBytes); // exactly the cap
        var inner = new DeliverThenBlock(filler, [32 * 1024, 32 * 1024]); // delivers exactly the cap, then blocks
        await using var stream = new EventScrubbingStream(inner, [Secret]);

        var buffer = new byte[4096];
        var readTask = stream.ReadAsync(buffer, 0, buffer.Length);
        var winner = await Task.WhenAny(readTask, Task.Delay(2_000));
        Assert.NotSame(readTask, winner); // at == cap there is nothing safe to emit yet

        inner.Release();
        var first = await readTask;
        using var output = new MemoryStream();
        output.Write(buffer, 0, first);
        await stream.CopyToAsync(output);
        Assert.Equal(filler, output.ToArray());
    }

    // When a secret longer than the cap pins safeEmit to exactly 0, the overflow guard
    // must emit nothing at all (an empty batch is a no-op, but the boundary is pinned).
    [Fact]
    public async Task Overflow_SafeEmitExactlyZero_EmitsNothing()
    {
        // first over-cap pending is 64 KiB + 1 KiB = 66560 = maxPatternLength - 1.
        var huge = new string('S', 66561);
        var data = NonLineBytes(65 * 1024);

        var inner = new BlockingAfterCapPassed(data);
        await using var stream = new EventScrubbingStream(inner, [huge]);

        var buffer = new byte[1024];
        var readTask = stream.ReadAsync(buffer, 0, buffer.Length);
        var winner = await Task.WhenAny(readTask, Task.Delay(3_000));
        Assert.False(readTask.IsFaulted);
        Assert.NotSame(readTask, winner); // safeEmit == 0: hold back everything, emit nothing

        inner.Release();
        var first = await readTask;
        using var output = new MemoryStream();
        output.Write(buffer, 0, first);
        await stream.CopyToAsync(output);
        Assert.Equal(data, output.ToArray());
    }

    // A boundary whose two ␊ bytes straddle the fill edge must be detected when the
    // second byte lands: the first event is cut, scrubbed, and delivered while the
    // upstream is already blocked again — progress proves the resume offset worked.
    [Fact]
    public async Task BoundarySplitAcrossFills_EmitsFirstEvent_BeforeNextByte()
    {
        const int Fill = 16 * 1024;
        // event 1 = "data: " + secret + X padding + ␊ (the ␊ is the fill's last byte);
        // event 2 opens with the boundary's second ␊.
        var event1 = $"data: {Secret}{new string('X', Fill - 6 - Secret.Length - 1)}\n";
        var event2 = "\ndata: tail\n\n";
        var input = event1 + event2;
        Assert.Equal(Fill - 1, input.IndexOf("\n\n", StringComparison.Ordinal)); // ␊ | ␊ across the fill edge

        var inner = new DeliverThenBlock(Encoding.UTF8.GetBytes(input), [Fill, 1]);
        await using var stream = new EventScrubbingStream(inner, [Secret]);

        var buffer = new byte[4096];
        var readTask = stream.ReadAsync(buffer, 0, buffer.Length);
        var winner = await Task.WhenAny(readTask, Task.Delay(5_000));
        Assert.Same(readTask, winner); // split boundary completed: event 1 must already flow
        var first = await readTask;
        var head = Encoding.UTF8.GetString(buffer, 0, first);
        Assert.Contains(Redacted, head);
        Assert.DoesNotContain(Secret, head);

        using var output = new MemoryStream();
        output.Write(buffer, 0, first);
        inner.Release();
        await stream.CopyToAsync(output);
        Assert.Equal(input.Replace(Secret, Redacted), Encoding.UTF8.GetString(output.ToArray()));
    }

    // --- test-only streams --------------------------------------------------------------

    // Random filler that cannot accidentally spell an event boundary.
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

    /// <summary>
    /// Serves bytes normally until more than <see cref="EventScrubbingStream.MaxEventBufferBytes"/>
    /// have been handed out, then blocks at the next read until <see cref="Release"/> —
    /// a witness that the stream emits while the upstream is still open mid-event.
    /// (The pending buffer starts at 32 KiB and grows in 32 KiB steps, so the cap is
    /// crossed only on the third read at the earliest.)
    /// </summary>
    private sealed class BlockingAfterCapPassed(byte[] data) : MemoryStream(data)
    {
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private long _delivered;

        public void Release() => _release.SetResult();

        public override async ValueTask<int> ReadAsync(Memory<byte> destination, CancellationToken cancellationToken = default)
        {
            if (Interlocked.Read(ref _delivered) > EventScrubbingStream.MaxEventBufferBytes)
            {
                await _release.Task.WaitAsync(cancellationToken);
            }

            var read = await base.ReadAsync(destination, cancellationToken);
            Interlocked.Add(ref _delivered, read);
            return read;
        }
    }

    /// <summary>
    /// Answers read i with at most <c>plan[i]</c> bytes, then blocks every later read
    /// until <see cref="Release"/> — a scripted upstream that stops the byte stream at
    /// an exact position (just past a boundary's last byte, or exactly at a cap).
    /// </summary>
    private sealed class DeliverThenBlock(byte[] data, int[] plan) : MemoryStream(data)
    {
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _readIndex;

        public void Release() => _release.SetResult();

        public override async ValueTask<int> ReadAsync(Memory<byte> destination, CancellationToken cancellationToken = default)
        {
            var index = _readIndex++;
            if (index < plan.Length)
            {
                var slice = destination.Length > plan[index] ? destination[..plan[index]] : destination;
                return await base.ReadAsync(slice, cancellationToken);
            }

            await _release.Task.WaitAsync(cancellationToken);
            return await base.ReadAsync(destination, cancellationToken);
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

    // ---- M31 batch-4b survivors: probe consumption, async dispose, hold-back exactness,
    // ---- fill sizing, and boundary clauses at the pending-buffer head ---------------------

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

    /// <summary>Records every destination length and answers at most one chunk per read.</summary>
    private sealed class ChunkCappedRecordingStream(byte[] data) : MemoryStream(data)
    {
        public List<int> Destinations { get; } = [];

        public override ValueTask<int> ReadAsync(Memory<byte> destination, CancellationToken cancellationToken = default)
        {
            Destinations.Add(destination.Length);
            var slice = destination.Length > 16384 ? destination[..16384] : destination;
            return base.ReadAsync(slice, cancellationToken);
        }
    }

    [Fact]
    public async Task ZeroLengthProbe_ConsumesNoInnerRead()
    {
        // The probe must not even ask the inner for bytes: consuming a fill and
        // returning 0 through the output path would burn a round trip the forwarder
        // never sees (the bytes re-emit, so content tests miss it — M31 triage).
        var inner = new CountingStream("data: hi\n\n"u8.ToArray());
        await using var stream = new EventScrubbingStream(inner, [Secret]);

        Assert.Equal(0, stream.Read(Span<byte>.Empty));
        Assert.Equal(0, await stream.ReadAsync(Memory<byte>.Empty));
        Assert.Equal(0, inner.Reads);
    }

    [Fact]
    public async Task DisposeAsync_DisposesInner()
    {
        // The async path must reach the inner's own DisposeAsync; the base's sync
        // fallback runs Dispose(false), which the wrapper deliberately ignores.
        var inner = new TrackingStream("x\n\n"u8.ToArray());
        var stream = new EventScrubbingStream(inner, [Secret]);

        await stream.DisposeAsync();

        Assert.True(inner.InnerDisposed);
    }

    [Fact]
    public async Task Overflow_HoldbackIsExactlyMaxPatternMinusOne()
    {
        // The overflow flush releases everything but the longest possible partial
        // match: exactly maxPattern-1 bytes held back. The 4096-byte-buffer progress
        // witness masks the two-byte differences; an 80 KiB destination sees the exact
        // first batch (M31 triage).
        var filler = NonLineBytes(70 * 1024);
        var inner = new BlockingAfterCapPassed(filler);
        await using var stream = new EventScrubbingStream(inner, [Secret]);

        var first = await stream.ReadAsync(new byte[80 * 1024]);

        inner.Release();
        Assert.Equal(70 * 1024 - (Secret.Length - 1), first);
    }

    [Fact]
    public async Task FillAtExactChunkBoundary_UsesFreeSpaceNotAResize()
    {
        // The resize fires only when free space falls BELOW a chunk. With a paced inner
        // the second fill lands on exactly 16,384 free bytes: it must read 16,384, not
        // a resized 32,768 (M31 :192 triage).
        var input = new string('a', 40000) + "\n\n" + new string('b', 20000);
        var inner = new ChunkCappedRecordingStream(Encoding.UTF8.GetBytes(input));
        await using var stream = new EventScrubbingStream(inner, [Secret]);
        using var output = new MemoryStream();

        await stream.CopyToAsync(output);

        Assert.Equal(input, Encoding.UTF8.GetString(output.ToArray()));
        Assert.Equal(32768, inner.Destinations[0]);
        Assert.Equal(16384, inner.Destinations[1]);
    }

    [Theory]
    [InlineData("x\n\n\n\rb")]      // second event starts ON a ␊
    [InlineData("x\n\n\r\n\r\nb")]  // second event starts ON a ␍␊␍␊
    [InlineData("x\n\n\r\r\ny")]    // second event starts ON a ␍␍␊
    public void BoundaryClauses_AtOffsetZero_ReadForwardOnly(string input)
    {
        // After the first event flushes, the pending buffer restarts exactly at the
        // next boundary's first byte — every clause must read forward from there,
        // never behind the head (M31 triage: index-behind mutants faulted right here).
        using var stream = new EventScrubbingStream(
            new MemoryStream(Encoding.UTF8.GetBytes(input)), [Secret]);
        using var output = new MemoryStream();
        stream.CopyTo(output);

        Assert.Equal(input, Encoding.UTF8.GetString(output.ToArray()));
    }

    [Theory]
    [InlineData("data: a\nQ\n\rb\n\n", "a\nQ\n\rb")] // ␊Q␊␍ must not cut at the ␍
    [InlineData("data: Q\r\nX\nb\n\n", "Q\r\nX\nb")] // ␍␊X␊ must not cut as ␍␊␍␊
    [InlineData("data: X\r\rQ\nb\n\n", "X\r\rQ\nb")] // ␍␍Q␊ must not cut as ␍␍␊
    public void BoundaryClauses_CutOnlyAtTheirOwnSpelling(string input, string secret)
    {
        using var stream = new EventScrubbingStream(
            new MemoryStream(Encoding.UTF8.GetBytes(input)), [secret]);
        using var output = new MemoryStream();
        stream.CopyTo(output);

        Assert.Equal(input.Replace(secret, Redacted), Encoding.UTF8.GetString(output.ToArray()));
    }
}
