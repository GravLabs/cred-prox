using System.Buffers;
using System.Diagnostics;
using System.Text;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M35: the scrubbing batch and the pending buffer come from an
/// <see cref="ArrayPool{T}"/>. These pin the pooling contract: (a) a dirty rented
/// array — filled here with sentinel bytes — never leaks into emitted output
/// (nothing is read past the logical length); (b) every buffer is returned exactly
/// once, cleared, even when the stream is abandoned mid-read and both Dispose paths
/// run; (c) redaction of secrets split across chunk boundaries, and SSE per-event
/// flushing, stay green through the pool, including a zero-length probe read
/// between reads.
/// </summary>
public sealed class ScrubbingPoolTests
{
    private const string Secret = "s3cr3t-token-0123456789abcdef";
    private const string Masked = "[redacted]";

    /// Rents exact-length arrays pre-filled with a sentinel (worst case for any read
    /// past the logical length) and counts returns per array instance.
    private sealed class TrackingPool : ArrayPool<byte>
    {
        public const byte Sentinel = 0xAA;

        private readonly Dictionary<byte[], int> _returnCounts = new();
        private readonly object _gate = new();

        public int Rents;

        public int ReturnsWithoutClear;

        public override byte[] Rent(int minimumLength)
        {
            var array = new byte[Math.Max(minimumLength, 1)];
            Array.Fill(array, Sentinel);
            lock (_gate)
            {
                Rents++;
            }

            return array;
        }

        public override void Return(byte[] array, bool clearArray = false)
        {
            lock (_gate)
            {
                _returnCounts.TryGetValue(array, out var n);
                _returnCounts[array] = n + 1;
                if (!clearArray)
                {
                    ReturnsWithoutClear++;
                }
            }
        }

        public int TotalReturns
        {
            get
            {
                lock (_gate)
                {
                    return _returnCounts.Values.Sum();
                }
            }
        }
    }

    private static async Task<byte[]> ReadAllAsync(Stream stream, int chunk)
    {
        using var output = new MemoryStream();
        var buffer = new byte[chunk];
        while (true)
        {
            var read = await stream.ReadAsync(buffer);
            if (read == 0)
            {
                break;
            }

            output.Write(buffer, 0, read);
        }

        return output.ToArray();
    }

    [Fact]
    public async Task ByteStream_DirtyRents_SecretSplitAcrossChunks_NoSentinelLeaks()
    {
        // ~40 KB body with the secret straddling the 16 KB fill boundary.
        var body = new StringBuilder()
            .Append('a', (16 * 1024) - (Secret.Length / 2))
            .Append(Secret)
            .Append('b', 24 * 1024)
            .ToString();

        await using var inner = new MemoryStream(Encoding.UTF8.GetBytes(body));
        var pool = new TrackingPool();
        var scrubbing = new ScrubbingStream(inner, [Secret], pool);

        var emitted = await ReadAllAsync(scrubbing, 4099); // ragged reads across batches

        await scrubbing.DisposeAsync(); // pending returns at dispose: settle before asserting

        var expected = Encoding.UTF8.GetBytes(body.Replace(Secret, Masked));
        Assert.Equal(expected, emitted);
        Assert.DoesNotContain(TrackingPool.Sentinel, emitted);
        Assert.True(pool.Rents > 1, "multi-chunk body must produce multiple batches");
        Assert.Equal(pool.Rents, pool.TotalReturns); // every rent returned, none twice
        Assert.Equal(0, pool.ReturnsWithoutClear); // secret-bearing buffers return cleared
    }

    [Fact]
    public async Task ByteStream_AbortMidStream_ReturnsLiveBatchExactlyOnce()
    {
        var body = new string('x', 64 * 1024) + Secret; // one big batch, never drained
        using var inner = new MemoryStream(Encoding.UTF8.GetBytes(body));
        var pool = new TrackingPool();
        var scrubbing = new ScrubbingStream(inner, [Secret], pool);

        var buffer = new byte[4096];
        var read = await scrubbing.ReadAsync(buffer);
        Assert.True(read > 0);
        Assert.True(pool.Rents > 0, "the first read must have rented a batch");

        scrubbing.Dispose();
        await scrubbing.DisposeAsync(); // double dispose must not double-return

        Assert.Equal(pool.Rents, pool.TotalReturns); // batch AND pending, none twice
        Assert.Equal(0, pool.ReturnsWithoutClear);
    }

    [Fact]
    public async Task Sse_ManyEvents_SecretSplitInsideEvent_ProbeRead_NoSentinelLeaks()
    {
        // Many small events (the per-event batch churn the +51 KB came from) plus one
        // ~35 KB event carrying a secret across a fill boundary.
        var events = new StringBuilder();
        for (var i = 0; i < 200; i++)
        {
            events.Append("data: tick-").Append(i).Append("\n\n");
        }

        events
            .Append("data: ")
            .Append('k', (16 * 1024) - (Secret.Length / 2))
            .Append(Secret)
            .Append('z', 20 * 1024)
            .Append("\n\n");

        var body = events.ToString();
        await using var inner = new MemoryStream(Encoding.UTF8.GetBytes(body));
        var pool = new TrackingPool();
        var scrubbing = new EventScrubbingStream(inner, [Secret], pool);

        using var output = new MemoryStream();
        var buffer = new byte[1021];
        while (true)
        {
            var read = await scrubbing.ReadAsync(buffer);
            if (read == 0)
            {
                break;
            }

            output.Write(buffer, 0, read);

            // Zero-length probe read: must return 0 and change no state.
            Assert.Equal(0, await scrubbing.ReadAsync(Memory<byte>.Empty));
        }

        await scrubbing.DisposeAsync(); // pending returns at dispose: settle before asserting

        var emitted = output.ToArray();
        var expected = Encoding.UTF8.GetBytes(body.Replace(Secret, Masked));
        Assert.Equal(expected, emitted);
        Assert.DoesNotContain(TrackingPool.Sentinel, emitted);
        Assert.True(pool.Rents > 200, "each event must produce its own pooled batch");
        Assert.Equal(pool.Rents, pool.TotalReturns);
        Assert.Equal(0, pool.ReturnsWithoutClear);
    }

    [Fact]
    public async Task Dispose_ThenRead_ThrowsObjectDisposed_AndNeverTouchesPool()
    {
        // After pooling, a post-dispose read is not just a contract violation — it
        // writes into buffers the pool may be handing to another request. Every
        // read path must refuse, and nothing may re-rent or double-return.
        using var inner = new MemoryStream(new byte[64]);
        var pool = new TrackingPool();
        var scrubbing = new ScrubbingStream(inner, [Secret], pool);
        await scrubbing.DisposeAsync();

        var buffer = new byte[16];
#pragma warning disable CA2022 // the read never materializes: every call below must throw first
        await Assert.ThrowsAsync<ObjectDisposedException>(async () => await scrubbing.ReadAsync(buffer));
        Assert.Throws<ObjectDisposedException>(() => scrubbing.Read(buffer, 0, buffer.Length));
        Assert.Throws<ObjectDisposedException>(() => scrubbing.Read(buffer.AsSpan()));
        await Assert.ThrowsAsync<ObjectDisposedException>(async () => await scrubbing.ReadAsync(Memory<byte>.Empty)); // disposed beats the probe shortcut

        var sse = new EventScrubbingStream(new MemoryStream(new byte[64]), [Secret], pool);
        await sse.DisposeAsync();
        await Assert.ThrowsAsync<ObjectDisposedException>(async () => await sse.ReadAsync(buffer));
#pragma warning restore CA2022

        Assert.Equal(pool.Rents, pool.TotalReturns); // dispose returned everything; reads added nothing
        Assert.Equal(0, pool.ReturnsWithoutClear);
    }

    /// <summary>
    /// An inner stream whose <c>ReadAsync</c> parks until the test releases it,
    /// and only then writes bytes into the destination — the exact shape of a
    /// transport mid-read when Dispose lands (F1): the write into the pooled
    /// pending buffer happens strictly after dispose completed.
    /// </summary>
    private sealed class ParkedReadStream : Stream
    {
        private readonly TaskCompletionSource _entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource<int> _release = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int ReadsIssued;

        public Task ReadEntered => _entered.Task;

        public void Release(int byteCount) => _release.SetResult(byteCount);

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override async ValueTask<int> ReadAsync(Memory<byte> destination, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref ReadsIssued);
            _entered.TrySetResult();
            var result = await _release.Task.ConfigureAwait(false);
            destination.Span.Slice(0, result).Fill(0x41); // RAW response bytes, post-dispose
            return result;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    [Fact]
    public async Task DisposeWhileReadInFlight_DefersPendingReturnToReaderFinally_ByteStream()
    {
        // F1 regression: dispose lands while an inner read is parked with the
        // pending buffer as its destination. Dispose must complete without
        // returning that buffer; the resuming read must discard what the
        // transport wrote and fail closed; its finally then performs the single
        // cleared return.
        await using var inner = new ParkedReadStream();
        var pool = new TrackingPool();
        var scrubbing = new ScrubbingStream(inner, [Secret], pool);

        var buffer = new byte[4096];
        var readTask = scrubbing.ReadAsync(buffer).AsTask();
        await inner.ReadEntered.WaitAsync(TimeSpan.FromSeconds(5));

        await scrubbing.DisposeAsync(); // completes while the read is parked

        // Pending still unreleased: the parked read may write into it (hazard 2).
        Assert.Equal(0, pool.TotalReturns);

        inner.Release(64); // transport lands RAW bytes after dispose completed
        await Assert.ThrowsAsync<ObjectDisposedException>(() => readTask);

        Assert.Equal(pool.Rents, pool.TotalReturns); // the reader's finally returned it, once
        Assert.Equal(0, pool.ReturnsWithoutClear);
        Assert.Equal(1, inner.ReadsIssued); // nothing further was issued into the doomed buffer

        scrubbing.Dispose(); // double dispose after the transfer: still one return
        Assert.Equal(pool.Rents, pool.TotalReturns);
    }

    [Fact]
    public async Task DisposeWhileReadInFlight_StopsSseProduceLoop_AndReturnsPendingOnce()
    {
        // F1 regression on the SSE arm: pre-fix the produce loop never re-checked
        // dispose — it re-entered FillPendingAsync forever (1261 late reads in a
        // synthetic parked-read probe), re-renting and writing into pool-owned
        // memory.
        await using var inner = new ParkedReadStream();
        var pool = new TrackingPool();
        var scrubbing = new EventScrubbingStream(inner, [Secret], pool);

        var buffer = new byte[4096];
        var readTask = scrubbing.ReadAsync(buffer).AsTask();
        await inner.ReadEntered.WaitAsync(TimeSpan.FromSeconds(5));

        await scrubbing.DisposeAsync();
        Assert.Equal(0, pool.TotalReturns);

        inner.Release(64);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => readTask);

        Assert.Equal(1, inner.ReadsIssued); // the disposed check stopped the loop
        Assert.Equal(pool.Rents, pool.TotalReturns);
        Assert.Equal(0, pool.ReturnsWithoutClear);
    }

    /// <summary>
    /// A recycling pool (returned arrays go back out to the next rent, like
    /// <see cref="ArrayPool{T}"/>.Shared) that also counts double-returns. The R1
    /// stress below uses it so a batch returned during a stale copy immediately
    /// reappears as a live rent — the exact window R1 closes.
    /// </summary>
    private sealed class ReusePool : ArrayPool<byte>
    {
        private readonly Stack<byte[]> _free = new();
        private readonly HashSet<byte[]> _out = new(); // currently-rented instances
        private readonly object _gate = new();
        private byte[]? _lastRentArray;
        private long _lastRentTimestamp;
        private int _lastRentThread;

        public int Rents;
        public int Returns;

        /// <summary>
        /// Rent-to-drain span of the most recent batch this pool saw complete
        /// (return of the last-rented array by the renting thread — the
        /// CopyOutput drain path). The stress disposer aims dispose relative to
        /// this measured window: the scrub phase inside a read is long and
        /// content-shaped, so only the stream's own timing knows when the copy
        /// is running.
        /// </summary>
        public long LastDrainSpanTimestamps;

        public override byte[] Rent(int minimumLength)
        {
            lock (_gate)
            {
                Rents++;
                byte[]? array = null;
                // LIFO but size-aware (the shared pool buckets by size): pop the
                // most recent array that fits, set the rest aside.
                var aside = new List<byte[]>();
                while (_free.Count > 0)
                {
                    var candidate = _free.Pop();
                    if (candidate.Length >= minimumLength)
                    {
                        array = candidate;
                        break;
                    }

                    aside.Add(candidate);
                }

                foreach (var small in aside)
                {
                    _free.Push(small);
                }

                array ??= new byte[Math.Max(minimumLength, 1)];
                _out.Add(array);
                _lastRentArray = array;
                _lastRentTimestamp = Stopwatch.GetTimestamp();
                _lastRentThread = Environment.CurrentManagedThreadId;
                return array;
            }
        }

        public override void Return(byte[] array, bool clearArray = false)
        {
            long drainSpan = 0;
            if (clearArray)
            {
                Array.Clear(array, 0, array.Length);
            }

            lock (_gate)
            {
                Returns++;
                if (array == _lastRentArray && Environment.CurrentManagedThreadId == _lastRentThread)
                {
                    drainSpan = Stopwatch.GetTimestamp() - _lastRentTimestamp; // the batch's live span
                }

                if (!_out.Remove(array))
                {
                    DoubleReturn = true; // returned while not owned: the R1/F1 class
                }

                _free.Push(array);
            }

            if (drainSpan != 0)
            {
                Interlocked.Exchange(ref LastDrainSpanTimestamps, drainSpan);
            }
        }

        public bool DoubleReturn;
    }

    // R1 stress. CopyOutput has no await, so a reader cannot be literally parked
    // inside it — there is no seam to park in, and a test-side post-dispose stamp
    // loses the microsecond race to the copy in flight. So let the pool itself be
    // the second writer the ruling warns about: every Return here is clearArray:
    // true (like the production call sites), so on the broken shape a dispose
    // landing while the sync reader is mid-CopyOutput hands Array.Clear of the
    // live batch a race against that copy. The copy is deliberately slow — a
    // freshly-allocated destination first-touches page by page at a few GB/s —
    // while Clear overtakes it at memory bandwidth, so the reader deterministically
    // lands on cleared (0x00) bytes: a byte its own body cannot produce. That is
    // the exposure witness, no second-request timing lottery involved. With
    // ownership transfer a mid-copy batch can never reach Return at all, so no
    // concurrent Clear exists: always green, never flakes.
    private static void RunR1Stress(bool eventStream, int iterations, byte[] victimBody, string ownAlphabet, int firstRead, int readSpread, int victims, int destinationSize)
    {
        var expected = new bool[256];
        foreach (var c in ownAlphabet)
        {
            expected[c] = true;
        }

        for (var iteration = 0; iteration < iterations; iteration++)
        {
            string? exposure = null;
            var threads = new List<Thread>();
            var pools = new List<ReusePool>();

            for (var v = 0; v < victims; v++)
            {
                // Pool per victim: a rent on this pool is then exactly this
                // victim's stream renting — the disposer's batch-rent trigger.
                var pool = new ReusePool();
                pools.Add(pool);
                var inner = new MemoryStream(victimBody);
                var stream = eventStream
                    ? (Stream)new EventScrubbingStream(inner, [Secret], pool)
                    : new ScrubbingStream(inner, [Secret], pool);

                // Target reads that land mid-drain: the live batch is partially
                // copied out at every one of them, which is the R1 window.
                var target = firstRead + (iteration * 7 + v * 3) % readSpread;
                int reads = 0;
                int inRead = 0; // 1 while inside a Read call — the disposer's trigger
                int done = 0;

                var victim = new Thread(() =>
                {
                    try
                    {
                        reads = 0;
                        while (true)
                        {
                            // Fresh LOH buffer per read (> 85 KB ⇒ fresh mmap,
                            // real first-touch page faults): the batch copy into
                            // it runs at page-fault pace, below the pool's
                            // Array.Clear speed — what turns a mid-copy dispose
                            // into visible cleared bytes instead of a lost race.
                            // ReadAsync (not the sync path) so the batch copy is
                            // the single destination copy.
                            var buffer = new byte[destinationSize];
                            Volatile.Write(ref inRead, 1);
                            var read = stream.ReadAsync(buffer).AsTask().GetAwaiter().GetResult();
                            Volatile.Write(ref inRead, 0);
                            Interlocked.Increment(ref reads);
                            if (read == 0)
                            {
                                return;
                            }

                            for (var i = 0; i < read; i++)
                            {
                                if (!expected[buffer[i]])
                                {
                                    lock (expected)
                                    {
                                        exposure ??= $"iter {iteration} victim {v}: foreign byte 0x{buffer[i]:X2} at offset {i}";
                                    }

                                    return;
                                }
                            }
                        }
                    }
                    catch (ObjectDisposedException)
                    {
                        // The expected outcome of racing a dispose.
                    }
                    finally
                    {
                        Volatile.Write(ref done, 1);
                        stream.Dispose();
                    }
                });

                var disposer = new Thread(() =>
                {
                    var sw = Stopwatch.StartNew();
                    while (Volatile.Read(ref reads) < target && Volatile.Read(ref done) == 0 && sw.ElapsedMilliseconds < 5000)
                    {
                        Thread.SpinWait(100);
                    }

                    if (Volatile.Read(ref done) != 0)
                    {
                        return; // race lost to EOF: nothing to interrupt
                    }

                    // Each rent on this victim's pool is the batch rent that
                    // opens a read's scrub→copy span: the pool is the only
                    // observer of that moment. Aim just before the span the pool
                    // measured for the last batch's rent→drain; if the read ends
                    // first (aim overshot), re-arm on the next rent — the single
                    // dispose fires only with a read still in flight.
                    for (var shot = 0; shot < 32 && Volatile.Read(ref done) == 0; shot++)
                    {
                        var lastRents = Volatile.Read(ref pool.Rents);
                        var mark = Stopwatch.GetTimestamp();
                        while (Volatile.Read(ref pool.Rents) == lastRents
                               && Volatile.Read(ref done) == 0
                               && Stopwatch.GetElapsedTime(mark).TotalMilliseconds < 100)
                        {
                            Thread.SpinWait(20);
                        }

                        if (Volatile.Read(ref done) != 0 || Volatile.Read(ref pool.Rents) == lastRents)
                        {
                            return;
                        }

                        var span = Interlocked.Read(ref pool.LastDrainSpanTimestamps);
                        var jitterMicros = (iteration * 977 + v * 331 + shot * 131) % 7 - 3;
                        var aim = span > 0
                            ? TimeSpan.FromSeconds((double)span / Stopwatch.Frequency) - TimeSpan.FromMicroseconds(6 - jitterMicros)
                            : TimeSpan.FromMicroseconds(40); // blind before the first drain
                        var rentT = Stopwatch.GetTimestamp();
                        while (Stopwatch.GetElapsedTime(rentT) < aim
                               && Volatile.Read(ref inRead) == 1 && Volatile.Read(ref done) == 0)
                        {
                            Thread.SpinWait(20);
                        }

                        if (Volatile.Read(ref inRead) == 1 && Volatile.Read(ref done) == 0
                            && Stopwatch.GetElapsedTime(rentT) >= aim)
                        {
                            stream.Dispose(); // broken shape: live batch returned mid-copy
                            return;
                        }
                    }
                });

                threads.Add(victim);
                threads.Add(disposer);
            }

            foreach (var t in threads)
            {
                t.Start();
            }

            foreach (var t in threads)
            {
                t.Join(TimeSpan.FromSeconds(15));
            }

            Assert.True(exposure is null, "R1 use-after-return: " + exposure);
            Assert.All(pools, p => Assert.False(p.DoubleReturn, "a buffer was returned while still owned"));
        }
    }

    [Fact]
    public void DisposeDuringBatchCopy_NeverReRentTheLiveBatch_ByteStream()
    {
        // A long body: every mid-drain target read sits inside some batch's copy
        // phase, which is where the disposer aims.
        var body = Encoding.UTF8.GetBytes(new string('a', 200 * 1024) + Secret + new string('a', 4096));
        // 'a' padding and the [redacted] mask: the full own-byte alphabet.
        RunR1Stress(eventStream: false, iterations: 150, body, ownAlphabet: "a[redacted]", firstRead: 2, readSpread: 5, victims: 4, destinationSize: 150 * 1024);
    }

    [Fact]
    public void DisposeDuringBatchCopy_NeverReRentTheLiveBatch_SseStream()
    {
        // Two events past the 64 KB cap: the degraded path emits a ~96 KB batch
        // per event, and the 128 KB destination drains it within one read —
        // putting the SSE arm on the same in-read copy window the byte arm
        // interrupts (read 1 teaches the pool the span, read 3 is the big batch
        // aimed at; the small tail-batch reads are harmless misses).
        var bigEvent = "data: " + new string('a', 100 * 1024) + Secret + "\n\n";
        var body = Encoding.UTF8.GetBytes(bigEvent + bigEvent);
        // "data: " framing, 'a' payload, mask, blank-line terminators.
        RunR1Stress(eventStream: true, iterations: 120, body, ownAlphabet: "data: \n[redacted]", firstRead: 1, readSpread: 3, victims: 3, destinationSize: 128 * 1024);
    }

    [Fact]
    public async Task Sse_AbortMidLargeEvent_ReturnsPendingAndBatchExactlyOnce()
    {
        // One event beyond the 64 KB cap: pending grows (each step rent-copy,
        // old returned cleared) and a degraded batch is still live at abort.
        // Both must return exactly once, cleared, across double dispose.
        var body = "data: " + new string('q', 64 * 1024) + Secret + "\n\n";
        using var inner = new MemoryStream(Encoding.UTF8.GetBytes(body));
        var pool = new TrackingPool();
        var scrubbing = new EventScrubbingStream(inner, [Secret], pool);

        var buffer = new byte[4096];
        Assert.True(await scrubbing.ReadAsync(buffer) > 0);
        Assert.True(pool.Rents > 1, "the oversized event must have grown the pending buffer");

        scrubbing.Dispose();
        await scrubbing.DisposeAsync();

        Assert.Equal(pool.Rents, pool.TotalReturns);
        Assert.Equal(0, pool.ReturnsWithoutClear);
    }
}
