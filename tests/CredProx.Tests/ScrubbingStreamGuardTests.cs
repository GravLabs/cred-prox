using System.Buffers;
using System.Text;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// Guards of the scrubbing read views that no framing or pool test reaches: Flush
/// never forwards to the inner stream, a sync read that meets inner EOF while bytes
/// are held back emits the held-back tail verbatim, and both dispose overloads racing
/// on separate threads still return every pooled buffer exactly once.
/// </summary>
public sealed class ScrubbingStreamGuardTests
{
    private const string Secret = "guard-token-0123456789abcdef";
    private const string Masked = "[redacted]";

    /// Rents and counts per-array returns so a double pool.Return is visible.
    private sealed class TrackingPool : ArrayPool<byte>
    {
        private readonly Dictionary<byte[], int> _returnCounts = new();
        private readonly object _gate = new();

        public int Rents;

        public int ReturnsWithoutClear;

        public override byte[] Rent(int minimumLength)
        {
            lock (_gate)
            {
                Rents++;
            }

            return new byte[Math.Max(minimumLength, 1)];
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

        /// <summary>How many distinct arrays came back — the sum alone hides a swap.</summary>
        public int DistinctReturned
        {
            get
            {
                lock (_gate)
                {
                    return _returnCounts.Count;
                }
            }
        }

        /// <summary>The most times any single array was returned.</summary>
        public int MaxReturnCount
        {
            get
            {
                lock (_gate)
                {
                    return _returnCounts.Count == 0 ? 0 : _returnCounts.Values.Max();
                }
            }
        }
    }

    /// Records every flush the wrapper performs on the inner stream.
    private sealed class FlushCountingStream : MemoryStream
    {
        public FlushCountingStream(byte[] buffer)
            : base(buffer)
        {
        }

        public int FlushCount;

        public override void Flush()
        {
            FlushCount++;
        }

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            FlushCount++;
            return Task.CompletedTask;
        }
    }

    private static string ReadToEndSync(Stream stream, int chunk)
    {
        using var output = new MemoryStream();
        var buffer = new byte[chunk];
        while (true)
        {
            var read = stream.Read(buffer, 0, buffer.Length);
            if (read == 0)
            {
                break;
            }

            output.Write(buffer, 0, read);
        }

        return Encoding.UTF8.GetString(output.ToArray());
    }

    [Fact]
    public async Task ByteStreamFlush_SyncAndAsync_DoNotForwardToInner_AndCostNothing()
    {
        var body = Encoding.UTF8.GetBytes($"x {Secret} y");
        await using var inner = new FlushCountingStream(body);
        await using var scrubbing = new ScrubbingStream(inner, [Secret]);

        scrubbing.Flush();
        await scrubbing.FlushAsync(CancellationToken.None);

        Assert.Equal(0, inner.FlushCount); // a read view has nothing to flush, and must not poke upstream

        // The stream stays fully usable after either flush.
        Assert.Equal($"x {Masked} y", ReadToEndSync(scrubbing, 7));
    }

    [Fact]
    public async Task EventStreamFlush_SyncAndAsync_DoNotForwardToInner_AndCostNothing()
    {
        await using var inner = new FlushCountingStream(Encoding.UTF8.GetBytes($"data: {Secret}\n\n"));
        await using var scrubbing = new EventScrubbingStream(inner, [Secret]);

        scrubbing.Flush();
        await scrubbing.FlushAsync(CancellationToken.None);

        Assert.Equal(0, inner.FlushCount);

        var emitted = await ReadAllAsync(scrubbing, 5);
        Assert.Equal("data: [redacted]\n\n", Encoding.UTF8.GetString(emitted));
    }

    [Fact]
    public void SyncRead_InnerEofWhileBytesHeldBack_EmitsHeldBackTailVerbatim()
    {
        // "SEC" is only the prefix of the secret: at the emit boundary five bytes are
        // held back awaiting continuation, but inner hits EOF immediately. The sync
        // read must zero the holdback on EOF and hand the tail out verbatim — the
        // bytes already known not to start a secret must not be trapped by it.
        using var inner = new MemoryStream("abcSEC"u8.ToArray());
        var scrubbing = new ScrubbingStream(inner, ["SECRET"]);

        var buffer = new byte[16];
        var first = scrubbing.Read(buffer, 0, buffer.Length);
        Assert.Equal("a", Encoding.UTF8.GetString(buffer, 0, first)); // boundary leaves 5 held back

        var second = scrubbing.Read(buffer, 0, buffer.Length);
        Assert.Equal("bcSEC", Encoding.UTF8.GetString(buffer, 0, second)); // EOF drained the holdback

        Assert.Equal(0, scrubbing.Read(buffer, 0, buffer.Length));
        scrubbing.Dispose();
    }

    [Fact]
    public async Task ConcurrentDispose_ByteStream_ReturnsEveryBufferExactlyOnce()
    {
        // Dispose() and DisposeAsync() released at the same instant both try to return
        // the live batch and the pending buffer; the Interlocked claims must let each
        // array back to the pool once, cleared, whichever thread wins.
        for (var round = 0; round < 300; round++)
        {
            var body = new string('x', 40 * 1024) + Secret; // pending + live batch at dispose
            using var inner = new MemoryStream(Encoding.UTF8.GetBytes(body));
            var pool = new TrackingPool();
            var scrubbing = new ScrubbingStream(inner, [Secret], pool: pool);

            var buffer = new byte[64];
            var read = await scrubbing.ReadAsync(buffer); // batch rented, far from drained
            Assert.True(read > 0);

            var gate = new ManualResetEventSlim(false);
            var syncDispose = Task.Run(() =>
            {
                gate.Wait();
                scrubbing.Dispose();
            });
            var asyncDispose = Task.Run(async () =>
            {
                gate.Wait();
                await scrubbing.DisposeAsync();
            });
            gate.Set();
            await Task.WhenAll(syncDispose, asyncDispose);

            Assert.Equal(pool.Rents, pool.TotalReturns); // batch AND pending, none twice
            Assert.Equal(pool.Rents, pool.DistinctReturned); // every rented array itself came back
            Assert.Equal(1, pool.MaxReturnCount); // none twice — a leak elsewhere cannot mask it
            Assert.Equal(0, pool.ReturnsWithoutClear);
        }
    }

    [Fact]
    public async Task ConcurrentDispose_EventStream_ReturnsEveryBufferExactlyOnce()
    {
        for (var round = 0; round < 300; round++)
        {
            var events = new StringBuilder();
            for (var i = 0; i < 30; i++)
            {
                events.Append("data: chunk").Append(i).Append('\n').Append('\n');
            }

            events.Append("data: ").Append(Secret).Append("\n\n");
            using var inner = new MemoryStream(Encoding.UTF8.GetBytes(events.ToString()));
            var pool = new TrackingPool();
            var scrubbing = new EventScrubbingStream(inner, [Secret], pool);

            var buffer = new byte[64];
            var read = await scrubbing.ReadAsync(buffer);
            Assert.True(read > 0);

            var gate = new ManualResetEventSlim(false);
            var syncDispose = Task.Run(() =>
            {
                gate.Wait();
                scrubbing.Dispose();
            });
            var asyncDispose = Task.Run(async () =>
            {
                gate.Wait();
                await scrubbing.DisposeAsync();
            });
            gate.Set();
            await Task.WhenAll(syncDispose, asyncDispose);

            Assert.Equal(pool.Rents, pool.TotalReturns);
            Assert.Equal(pool.Rents, pool.DistinctReturned);
            Assert.Equal(1, pool.MaxReturnCount);
            Assert.Equal(0, pool.ReturnsWithoutClear);
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
}
