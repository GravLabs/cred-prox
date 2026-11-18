using System.Buffers;
using System.Text;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage for <see cref="SecretScrubber">: the batch contract no
/// stream test reaches — the emit boundary is exclusive, a confirmed straddling
/// match consumes its tail, and both growth paths (mid-batch resize, tail resize)
/// keep every replacement. These paths only fire at arithmetic corners of the
/// over-allocated batch, which is why stream-level tests never touched them.
/// </summary>
public sealed class SecretScrubberTests
{
    private static readonly byte[] Repl = "[redacted]"u8.ToArray();

    private static (string Batch, int BatchLength, int ConsumedThrough) Scrub(
        string pending, int emitLength, params string[] secrets)
    {
        var pool = ArrayPool<byte>.Shared;
        var (batch, batchLength, consumedThrough) = SecretScrubber.ScrubBatch(
            Encoding.UTF8.GetBytes(pending),
            emitLength,
            SecretScrubber.CompilePatterns(secrets),
            Repl,
            pool);

        var result = (Encoding.UTF8.GetString(batch, 0, batchLength), batchLength, consumedThrough);
        pool.Return(batch, clearArray: true);
        return result;
    }

    // --- pattern compilation -------------------------------------------------------------

    [Fact]
    public void CompilePatterns_SkipsNullOrEmpty_OrdersLongestFirst()
    {
        var patterns = SecretScrubber.CompilePatterns([null!, "", "ab", "abcd"]);

        Assert.Collection(
            patterns,
            p => Assert.Equal("abcd", Encoding.UTF8.GetString(p)),
            p => Assert.Equal("ab", Encoding.UTF8.GetString(p)));
    }

    [Fact]
    public void Scrub_LongestPatternWins_AtSameStart()
    {
        var (batch, _, consumed) = Scrub("abcd", 4, "abc", "abcd");

        Assert.Equal("[redacted]", batch);
        Assert.Equal(4, consumed);
    }

    // --- emit boundary ---------------------------------------------------------------

    // A match that STARTS at the boundary belongs to the next batch: the loop is
    // exclusive of emitLength. (An empty-batch overflow flush relies on this.)
    [Fact]
    public void MatchStartingExactlyAtEmitBoundary_IsLeftToNextBatch()
    {
        var (batch, batchLength, consumed) = Scrub("xyab", 2, "ab");

        Assert.Equal("xy", batch);
        Assert.Equal(2, batchLength);
        Assert.Equal(2, consumed);
    }

    // A match fully present in pending but running past the boundary is a confirmed
    // secret: it is replaced and consumes its tail past the boundary.
    [Fact]
    public void MatchStraddlingEmitBoundary_IsReplacedAndConsumesItsTail()
    {
        var (batch, batchLength, consumed) = Scrub("xyabcd", 4, "abc");

        Assert.Equal("xy[redacted]", batch);
        Assert.Equal(12, batchLength);
        Assert.Equal(5, consumed); // match a-b-c ends at 5, one byte past the boundary
    }

    // --- growth paths -------------------------------------------------------------------

    // Two replacements plus literals exceed the initial capacity (emitLength + one
    // replacement): the mid-batch resize must fire and keep every replacement.
    [Fact]
    public void GrowthAcrossManyMatches_ResizesMidBatch_KeepsEveryReplacement()
    {
        var (batch, batchLength, consumed) = Scrub("zzabzzaby", 9, "ab");

        Assert.Equal("zz[redacted]zz[redacted]y", batch);
        Assert.Equal(25, batchLength);
        Assert.Equal(9, consumed);
    }

    // Geometry where every mid-batch needed fits the initial capacity exactly, but the
    // trailing literal after the last replacement overflows it: the tail resize must
    // fire. (batchLength == capacity exactly at the tail check.)
    [Fact]
    public void TailAfterExactCapacity_ResizesForTail_AndAppendsVerbatimBytes()
    {
        var (batch, batchLength, consumed) = Scrub("abab123456", 10, "ab");

        Assert.Equal("[redacted][redacted]123456", batch);
        Assert.Equal(26, batchLength);
        Assert.Equal(10, consumed);
    }

    // No secrets and no matches: the batch is the emit region verbatim.
    [Fact]
    public void NoMatches_BatchIsEmitRegionVerbatim()
    {
        var (batch, batchLength, consumed) = Scrub("hello world", 5, "zz");

        Assert.Equal("hello", batch);
        Assert.Equal(5, batchLength);
        Assert.Equal(5, consumed);
    }

    // --- growth paths, proven with exact-size rents --------------------------------------
    //
    // ArrayPool.Shared rounds every rent up to the next power-of-two bucket, so the
    // geometry above never actually resized. An exact-size pool makes each resize
    // observable: the requested-size sequence pins WHICH branch fired (the mid-batch
    // branch doubles, the tail branch rents exactly what remains) and the return counts
    // pin that every displaced array goes back to the pool cleared.

    private sealed class ExactSizePool : ArrayPool<byte>
    {
        private readonly Dictionary<byte[], int> _returns = new();
        private readonly object _gate = new();
        private readonly int _throwOnRent;
        private int _rents;

        public ExactSizePool(int throwOnRent = 0) => _throwOnRent = throwOnRent;

        public List<int> RentSizes { get; } = [];

        public int TotalReturns
        {
            get
            {
                lock (_gate)
                {
                    return _returns.Values.Sum();
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
                    return _returns.Count;
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
                    return _returns.Count == 0 ? 0 : _returns.Values.Max();
                }
            }
        }

        public int ReturnsWithoutClear
        {
            get
            {
                lock (_gate)
                {
                    return _withoutClear;
                }
            }
        }

        private int _withoutClear;

        public override byte[] Rent(int minimumLength)
        {
            lock (_gate)
            {
                _rents++;
                if (_rents == _throwOnRent)
                {
                    throw new InvalidOperationException("injected rent failure");
                }

                RentSizes.Add(minimumLength);
            }

            return new byte[Math.Max(minimumLength, 1)];
        }

        public override void Return(byte[] array, bool clearArray = false)
        {
            lock (_gate)
            {
                _returns.TryGetValue(array, out var n);
                _returns[array] = n + 1;
                if (!clearArray)
                {
                    _withoutClear++;
                }
            }
        }
    }

    [Fact]
    public void MidBatchGrowth_ExactPool_DoublesRentAndDisplacedArrayReturnsCleared()
    {
        // Same geometry as GrowthAcrossManyMatches: the second replacement needs 24 bytes
        // against a 19-byte batch, so the mid-batch branch re-rents max(24, 2*19) = 38.
        var pool = new ExactSizePool();
        var (batch, batchLength, consumedThrough) = SecretScrubber.ScrubBatch(
            Encoding.UTF8.GetBytes("zzabzzaby"), 9, SecretScrubber.CompilePatterns(["ab"]), Repl, pool);

        var text = Encoding.UTF8.GetString(batch, 0, batchLength);
        pool.Return(batch, clearArray: true);

        Assert.Equal("zz[redacted]zz[redacted]y", text);
        Assert.Equal(25, batchLength);
        Assert.Equal(9, consumedThrough);
        Assert.Equal([19, 38], pool.RentSizes);
        Assert.Equal(2, pool.TotalReturns); // displaced array + caller's batch
        Assert.Equal(2, pool.DistinctReturned); // each one, not one array twice
        Assert.Equal(1, pool.MaxReturnCount);
        Assert.Equal(0, pool.ReturnsWithoutClear); // secret-bearing buffers always cleared
    }

    [Fact]
    public void TailGrowth_ExactPool_RentsExactlyTheRemainingTail()
    {
        // Same geometry as TailAfterExactCapacity: every mid-batch need fits the 20-byte
        // initial rent exactly, and only the 6-byte tail overflows — so the tail branch
        // fires once, with a rent of 20 + 6 and no doubling.
        var pool = new ExactSizePool();
        var (batch, batchLength, consumedThrough) = SecretScrubber.ScrubBatch(
            Encoding.UTF8.GetBytes("abab123456"), 10, SecretScrubber.CompilePatterns(["ab"]), Repl, pool);

        var text = Encoding.UTF8.GetString(batch, 0, batchLength);
        pool.Return(batch, clearArray: true);

        Assert.Equal("[redacted][redacted]123456", text);
        Assert.Equal(26, batchLength);
        Assert.Equal(10, consumedThrough);
        Assert.Equal([20, 26], pool.RentSizes);
        Assert.Equal(2, pool.TotalReturns);
        Assert.Equal(2, pool.DistinctReturned);
        Assert.Equal(1, pool.MaxReturnCount);
        Assert.Equal(0, pool.ReturnsWithoutClear);
    }

    [Fact]
    public void RentFailureMidGrowth_ReturnsStillOwnedBufferClearedOnce()
    {
        // The growth rent throws: the batch rented at entry was never handed to the
        // caller, so the guard in the finally must return exactly that buffer, cleared.
        var pool = new ExactSizePool(throwOnRent: 2);

        Assert.Throws<InvalidOperationException>(() => SecretScrubber.ScrubBatch(
            Encoding.UTF8.GetBytes("zzabzzaby"), 9, SecretScrubber.CompilePatterns(["ab"]), Repl, pool));

        Assert.Equal([19], pool.RentSizes); // the second rent never completed
        Assert.Equal(1, pool.TotalReturns); // only the still-owned entry buffer
        Assert.Equal(1, pool.DistinctReturned);
        Assert.Equal(1, pool.MaxReturnCount);
        Assert.Equal(0, pool.ReturnsWithoutClear);
    }
}
