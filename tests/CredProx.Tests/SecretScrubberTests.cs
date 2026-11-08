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
        var (batch, batchLength, consumedThrough) = SecretScrubber.ScrubBatch(
            Encoding.UTF8.GetBytes(pending),
            emitLength,
            SecretScrubber.CompilePatterns(secrets),
            Repl);

        return (Encoding.UTF8.GetString(batch, 0, batchLength), batchLength, consumedThrough);
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
}
