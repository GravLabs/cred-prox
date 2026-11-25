using System.Text;
using CredProx;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// §5.2 (M50 row): JSON usage-reader units — split-token rescan, malformed tail,
/// usage-absent. The reader walks the bytes held so far on every chunk from offset 0
/// (options-ctor whole-document shape), so the split cells are the core witness that a
/// token cut at any boundary still settles to the provider's values, and the malformed
/// cells pin "settled values stand, nothing guessed".
/// </summary>
public sealed class CredProxMeteringJsonReaderTests
{
    private const string Complete = """{"id":"msg_1","usage":{"input_tokens":120,"output_tokens":340},"stop_reason":"end_turn"}""";

    private static readonly byte[] CompleteBytes = Encoding.UTF8.GetBytes(Complete);

    private static (long? In, long? Out) Feed(AnthropicJsonUsageReader reader, byte[] bytes, params int[] splits)
    {
        var offset = 0;
        foreach (var split in splits)
        {
            reader.Observe(bytes.AsSpan(offset, split - offset), endOfStream: false);
            offset = split;
        }

        reader.Observe(bytes.AsSpan(offset), endOfStream: true);
        return (reader.InputTokens, reader.OutputTokens);
    }

    [Fact]
    public void CompleteDocumentInOneChunk_ReportsBothTokenCounts()
    {
        var (input, output) = Feed(new AnthropicJsonUsageReader(), CompleteBytes);
        Assert.Equal(120, input);
        Assert.Equal(340, output);
    }

    [Fact]
    public void NonPositiveTokenCounts_AreNotReported()
    {
        // M50 fold LOW-1: a non-positive count is not a report — nothing is recorded, so a
        // hostile or buggy vendor body can never drive a monotonic counter down.
        var bytes = Encoding.UTF8.GetBytes(
            """{"id":"msg_1","usage":{"input_tokens":-5,"output_tokens":0},"stop_reason":"end_turn"}""");
        var (input, output) = Feed(new AnthropicJsonUsageReader(), bytes);
        Assert.Null(input);
        Assert.Null(output);
    }

    [Fact]
    public void UsageNestedOutsideRootDepth_IsIgnored()
    {
        // M50 fold LOW-2 decoy (pin for the already root-depth-gated JSON reader, so the two
        // transports agree): a "usage" at depth 3 carrying large counts must not count;
        // only the root-depth usage does.
        var bytes = Encoding.UTF8.GetBytes(
            """{"id":"msg_1","meta":{"block":{"usage":{"input_tokens":99999,"output_tokens":99999}}},"usage":{"input_tokens":120,"output_tokens":340}}""");
        var (input, output) = Feed(new AnthropicJsonUsageReader(), bytes);
        Assert.Equal(120, input);
        Assert.Equal(340, output);
    }

    [Theory]
    // Inside the input number, between the two usage fields, inside "output" key,
    // inside the trailing member, and just before the final brace.
    [InlineData(new[] { 30 })]
    [InlineData(new[] { 40 })]
    [InlineData(new[] { 40, 55 })]
    [InlineData(new[] { 40, 55, 78 })]
    [InlineData(new[] { 40, 55, 78, 86 })]
    public void TokenCutAtAnyBoundary_RescansToTheSameValues(int[] splits)
    {
        var (input, output) = Feed(new AnthropicJsonUsageReader(), CompleteBytes, splits);
        Assert.Equal(120, input);
        Assert.Equal(340, output);
    }

    [Fact]
    public void UsageAbsent_StaysUnmetered()
    {
        var bytes = Encoding.UTF8.GetBytes("""{"id":"msg_1","content":[],"stop_reason":"end_turn"}""");
        var (input, output) = Feed(new AnthropicJsonUsageReader(), bytes);
        Assert.Null(input);
        Assert.Null(output);
    }

    [Fact]
    public void MalformedAfterCompleteUsage_SettledValuesStand()
    {
        var bytes = Encoding.UTF8.GetBytes("""{"usage":{"input_tokens":5,"output_tokens":7}} <<< trailing garbage""");
        var (input, output) = Feed(new AnthropicJsonUsageReader(), bytes);
        Assert.Equal(5, input);
        Assert.Equal(7, output);
    }

    [Fact]
    public void MalformedBeforeUsageClose_FinalIsWhatWasRead_NothingGuessed()
    {
        var bytes = Encoding.UTF8.GetBytes("""{"usage":{"input_tokens":9,,"broken":}""");
        var (input, output) = Feed(new AnthropicJsonUsageReader(), bytes);
        Assert.Equal(9, input);
        Assert.Null(output);
    }

    [Fact]
    public void TruncatedUsageAtEof_SettledFieldStands()
    {
        var bytes = Encoding.UTF8.GetBytes("""{"usage":{"input_tokens":42,"output_to""");
        var (input, output) = Feed(new AnthropicJsonUsageReader(), bytes);
        Assert.Equal(42, input);
        Assert.Null(output);
    }

    [Fact]
    public void ZeroLengthFinalProbeAfterCompleteDocumentStaysUnmetered()
    {
        var reader = new AnthropicJsonUsageReader();
        reader.Observe(Encoding.UTF8.GetBytes("""{"id":"x"}"""), endOfStream: false);
        reader.Observe([], endOfStream: true);
        Assert.Null(reader.InputTokens);
        Assert.Null(reader.OutputTokens);
    }

    [Fact]
    public void NonNumericUsageValues_AreNotCounted()
    {
        var bytes = Encoding.UTF8.GetBytes("""{"usage":{"input_tokens":"120","output_tokens":null}}""");
        var (input, output) = Feed(new AnthropicJsonUsageReader(), bytes);
        Assert.Null(input);
        Assert.Null(output);
    }

    [Fact]
    public void NumbersNestedInsideUsageStructures_AreNotTopLevelUsageFields()
    {
        var bytes = Encoding.UTF8.GetBytes(
            """{"usage":{"cache_creation_input_tokens":{"ephemeral_5m_input_tokens":999},"output_tokens":21}}""");
        var (input, output) = Feed(new AnthropicJsonUsageReader(), bytes);
        Assert.Null(input);
        Assert.Equal(21, output);
    }

    [Fact]
    public void SecondUsageObjectAfterClose_DoesNotRecount()
    {
        // Not a legal single JSON document, but the reader must never double-count if a
        // concatenated stream shape ever reaches it: the first settled usage stands.
        var bytes = Encoding.UTF8.GetBytes("""{"usage":{"input_tokens":1,"output_tokens":2}}{"usage":{"input_tokens":9,"output_tokens":9}}""");
        var (input, output) = Feed(new AnthropicJsonUsageReader(), bytes);
        Assert.Equal(1, input);
        Assert.Equal(2, output);
    }

    [Theory]
    [InlineData("application/json", true)]
    [InlineData("application/JSON", true)]
    [InlineData("application/vnd.anthropic+json", true)]
    [InlineData("application/json; charset=utf-8", false)] // the feature passes the bare media type; a full header value is not claimed
    [InlineData("text/event-stream", false)]
    [InlineData("text/plain", false)]
    [InlineData(null, false)]
    public void CanRead_ClaimsExactJsonAndPlusJsonSuffixes(string? mediaType, bool expected) =>
        Assert.Equal(expected, new AnthropicJsonUsageReader().CanRead(mediaType));

    [Fact]
    public void FreshReaderPerCall_KeepsNoState()
    {
        var first = new AnthropicJsonUsageReader();
        Feed(first, CompleteBytes);
        Assert.Equal(120, first.InputTokens);

        var second = new AnthropicJsonUsageReader();
        second.Observe(Encoding.UTF8.GetBytes("""{"id":"x"}"""), endOfStream: true);
        Assert.Null(second.InputTokens);
        Assert.Null(second.OutputTokens);
    }

    [Fact]
    public void ConstructionStaysCheapUntilBytesArrive()
    {
        // Same M50 rule as the SSE reader: construction plus an empty-stream end must
        // not allocate the working window; the growth path still reaches 8192 on the
        // first real chunk (exercised by every parsing cell above).
        GC.GetAllocatedBytesForCurrentThread(); // settle the measuring machinery
        var before = GC.GetAllocatedBytesForCurrentThread();
        var reader = new AnthropicJsonUsageReader();
        Assert.False(reader.CanRead("text/event-stream"));
        reader.Observe([], endOfStream: true);
        Assert.Null(reader.InputTokens);
        var cost = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.True(
            cost < 16 * 1024,
            $"constructing and ending an empty JSON reader allocated {cost} bytes");
    }

    [Fact]
    public void OverflowNumberInUsage_DoesNotEndTheWindow_LaterGoodFieldStillCounts()
    {
        // M50 fold INFO-a: GetInt64 threw on an int64-overflow token and the peek's catch
        // ended the whole parse window with it — a valid output_tokens later in the same
        // body was lost. TryGetInt64 degrades the field, not the window: the over-long
        // input stays null (nothing guessed) and the good output is still reported.
        var bytes = Encoding.UTF8.GetBytes(
            """{"usage":{"input_tokens":99999999999999999999,"output_tokens":340},"stop_reason":"end_turn"}""");
        var (input, output) = Feed(new AnthropicJsonUsageReader(), bytes);
        Assert.Null(input);
        Assert.Equal(340, output);
    }
}
