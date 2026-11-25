using System.Text;
using CredProx;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// §5.2 (M50 row): SSE framing units — every boundary spelling, the oversized-event
/// skip-recovery (including a terminator split across chunks while skipping), and the
/// cumulative <c>output_tokens</c> last-seen-wins rule. The reader only ever sees copies
/// (byte identity of the forwarded stream is a pipeline-level cell); these cells pin
/// framing and usage extraction.
/// </summary>
public sealed class CredProxMeteringSseReaderTests
{
    private const string StartEvent = """data: {"type":"message_start","message":{"usage":{"input_tokens":100,"output_tokens":1}}}""";
    private const string DeltaEvent = """data: {"type":"message_delta","usage":{"output_tokens":25}}""";

    private static (long? In, long? Out) Feed(AnthropicSseUsageReader reader, string text, bool endOfStream = true)
    {
        reader.Observe(Encoding.UTF8.GetBytes(text), endOfStream);
        return (reader.InputTokens, reader.OutputTokens);
    }

    [Theory]
    [InlineData("\n\n")]
    [InlineData("\r\r")]
    [InlineData("\n\r\n")]
    [InlineData("\r\n\n")]
    [InlineData("\r\n\r\n")]
    public void EveryBoundarySpelling_FramesBothEvents(string boundary)
    {
        var (input, output) = Feed(new AnthropicSseUsageReader(), StartEvent + boundary + DeltaEvent + boundary);
        Assert.Equal(100, input);
        Assert.Equal(25, output);
    }

    [Fact]
    public void ByteByByteDelivery_SameValues()
    {
        var bytes = Encoding.UTF8.GetBytes(StartEvent + "\n\n" + DeltaEvent + "\n\n");
        var reader = new AnthropicSseUsageReader();
        foreach (var b in bytes)
        {
            reader.Observe(new[] { b }, endOfStream: false);
        }

        reader.Observe([], endOfStream: true);
        Assert.Equal(100, reader.InputTokens);
        Assert.Equal(25, reader.OutputTokens);
    }

    [Fact]
    public void OutputTokensAreCumulative_LastSeenStands()
    {
        var text = StartEvent + "\n\n"
            + "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":10}}\n\n"
            + "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":30}}\n\n"
            + "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":17}}\n\n";
        var (input, output) = Feed(new AnthropicSseUsageReader(), text);
        Assert.Equal(100, input);
        Assert.Equal(17, output);
    }

    [Fact]
    public void NonPositiveTokenCounts_AreNotReported()
    {
        // M50 fold LOW-1: a non-positive count is not a report — nothing is recorded, so a
        // hostile or buggy vendor body can never drive a monotonic counter down.
        var (input, output) = Feed(new AnthropicSseUsageReader(),
            """data: {"type":"message_start","message":{"usage":{"input_tokens":-5,"output_tokens":-7}}}""" + "\n\n"
            + """data: {"type":"message_delta","usage":{"input_tokens":0,"output_tokens":0}}""" + "\n\n");
        Assert.Null(input);
        Assert.Null(output);

        // Cumulative output: a zero that arrives after a positive does not overwrite it.
        var kept = Feed(new AnthropicSseUsageReader(), StartEvent + "\n\n"
            + "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":0}}\n\n");
        Assert.Equal(100, kept.In);
        Assert.Equal(1, kept.Out);
    }

    [Fact]
    public void UsageOutsideTheDocumentedShape_IsIgnored_DocumentedShapeStillCounts()
    {
        // M50 fold LOW-2: only root-on-message_delta and message.usage-on-message_start are
        // the provider's report. Decoys carry large counts so an applied decoy is provable:
        // depth-3 inside a tool result, a wrong branch on message_start, and a typeless event.
        var text = """data: {"type":"message_delta","content_block":{"tool_result":{"usage":{"input_tokens":99999,"output_tokens":99999}}},"usage":{"input_tokens":10,"output_tokens":20}}""" + "\n\n"
            + """data: {"type":"message_start","delta":{"usage":{"input_tokens":88888}}}""" + "\n\n"
            + """data: {"usage":{"input_tokens":77777}}""" + "\n\n";
        var (input, output) = Feed(new AnthropicSseUsageReader(), text);
        Assert.Equal(10, input);
        Assert.Equal(20, output);
    }

    [Fact]
    public void OversizedEventIsSkipped_AndFollowingEventsAreStillMetered()
    {
        var big = "data: " + new string('x', 70 * 1024);
        var text = big + "\n\n" + DeltaEvent + "\n\n";
        var (input, output) = Feed(new AnthropicSseUsageReader(), text);
        Assert.Null(input);
        Assert.Equal(25, output);
    }

    [Fact]
    public void TerminatorOfSkippedEventSplitAcrossChunks_NextEventStillMetered()
    {
        // First chunk trips the cap mid-event; the \r\n\r\n terminator then arrives split
        // across two further chunks while the reader is in skip mode.
        var reader = new AnthropicSseUsageReader();
        reader.Observe(Encoding.UTF8.GetBytes("data: " + new string('x', 64 * 1024)), endOfStream: false);
        reader.Observe(Encoding.UTF8.GetBytes(new string('y', 10) + "\r"), endOfStream: false);
        reader.Observe(Encoding.UTF8.GetBytes("\n\r\n" + DeltaEvent), endOfStream: false);
        reader.Observe(Encoding.UTF8.GetBytes("\n\n"), endOfStream: true);
        Assert.Equal(25, reader.OutputTokens);
    }

    [Fact]
    public void FinalEventWithoutTrailingBlankLine_IsStillReadAtEndOfStream()
    {
        var (input, output) = Feed(new AnthropicSseUsageReader(), StartEvent + "\n\n" + DeltaEvent);
        Assert.Equal(100, input);
        Assert.Equal(25, output);
    }

    [Fact]
    public void NonJsonAndUsagelessEvents_AreUnmetered_AndDoNotBlockLaterOnes()
    {
        var text = "data: not json at all\n\ndata: {\"type\":\"ping\"}\n\n" + DeltaEvent + "\n\n";
        var (input, output) = Feed(new AnthropicSseUsageReader(), text);
        Assert.Null(input);
        Assert.Equal(25, output);
    }

    [Fact]
    public void CommentAndNonDataFields_AreIgnored()
    {
        var text = ": keep-alive\nevent: message_start\nid: 1\nretry: 500\n" + StartEvent + "\n\n";
        var (input, _) = Feed(new AnthropicSseUsageReader(), text);
        Assert.Equal(100, input);
    }

    [Fact]
    public void DataColonWithoutSpace_StillParsed()
    {
        var text = "data:{\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":7}}}\n\n";
        var (input, output) = Feed(new AnthropicSseUsageReader(), text);
        Assert.Equal(7, input);
        Assert.Null(output);
    }

    [Fact]
    public void DeeplyNestedJsonBeyondParserDepth_IsUnmeteredNotGuessed()
    {
        var nested = string.Concat(Enumerable.Repeat("{\"a\":", 80)) + "{\"usage\":{\"input_tokens\":5}}" + new string('}', 80);
        var (input, output) = Feed(new AnthropicSseUsageReader(), "data: " + nested + "\n\n");
        Assert.Null(input);
        Assert.Null(output);
    }

    [Fact]
    public void ZeroLengthProbeWithMoreChunksPending_DoesNotFinalizeEarly()
    {
        var reader = new AnthropicSseUsageReader();
        reader.Observe(Encoding.UTF8.GetBytes(StartEvent + "\n"), endOfStream: false);
        reader.Observe([], endOfStream: false); // a zero-length probe read
        reader.Observe(Encoding.UTF8.GetBytes("\ndata: {\"x\":1}\n\n"), endOfStream: false);
        reader.Observe([], endOfStream: true);
        Assert.Equal(100, reader.InputTokens);
    }

    [Theory]
    [InlineData("text/event-stream", true)]
    [InlineData("TEXT/EVENT-STREAM", true)]
    [InlineData("application/json", false)]
    [InlineData("text/plain", false)]
    [InlineData(null, false)]
    public void CanRead_ClaimsOnlyEventStream(string? mediaType, bool expected) =>
        Assert.Equal(expected, new AnthropicSseUsageReader().CanRead(mediaType));

    [Fact]
    public void ConstructionStaysCheapUntilBytesArrive()
    {
        // The usage opt-in constructs every registered reader per response to probe
        // CanRead (M50 bench finding): the 64 KB frame must only materialise once a
        // chunk really carries bytes, or every usage-opted JSON response pays for it.
        GC.GetAllocatedBytesForCurrentThread(); // settle the measuring machinery
        var before = GC.GetAllocatedBytesForCurrentThread();
        var reader = new AnthropicSseUsageReader();
        Assert.False(reader.CanRead("application/json"));
        Assert.Null(reader.InputTokens);
        var probeCost = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.True(
            probeCost < 16 * 1024,
            $"constructing and probing an SSE reader allocated {probeCost} bytes");

        reader.Observe("data: x\n\n"u8.ToArray(), endOfStream: false);
        var frameCost = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.True(
            frameCost >= AnthropicSseUsageReader.MaxEventBytes,
            $"the frame did not materialise when bytes arrived (only {frameCost} bytes)");
    }
}
