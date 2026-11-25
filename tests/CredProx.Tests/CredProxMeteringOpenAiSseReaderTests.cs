using System.Text;
using CredProx;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M54 ADR-0009: OpenAI streaming usage-reader units. The events are the shapes measured
/// against a Foundry Local 2.5.0 CPU server (docs/foundry-local-notes.md): content deltas,
/// a finish_reason event, and — only when the caller asked for
/// <c>stream_options.include_usage</c> — exactly one usage-only event (empty
/// <c>choices</c> plus <c>usage</c>) before <c>data: [DONE]</c>. Without that event the
/// stream is unmetered. The framing suite (boundary spellings, byte-by-byte delivery,
/// oversized-event skip with clean resume, trailing-event-without-terminator) mirrors the
/// Anthropic SSE reader.
/// </summary>
public sealed class CredProxMeteringOpenAiSseReaderTests
{
    private const string ContentEvent = """data: {"id":"chatcmpl-abc","object":"chat.completion.chunk","created":1,"model":"qwen3-4b-generic-cpu:3","choices":[{"index":0,"delta":{"content":"OK"},"finish_reason":null}]}""";
    private const string FinishEvent = """data: {"id":"chatcmpl-abc","object":"chat.completion.chunk","created":1,"model":"qwen3-4b-generic-cpu:3","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}""";
    private const string UsageEvent = """data: {"id":"chatcmpl-abc","object":"chat.completion.chunk","created":1,"model":"qwen3-4b-generic-cpu:3","choices":[],"usage":{"completion_tokens":32,"completion_tokens_details":{"reasoning_tokens":31},"prompt_tokens":13,"prompt_tokens_details":{"cached_tokens":0},"total_tokens":45}}""";
    private const string Done = "data: [DONE]";

    private static (long? In, long? Out) Feed(OpenAiSseUsageReader reader, string text, bool endOfStream = true)
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
    public void EveryBoundarySpelling_CountsTheUsageOnlyEvent(string boundary)
    {
        var (input, output) = Feed(
            new OpenAiSseUsageReader(),
            ContentEvent + boundary + FinishEvent + boundary + UsageEvent + boundary + Done + boundary);
        Assert.Equal(13, input);
        Assert.Equal(32, output); // details.reasoning_tokens NOT added again: 32 stands
    }

    [Fact]
    public void ByteByByteDelivery_SameValues()
    {
        var bytes = Encoding.UTF8.GetBytes(UsageEvent + "\n\n" + Done + "\n\n");
        var reader = new OpenAiSseUsageReader();
        foreach (var b in bytes)
        {
            reader.Observe(new[] { b }, endOfStream: false);
        }

        reader.Observe([], endOfStream: true);
        Assert.Equal(13, reader.InputTokens);
        Assert.Equal(32, reader.OutputTokens);
    }

    [Fact]
    public void StreamWithoutUsageEvent_IsUnmetered()
    {
        // The measured default: no stream_options.include_usage, no usage anywhere.
        var (input, output) = Feed(
            new OpenAiSseUsageReader(),
            ContentEvent + "\n\n" + FinishEvent + "\n\n" + Done + "\n\n");
        Assert.Null(input);
        Assert.Null(output);
    }

    [Fact]
    public void ContentEventCarryingUsage_IsIgnored_UsageOnlyEventCounts()
    {
        // A usage field on an event that still carries a choice is not the provider's
        // usage-only report (a relaying gateway must not misread it).
        var (input, output) = Feed(
            new OpenAiSseUsageReader(),
            """data: {"choices":[{"index":0,"delta":{"content":"x"}}],"usage":{"prompt_tokens":99,"completion_tokens":99}}"""
            + "\n\n" + UsageEvent + "\n\n");
        Assert.Equal(13, input);
        Assert.Equal(32, output);
    }

    [Fact]
    public void UsageOnEventThatStillCarriesChoices_IsNotTrusted()
    {
        // Isolated witness for the choices-empty half of the gate: the ONLY event carries
        // a choice and a usage object together — that is not the provider's usage-only
        // report, and nothing counts. (ContentEventCarryingUsage cannot witness this half
        // alone: the later real usage event would overwrite the wrong values anyway.)
        var (input, output) = Feed(
            new OpenAiSseUsageReader(),
            """data: {"choices":[{"index":0,"delta":{"content":"x"}}],"usage":{"prompt_tokens":99,"completion_tokens":99}}"""
            + "\n\n");
        Assert.Null(input);
        Assert.Null(output);
    }

    [Fact]
    public void DoneLine_IsNotJson_AndDoesNotBlockTheEarlierUsage()
    {
        var (input, output) = Feed(new OpenAiSseUsageReader(), UsageEvent + "\n\n" + Done + "\n\n");
        Assert.Equal(13, input);
        Assert.Equal(32, output);
    }

    [Fact]
    public void LastUsageOnlyEventStands()
    {
        var (input, output) = Feed(
            new OpenAiSseUsageReader(),
            """data: {"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":20}}"""
            + "\n\n" + UsageEvent + "\n\n");
        Assert.Equal(13, input);
        Assert.Equal(32, output);
    }

    [Fact]
    public void NonPositiveTokenCounts_AreNotReported()
    {
        // The trust rule the counter descriptions advertise, OpenAI-SSE spelling: a
        // usage-only event carrying non-positive counts is not a report — each field
        // stays null (never reported), because a hostile or buggy vendor body must never
        // drive a monotonic counter down. Deleting either `> 0` guard in ApplyUsage turns
        // this cell RED: the rule was pinned on the Anthropic-SSE and OpenAI-JSON
        // paths only, never here.
        var (input, output) = Feed(
            new OpenAiSseUsageReader(),
            """data: {"choices":[],"usage":{"prompt_tokens":0,"completion_tokens":-5}}"""
            + "\n\n" + Done + "\n\n");
        Assert.Null(input);
        Assert.Null(output);
    }

    [Fact]
    public void OversizedEventIsSkipped_AndFollowingEventsAreStillMetered()
    {
        var giant = "data: {\"choices\":[],\"blob\":\"" + new string('x', OpenAiSseUsageReader.MaxEventBytes) + "\"}";
        var (input, output) = Feed(new OpenAiSseUsageReader(), giant + "\n\n" + UsageEvent + "\n\n");
        Assert.Equal(13, input);
        Assert.Equal(32, output);
    }

    [Fact]
    public void TerminatorOfSkippedEventSplitAcrossChunks_NextEventStillMetered()
    {
        var giant = "data: {\"choices\":[],\"blob\":\"" + new string('x', OpenAiSseUsageReader.MaxEventBytes) + "\"}\n";
        var reader = new OpenAiSseUsageReader();
        reader.Observe(Encoding.UTF8.GetBytes(giant), endOfStream: false); // skip mode starts at the cap
        reader.Observe(Encoding.UTF8.GetBytes("\n"), endOfStream: false); // terminator completes across the edge
        reader.Observe(Encoding.UTF8.GetBytes(UsageEvent + "\n\n"), endOfStream: true);
        Assert.Equal(13, reader.InputTokens);
        Assert.Equal(32, reader.OutputTokens);
    }

    [Fact]
    public void FinalEventWithoutTrailingBlankLine_IsStillReadAtEndOfStream()
    {
        var (input, output) = Feed(new OpenAiSseUsageReader(), UsageEvent);
        Assert.Equal(13, input);
        Assert.Equal(32, output);
    }

    [Fact]
    public void NonJsonAndUsagelessEvents_AreUnmetered_AndDoNotBlockLaterOnes()
    {
        var (input, output) = Feed(
            new OpenAiSseUsageReader(),
            "data: {oops\n\ndata: {\"x\":1}\n\n" + UsageEvent + "\n\n");
        Assert.Equal(13, input);
        Assert.Equal(32, output);
    }

    [Fact]
    public void CommentAndNonDataFields_AreIgnored()
    {
        var (input, output) = Feed(
            new OpenAiSseUsageReader(),
            ": keep-alive\n\nevent: message\nid: 7\nretry: 100\n\n" + UsageEvent + "\n\n");
        Assert.Equal(13, input);
        Assert.Equal(32, output);
    }

    [Fact]
    public void DataColonWithoutSpace_StillParsed()
    {
        var (input, output) = Feed(
            new OpenAiSseUsageReader(),
            """data:{"choices":[],"usage":{"prompt_tokens":13,"completion_tokens":32}}""" + "\n\n");
        Assert.Equal(13, input);
        Assert.Equal(32, output);
    }

    [Fact]
    public void WrapperHidesUsage_IsIgnored()
    {
        // usage and empty choices only count at the event root; a wrapper fails the gate.
        var (input, output) = Feed(
            new OpenAiSseUsageReader(),
            """data: {"wrapper":{"choices":[],"usage":{"prompt_tokens":5,"completion_tokens":5}}}\n\n""");
        Assert.Null(input);
        Assert.Null(output);
    }

    [Fact]
    public void ZeroLengthProbeWithMoreChunksPending_DoesNotFinalizeEarly()
    {
        var reader = new OpenAiSseUsageReader();
        reader.Observe(Encoding.UTF8.GetBytes(UsageEvent + "\n"), endOfStream: false);
        reader.Observe([], endOfStream: false); // a zero-length probe read
        reader.Observe(Encoding.UTF8.GetBytes("\ndata: {\"x\":1}\n\n"), endOfStream: false);
        reader.Observe([], endOfStream: true);
        Assert.Equal(13, reader.InputTokens);
    }

    [Theory]
    [InlineData("text/event-stream", true)]
    [InlineData("TEXT/EVENT-STREAM", true)]
    [InlineData("application/json", false)]
    [InlineData("text/plain", false)]
    [InlineData(null, false)]
    public void CanRead_ClaimsOnlyEventStream(string? mediaType, bool expected) =>
        Assert.Equal(expected, new OpenAiSseUsageReader().CanRead(mediaType));

    [Fact]
    public void ConstructionStaysCheapUntilBytesArrive()
    {
        // Same M50 bench finding as the Anthropic reader: selection constructs every
        // registered reader per response, so the 64 KB frame must materialise only once
        // a chunk really carries bytes.
        GC.GetAllocatedBytesForCurrentThread(); // settle the measuring machinery
        var before = GC.GetAllocatedBytesForCurrentThread();
        var reader = new OpenAiSseUsageReader();
        Assert.Equal("openai", reader.Format);
        Assert.False(reader.CanRead("application/json"));
        Assert.Null(reader.InputTokens);
        var probeCost = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.True(
            probeCost < 16 * 1024,
            $"constructing and probing an SSE reader allocated {probeCost} bytes");

        reader.Observe("data: x\n\n"u8.ToArray(), endOfStream: false);
    }
}
