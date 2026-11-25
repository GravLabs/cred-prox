using System.Text;
using CredProx;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M54 ADR-0009: OpenAI non-streaming usage-reader units. The fixtures are the shapes
/// measured against a Foundry Local 2.5.0 CPU server (docs/foundry-local-notes.md): the
/// <c>usage</c> object with its <c>*_tokens_details</c> nesting, the OpenAI error
/// envelope on 404 and 400. The walk discipline (split tokens, malformed tails, root-depth
/// gating) mirrors the Anthropic JSON reader — the two transports must agree.
/// </summary>
public sealed class CredProxMeteringOpenAiJsonReaderTests
{
    private const string Complete = """{"id":"chatcmpl-abc","object":"chat.completion","created":1,"model":"qwen3-4b-generic-cpu:3","choices":[{"index":0,"message":{"role":"assistant","content":"OK","reasoning_content":"thinking hard"},"finish_reason":"stop"}],"usage":{"completion_tokens":32,"completion_tokens_details":{"reasoning_tokens":31},"prompt_tokens":13,"prompt_tokens_details":{"cached_tokens":0},"total_tokens":45}}""";

    private static readonly byte[] CompleteBytes = Encoding.UTF8.GetBytes(Complete);

    private static (long? In, long? Out) Feed(OpenAiJsonUsageReader reader, byte[] bytes, params int[] splits)
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
    public void CompleteDocument_ReportsPromptAndCompletionTokens()
    {
        var (input, output) = Feed(new OpenAiJsonUsageReader(), CompleteBytes);
        Assert.Equal(13, input);
        Assert.Equal(32, output);
    }

    [Fact]
    public void ReasoningTokens_AreNotAddedAgain()
    {
        // The measured trap: completion_tokens ALREADY contains reasoning_tokens on this
        // format (13+32 total, details says reasoning 31). A reader that added the detail
        // would report 63 output; the correct answer is the provider's 32.
        var (input, output) = Feed(new OpenAiJsonUsageReader(), CompleteBytes);
        Assert.Equal(13, input);
        Assert.Equal(32, output);
        Assert.NotEqual(32 + 31, output);
    }

    [Fact]
    public void NonPositiveTokenCounts_AreNotReported()
    {
        var bytes = Encoding.UTF8.GetBytes(
            """{"id":"chatcmpl-abc","usage":{"prompt_tokens":0,"completion_tokens":-5}}""");
        var (input, output) = Feed(new OpenAiJsonUsageReader(), bytes);
        Assert.Null(input);
        Assert.Null(output);
    }

    [Fact]
    public void DetailObjectsOnly_AreNotCounts()
    {
        // *_tokens_details are objects, not counts: the container rule must keep them from
        // reporting, and their inner numbers sit below the walked field depth.
        var bytes = Encoding.UTF8.GetBytes(
            """{"id":"chatcmpl-abc","usage":{"completion_tokens_details":{"reasoning_tokens":9},"prompt_tokens_details":{"cached_tokens":4}}}""");
        var (input, output) = Feed(new OpenAiJsonUsageReader(), bytes);
        Assert.Null(input);
        Assert.Null(output);
    }

    [Fact]
    public void UsageOutsideRootDepth_IsIgnored()
    {
        // The decoy the Anthropic JSON reader pins, OpenAI spelling: a deep "usage"
        // carrying huge numbers must not count; only the root-depth usage does.
        var bytes = Encoding.UTF8.GetBytes(
            """{"id":"chatcmpl-abc","meta":{"block":{"usage":{"prompt_tokens":99999,"completion_tokens":99999}}},"usage":{"prompt_tokens":13,"completion_tokens":32}}""");
        var (input, output) = Feed(new OpenAiJsonUsageReader(), bytes);
        Assert.Equal(13, input);
        Assert.Equal(32, output);
    }

    [Fact]
    public void SameNameDecoyInsideUsage_CountsOnlyTheTopLevelFields()
    {
        // The Anthropic NumbersNestedInsideUsageStructures shape, OpenAI spelling: a
        // nested "usage" inside usage carrying a huge count must not overwrite
        // the top-level fields. This is the cell that kills the depth-2 field gate: widen
        // the `CurrentDepth == 2` gates on the PropertyName and Number cases and the
        // depth-3 decoy field is detected and counted (99999) — this cell goes RED.
        var bytes = Encoding.UTF8.GetBytes(
            """{"usage":{"prompt_tokens":13,"completion_tokens":32,"usage":{"prompt_tokens":99999}}}""");
        var (input, output) = Feed(new OpenAiJsonUsageReader(), bytes);
        Assert.Equal(13, input);
        Assert.Equal(32, output);
    }

    [Fact]
    public void NestedNamesakeUsage_Alone_ReportsNothing()
    {
        // The same decoy without any top-level counts: nothing arrives, because a name at
        // depth 2 is the only thing that pairs a field, and depth-2 names never see the
        // nested numbers. Together with the cell above this pins the whole nesting
        // defence — top-level fields stand, nested values never count.
        var bytes = Encoding.UTF8.GetBytes(
            """{"usage":{"prompt_tokens_details":{"cached_tokens":4},"usage":{"prompt_tokens":99999,"completion_tokens":99999}}}""");
        var (input, output) = Feed(new OpenAiJsonUsageReader(), bytes);
        Assert.Null(input);
        Assert.Null(output);
    }

    [Fact]
    public void ModelNotFound404Body_IsUnmetered()
    {
        // Measured 404 envelope (the type stays invalid_request_error on this server).
        var bytes = Encoding.UTF8.GetBytes(
            """{"error":{"code":null,"param":null,"message":"Model not found: No model matching 'no-such-model:1'","type":"invalid_request_error"}}""");
        var (input, output) = Feed(new OpenAiJsonUsageReader(), bytes);
        Assert.Null(input);
        Assert.Null(output);
    }

    [Fact]
    public void MalformedRequest400Body_IsUnmetered()
    {
        var bytes = Encoding.UTF8.GetBytes(
            """{"error":{"code":null,"param":null,"message":"[json.exception.type_error.302] type must be number, but is string","type":"invalid_request_error"}}""");
        var (input, output) = Feed(new OpenAiJsonUsageReader(), bytes);
        Assert.Null(input);
        Assert.Null(output);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(17)]
    [InlineData(64)]
    [InlineData(200)]
    public void SplitAtEveryCut_RescansToTheSameValues(int split)
    {
        var (input, output) = Feed(new OpenAiJsonUsageReader(), CompleteBytes, split);
        Assert.Equal(13, input);
        Assert.Equal(32, output);
    }

    [Fact]
    public void OutOfRangeNumber_DoesNotCloseWindow_GoodFieldStillCounts()
    {
        // Decline, not failure: TryGetInt64 declines instead of throwing, so the walk
        // survives the oversized token and the next field still reports.
        var bytes = Encoding.UTF8.GetBytes(
            """{"usage":{"prompt_tokens":99999999999999999999,"completion_tokens":5}}""");
        var (input, output) = Feed(new OpenAiJsonUsageReader(), bytes);
        Assert.Null(input);
        Assert.Equal(5, output);
    }

    [Fact]
    public void MalformedTailAfterClosedUsage_SettledValuesStand()
    {
        // usage closes before the garbage: the attempt is over, the garbage never parses.
        var bytes = Encoding.UTF8.GetBytes(
            """{"usage":{"prompt_tokens":13,"completion_tokens":32},"choices":[oops""");
        var (input, output) = Feed(new OpenAiJsonUsageReader(), bytes);
        Assert.Equal(13, input);
        Assert.Equal(32, output);
    }

    [Fact]
    public void Format_IsOpenAi() =>
        Assert.Equal("openai", new OpenAiJsonUsageReader().Format);

    [Theory]
    [InlineData("application/json", true)]
    [InlineData("APPLICATION/JSON", true)]
    [InlineData("application/vnd.acme+json", true)]
    [InlineData("text/event-stream", false)]
    [InlineData("text/plain", false)]
    [InlineData(null, false)]
    public void CanRead_ClaimsJsonShapes(string? mediaType, bool expected) =>
        Assert.Equal(expected, new OpenAiJsonUsageReader().CanRead(mediaType));
}
