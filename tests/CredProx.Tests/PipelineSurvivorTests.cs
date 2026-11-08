using System.Net.Http.Headers;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage of the pipeline helpers: the text-type registry behind every body
/// rewrite decision, the content-encoding classification's guard, and the request cloner's
/// typed-options re-keying. The missing-separator and null-encoding-entry branches are
/// unreachable under BCL header validation (MediaTypeHeaderValue requires a non-empty type
/// and subtype, the encoding collection rejects nulls) — those rows are equivalence.
/// </summary>
public sealed class PipelineSurvivorTests
{
    [Theory]
    [InlineData("application/x-javascript")]
    [InlineData("application/ecmascript")]
    [InlineData("application/x-yaml")]
    [InlineData("application/ndjson")]
    [InlineData("application/xhtml+xml")]
    public void TextLike_RegistrySubtypes_AreRewritableText(string mediaType)
    {
        Assert.True(ResponseBodies.IsTextLike(MediaTypeHeaderValue.Parse(mediaType)));
    }

    [Theory]
    [InlineData("/json")]
    [InlineData("/")]
    public void TextLike_EmptyTypePart_IsUnreachableBecauseTheParserRefusesIt(string mediaType)
    {
        // IsTextLike's missing-separator boundary only differs from its neighbour for a
        // media type with an empty type part; such a value never reaches any gate that
        // sees a MediaTypeHeaderValue because the BCL parser refuses to build one.
        Assert.Throws<FormatException>(() => MediaTypeHeaderValue.Parse(mediaType));
    }

    [Fact]
    public void ResolveDecoding_NullContent_ThrowsArgumentNull_NotNullReference()
    {
        Assert.Throws<ArgumentNullException>(
            () => ResponseBodies.ResolveDecoding(null!, out _, out _));
    }

    [Fact]
    public void Clone_PreservesTypedRequestOptions()
    {
        // Options re-key by the value's runtime type so a typed TryGetValue on the clone
        // still finds what the credential feature stashed.
        var request = new HttpRequestMessage(HttpMethod.Get, "https://vendor.invalid/x");
        request.Options.Set(new HttpRequestOptionsKey<string>("triage-option"), "stashed-value");

        var clone = ProxyRequestCloner.Clone(request, body: null);

        Assert.True(clone.Options.TryGetValue(new HttpRequestOptionsKey<string>("triage-option"), out var value));
        Assert.Equal("stashed-value", value);
    }
}
