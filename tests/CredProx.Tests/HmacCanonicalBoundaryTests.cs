using Xunit;

namespace CredProx.Tests;

/// <summary>
/// Boundary binding of the HMAC canonical string (qitem-20261120025812-1841885579827f16):
/// the signer REFUSES — never escapes or joins — a component value that carries the
/// configured separator, or one carrying the ',' that joins a multi-value header's
/// values. Refusal messages name the component and never carry a value. Vendor
/// compatibility is pinned the other way too: a clean request canonicalizes byte-for-byte
/// as the documented vendor-side join, computed here independently of the signer.
/// </summary>
public sealed class HmacCanonicalBoundaryTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 15, 10, 0, 0, TimeSpan.Zero);

    private static readonly (HmacComponentKind Kind, string Argument)[] TwoHeaders =
        [(HmacComponentKind.Header, "X-A"), (HmacComponentKind.Header, "X-B")];

    private static HttpRequestMessage Post() => new(HttpMethod.Post, "http://vendor.example/api");

    [Fact]
    public void DefaultSeparator_NewlineBearingUnvalidatedValue_Refuses()
    {
        // TryAddWithoutValidation only: the BCL validator refuses this value, which is
        // why the newline default is safe on validated attach paths (qitem-bf1a82fd's
        // measurement). The canonical layer must still refuse it on its own.
        var request = Post();
        request.Headers.TryAddWithoutValidation("X-A", "token\nX-B: forged");
        var ex = Assert.Throws<HmacCanonicalAmbiguousException>(() =>
            HmacSigner.BuildCanonicalString(TwoHeaders, request, [], new HmacOptions { Separator = "\n" }, T0));
        Assert.Contains("X-A", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("forged", ex.Message, StringComparison.Ordinal); // names the component, never the value
    }

    [Fact]
    public void PipeSeparator_PipeBearingValue_Refuses()
    {
        // '|' needs NO validation bypass: Headers.Add accepts it, so with Separator="|"
        // the collision is constructible from a caller's own validated headers.
        var request = Post();
        request.Headers.Add("X-A", "a|b");
        var ex = Assert.Throws<HmacCanonicalAmbiguousException>(() =>
            HmacSigner.BuildCanonicalString(TwoHeaders, request, [], new HmacOptions { Separator = "|" }, T0));
        Assert.Contains("X-A", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("a|b", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void QueryComponent_CarryingSeparator_Refuses()
    {
        var components = new[] { (HmacComponentKind.Query, string.Empty) };
        Assert.Throws<HmacCanonicalAmbiguousException>(() =>
            HmacSigner.BuildCanonicalString(components, Post(), [], new HmacOptions { Separator = "&" }, T0, "/api", "a=1&b=2"));
    }

    [Fact]
    public void PathComponent_CarryingSeparator_Refuses()
    {
        var components = new[] { (HmacComponentKind.Path, string.Empty) };
        Assert.Throws<HmacCanonicalAmbiguousException>(() =>
            HmacSigner.BuildCanonicalString(components, Post(), [], new HmacOptions { Separator = "/" }, T0, "/api/widgets"));
    }

    [Fact]
    public void MultiValueHeader_CommaInsideOneValue_Refuses()
    {
        // Both values are validator-legal; joined by ',' they read back ambiguously.
        var request = Post();
        request.Headers.Add("X-A", "one");
        request.Headers.Add("X-A", "b,c");
        var ex = Assert.Throws<HmacCanonicalAmbiguousException>(() =>
            HmacSigner.BuildCanonicalString(TwoHeaders, request, [], new HmacOptions { Separator = "\n" }, T0));
        Assert.Contains("X-A", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("b,c", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void SingleValueHeader_CommaStaysVerbatim()
    {
        // Nothing joined this ','; the component still reads back exactly once.
        var request = Post();
        request.Headers.Add("X-A", "a,b");
        request.Headers.Add("X-B", "z");
        var canonical = HmacSigner.BuildCanonicalString(TwoHeaders, request, [], new HmacOptions { Separator = "\n" }, T0);
        Assert.Equal("a,b\nz", canonical);
    }

    [Fact]
    public void CommaSeparator_ValueJoinedByTheSeparator_Refuses()
    {
        // The ',' that joins a multi-value header IS the configured separator here: the
        // resolved component value carries it — measured at 04a6570 as canonical-equal
        // AND signature-equal through plain validated Headers.Add, two clean values.
        var request = Post();
        request.Headers.Add("X-A", "one");
        request.Headers.Add("X-A", "two");
        Assert.Throws<HmacCanonicalAmbiguousException>(() =>
            HmacSigner.BuildCanonicalString(TwoHeaders, request, [], new HmacOptions { Separator = "," }, T0));
    }

    [Fact]
    public void CleanRequest_CanonicalIsThePlainVendorJoin()
    {
        // Vendor compatibility pin: a request with no separator-bearing value signs over
        // exactly the documented join — unchanged behaviour for every conforming site.
        var request = Post();
        request.Headers.Add("X-A", "alpha");
        request.Headers.Add("X-B", "beta");
        var canonical = HmacSigner.BuildCanonicalString(TwoHeaders, request, [], new HmacOptions { Separator = "\n" }, T0);
        Assert.Equal(string.Join("\n", ["alpha", "beta"]), canonical);
    }
}
