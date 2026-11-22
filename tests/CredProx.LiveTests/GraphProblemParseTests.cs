using Xunit;

namespace CredProx.LiveTests;

// The curated parse the Graph live cell goes through (GraphEnv.ParseGraphProblem),
// pinned offline: the graph-shaped read of extensions.vendor_detail.error.code,
// the curated failure texts, the no-echo rule, and the live cell's call into the
// helper - so a live-cell rewrite back to a raw JsonDocument.Parse turns RED
// here, not in a live run (m46m INFO 09030a9). The path itself against the
// SHIPPED normaliser is pinned in ErrorNormalisationFeatureTests
// .GraphShapedErrorBody_VendorDetailCarriesError_Code.
// Class and cell names carry none of live-run.sh's leg filter tokens.
[Trait("Layer", "Offline")]
public sealed class GraphProblemParseTests
{
    [Fact]
    public void ParseGraphProblem_GraphShapedBody_ReadsBothCodes()
    {
        var body = """{"type":"https://credprox.dev/errors/vendor-error","status":403,"extensions":{"code":"credprox.vendor_error","vendor_detail":{"error":{"code":"Authorization_RequestDenied","message":"Access to a restricted resource."}}}}""";
        var (extensionsCode, vendor) = GraphEnv.ParseGraphProblem(body, 403, "users probe");
        Assert.Equal("credprox.vendor_error", extensionsCode);
        Assert.Equal("Authorization_RequestDenied", vendor);
    }

    [Fact]
    public void ParseGraphProblem_UnparseableBody_FailsCurated_NeverEchoesBody()
    {
        var ex = Assert.Throws<Xunit.Sdk.XunitException>(
            () => GraphEnv.ParseGraphProblem("not-json canary-body-do-not-echo", 403, "users probe"));
        Assert.Contains("unparseable", ex.Message, StringComparison.Ordinal);
        Assert.Contains("extensions.vendor_detail.error.code", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("canary-body-do-not-echo", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ParseGraphProblem_NoExtensionsCode_FailsCurated_NeverEchoesBody()
    {
        var ex = Assert.Throws<Xunit.Sdk.XunitException>(
            () => GraphEnv.ParseGraphProblem("""{"extensions":{"vendor_detail":{"error":{"code":"canary-x"}}}}""", 403, "users probe"));
        Assert.Contains("no extensions.code", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("canary-x", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void LiveGraphCell_ParsesThroughTheCuratedHelper()
    {
        // the use-pin: the offline cells above only guard the live path while the
        // live cell actually calls the helper:
        var source = File.ReadAllText(LocateLiveGraphSource());
        Assert.Contains("GraphEnv.ParseGraphProblem(", source, StringComparison.Ordinal);
        Assert.DoesNotContain("JsonDocument.Parse(usersBody)", source, StringComparison.Ordinal);
    }

    private static string LocateLiveGraphSource()
    {
        var own = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
        var parts = own.Split(Path.DirectorySeparatorChar);
        var binIndex = Array.IndexOf(parts, "bin");
        if (binIndex < 3)
        {
            throw new InvalidOperationException($"unexpected test assembly location '{own}'");
        }

        var repoRoot = string.Join(Path.DirectorySeparatorChar, parts[..(binIndex - 2)]);
        return Path.Combine(repoRoot, "tests", "CredProx.LiveTests", "MicrosoftGraphLiveTests.cs");
    }
}
