using CredProx;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The configuration-model guards (§5.2): an operation entry with no methods and no
/// patterns admits everything (the emptiness checks are what make the dimensions opt-in —
/// they must not silently flip). Caller-key entry shape (exactly-SHA-256 hash, key ids)
/// belongs to the keys package now and is pinned by its own rules' cells.
/// </summary>
public sealed class CallerDefinitionGuardTests
{
    [Fact]
    public void Rule_NoMethodsNoPaths_MatchesAnything()
    {
        // An entry constrained only by route (or by nothing at all) is an explicit
        // "everything else is fine": the empty sets must not refuse.
        var rule = new CallerOperationRule(route: null, methods: [], pathPatterns: []);

        Assert.True(rule.Matches("any-route", "POST", "/anything"));
    }

    [Fact]
    public void Rule_SecondPatternMatches()
    {
        // At least one pattern matching is enough.
        var rule = new CallerOperationRule(null, [], ["/a", "/b"]);

        Assert.True(rule.Matches("r", "GET", "/b"));
        Assert.False(rule.Matches("r", "GET", "/c"));
    }

    [Fact]
    public void Rule_EmptyRouteString_TreatedAsAnyRoute()
    {
        var rule = new CallerOperationRule("", ["GET"], []);

        Assert.True(rule.Matches("whatever-route", "GET", "/x"));
    }
}
