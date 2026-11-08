using CredProx;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The configuration-model guards (§5.2 "Caller API keys"): a caller key is exactly a
/// SHA-256 hash, a caller never exists without at least one key, and an operation entry
/// with no methods and no patterns admits everything (the emptiness checks are what make
/// the dimensions opt-in — they must not silently flip).
/// </summary>
public sealed class CallerDefinitionGuardTests
{
    [Fact]
    public void CallerKey_ShortHash_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(
            () => new CallerKey("k1", new byte[31], expiresAt: null));

        Assert.Equal("hash", ex.ParamName);
        Assert.Contains("32 bytes", ex.Message);
    }

    [Fact]
    public void CallerKey_LongHash_Throws()
    {
        Assert.Throws<ArgumentException>(
            () => new CallerKey("k1", new byte[33], expiresAt: null));
    }

    [Fact]
    public void CallerDefinition_NoKeys_Throws_NamingTheCaller()
    {
        var ex = Assert.Throws<ArgumentException>(
            () => new CallerDefinition("app-a", [], [], limits: null));

        Assert.Equal("keys", ex.ParamName);
        Assert.Contains("app-a", ex.Message);
    }

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
