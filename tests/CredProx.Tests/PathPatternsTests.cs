using CredProx;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// Path-pattern semantics for caller operation allow-lists (§5.2 "Operation allow-lists"):
/// ordinal case-sensitive matching, <c>*</c> = one non-empty segment, trailing <c>**</c> =
/// zero or more, and the traversal/encoding refusals of <see cref="PathPatterns.IsSafePath"/>.
/// </summary>
public sealed class PathPatternsTests
{
    [Theory]
    [InlineData("/reports", "/reports", true)]
    [InlineData("/reports/", "/reports", true)]           // trailing slash not distinct
    [InlineData("/reports", "/reports/", true)]           // ... on either side
    [InlineData("/reports/q1", "/reports/*", true)]
    [InlineData("/reports", "/reports/*", false)]         // * needs one segment
    [InlineData("/reports/q1/q2", "/reports/*", false)]   // * is exactly one
    [InlineData("/reports/q1/q2", "/reports/**", true)]
    [InlineData("/reports", "/reports/**", true)]         // ** admits zero
    [InlineData("/reports/", "/reports/**", true)]
    [InlineData("/admin", "/reports/**", false)]
    [InlineData("/Reports", "/reports", false)]           // case-sensitive
    [InlineData("/reports", "/REPORTS", false)]
    [InlineData("/a/b", "/a/*/c", false)]                 // literal tail mismatch
    [InlineData("/a/b/c", "/a/*/c", true)]
    public void Matches(string path, string pattern, bool expected) =>
        Assert.Equal(expected, PathPatterns.Matches(path, pattern));

    [Theory]
    [InlineData("/reports", true)]
    [InlineData("/reports/**", true)]
    [InlineData("/**", true)]
    [InlineData("/a/*/b", true)]
    [InlineData("reports", false)]        // no leading slash
    [InlineData("", false)]
    [InlineData("/a/**/b", false)]        // ** must be trailing
    [InlineData("/a/x*", false)]          // partial wildcard
    [InlineData("/a/*x", false)]
    [InlineData("/a/?", false)]           // no ? wildcard
    public void IsValidPattern(string pattern, bool expected) =>
        Assert.Equal(expected, PathPatterns.IsValidPattern(pattern));

    [Theory]
    [InlineData("/api/thing", "/api/thing", true)]
    [InlineData("/api/thing", "/a/../admin", false)]      // dot segments
    [InlineData("/a/./b", "/a/./b", false)]
    [InlineData("/..", "/..", false)]
    [InlineData("/a%2fb", "/a/b", false)]                 // encoded separator in raw
    [InlineData("/a%2Fb", "/a/b", false)]
    [InlineData("/a%5cb", "/a/b", false)]                 // encoded backslash
    [InlineData("/a%2eb", "/a.b", false)]                 // encoded dot
    [InlineData("/%2e%2e/admin", "/../admin", false)]     // encoded traversal
    [InlineData("/a%252fb", "/a%2fb", false)]             // double encoding
    [InlineData("/a\\b", "/a\\b", false)]                 // literal backslash in decoded
    [InlineData("/a\u0001b", "/a\u0001b", false)]         // control character
    [InlineData("/a\u007fb", "/a\u007fb", false)]         // DEL
    [InlineData("api/thing", "api/thing", false)]         // not rooted
    [InlineData("", "", false)]
    [InlineData("/a%20b", "/a b", true)]                  // ordinary escapes are fine
    // F2 regressions: a '%' adjacent to a real escape must not hide it from the scan.
    [InlineData("/a/%/%2fb", "/a/%/%2fb", false)]         // %/%2f (shrunk counterexample)
    [InlineData("/a/%%2fb", "/a/%%2fb", false)]           // %%2f
    [InlineData("/a/%%2eb", "/a/%%2eb", false)]           // %%2e
    [InlineData("/a/%%25b", "/a/%%25b", false)]           // %%25
    [InlineData("/allowed/%%25admin", "/allowed/%%25admin", false)] // %%25, long form
    // Empty-segment decision: Matches collapses them, so they are refused, not matched.
    [InlineData("/a//b", "/a//b", false)]                 // interior empty segment
    [InlineData("//a", "//a", false)]                     // leading empty segment
    [InlineData("/a/b/", "/a/b/", true)]                  // single trailing slash stays fine
    public void IsSafePath(string raw, string decoded, bool expected) =>
        Assert.Equal(expected, PathPatterns.IsSafePath(raw, decoded));

    [Fact]
    public void IsSafePath_NullRaw_UsesDecodedOnly()
    {
        // The raw target is only consulted for escape tricks; without it the decoded
        // checks still refuse traversal.
        Assert.True(PathPatterns.IsSafePath(null, "/api/thing"));
        Assert.False(PathPatterns.IsSafePath(null, "/a/../admin"));
    }
}
