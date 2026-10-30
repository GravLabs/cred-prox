using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// Path-pattern matching for caller operation allow-lists (§4 Phase B, §5.2 "Operation
/// allow-lists"). Two rules make the traversal variants of §5.2 fail closed:
/// <list type="bullet">
/// <item><see cref="IsSafePath"/> rejects any path carrying traversal or encoding tricks
/// — dot segments, empty segments, backslashes, control characters, or percent-escapes of
/// <c>/</c>, <c>\</c>, <c>.</c> and <c>%</c> in the raw target — before any pattern is
/// consulted, so <c>/a/../admin</c>, <c>/a%2Fadmin</c>, <c>%2e%2e</c>, <c>/a//admin</c> and
/// double encodings never reach a match at all;</item>
/// <item>matching is ordinal and case-sensitive on the decoded path, so case tricks and
/// unicode homoglyphs simply do not match an ASCII pattern.</item>
/// </list>
/// Pattern syntax: a leading <c>/</c>, <c>*</c> matches exactly one non-empty segment, a
/// trailing <c>**</c> matches the remaining segments (zero or more).
/// </summary>
[Experimental("CREDPROX001")]
internal static class PathPatterns
{
    /// <summary>
    /// Whether the raw and decoded request paths are free of traversal and encoding
    /// tricks. A path that fails this is refused regardless of what it would match.
    /// </summary>
    /// <param name="rawPath">The raw (still percent-encoded) request path.</param>
    /// <param name="decodedPath">The decoded request path.</param>
    public static bool IsSafePath(string? rawPath, string? decodedPath)
    {
        if (string.IsNullOrEmpty(decodedPath) || decodedPath[0] != '/')
        {
            return false;
        }

        // The raw target must not smuggle separators or dots through percent-escapes, and
        // must not double-encode (%25 would re-decode into another escape layer). Every
        // '%' is examined: skipping past a harmless escape's two hex digits would let a
        // '%' adjacent to a real escape hide it (%/%2f, %%2f, %%25 all evade that way).
        if (rawPath is not null)
        {
            for (var i = 0; i < rawPath.Length - 2; i++)
            {
                if (rawPath[i] != '%')
                {
                    continue;
                }

                var escape = rawPath.Substring(i + 1, 2);
                if (escape.Equals("2f", StringComparison.OrdinalIgnoreCase)
                    || escape.Equals("5c", StringComparison.OrdinalIgnoreCase)
                    || escape.Equals("2e", StringComparison.OrdinalIgnoreCase)
                    || escape.Equals("25", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
            }
        }

        foreach (var c in decodedPath)
        {
            if (c < 0x20 || c == '\\' || c == 0x7f)
            {
                return false;
            }
        }

        // Empty segments are refused outright (explicit decision, M6 review): Matches
        // collapses them, so /allowed//admin would match /allowed/* while being
        // forwarded with the double slash intact — a decoded-vs-forwarded disagreement
        // surface an upstream that normalizes '//' resolves differently. A legitimate
        // path never needs one; a single trailing slash stays allowed (not a distinct
        // operation).
        if (decodedPath.Contains("//", StringComparison.Ordinal))
        {
            return false;
        }

        // Dot segments in the decoded path: /a/../admin, /a/./admin, /..%2f — whatever
        // survived decoding — are refused outright; a legitimate path never needs them.
        foreach (var segment in decodedPath.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            if (segment == "." || segment == "..")
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Whether <paramref name="decodedPath"/> matches <paramref name="pattern"/> (ordinal,
    /// case-sensitive). Assumes both passed <see cref="IsSafePath"/>-style checks.
    /// </summary>
    /// <param name="decodedPath">The decoded, PathBase-stripped request path.</param>
    /// <param name="pattern">The configured pattern.</param>
    public static bool Matches(string decodedPath, string pattern)
    {
        if (string.IsNullOrEmpty(pattern) || pattern[0] != '/'
            || string.IsNullOrEmpty(decodedPath) || decodedPath[0] != '/')
        {
            return false;
        }

        var pathSegments = Split(decodedPath);
        var patternSegments = Split(pattern);

        var p = 0;
        for (; p < patternSegments.Length; p++)
        {
            var segment = patternSegments[p];

            if (segment == "**")
            {
                // A trailing ** admits the remaining segments, zero or more; a ** anywhere
                // else is a pattern the binder rejects at startup.
                return p == patternSegments.Length - 1;
            }

            if (p >= pathSegments.Length)
            {
                return false;
            }

            if (segment == "*")
            {
                if (pathSegments[p].Length == 0)
                {
                    return false;
                }

                continue;
            }

            if (!string.Equals(segment, pathSegments[p], StringComparison.Ordinal))
            {
                return false;
            }
        }

        return p == pathSegments.Length;
    }

    /// <summary>
    /// Validates a configured pattern's shape (startup): leading <c>/</c>, segments are
    /// literals, <c>*</c>, or a trailing <c>**</c>.
    /// </summary>
    /// <param name="pattern">The configured pattern.</param>
    public static bool IsValidPattern(string pattern)
    {
        if (string.IsNullOrEmpty(pattern) || pattern[0] != '/')
        {
            return false;
        }

        var segments = Split(pattern);
        for (var i = 0; i < segments.Length; i++)
        {
            var segment = segments[i];
            if (segment == "**" && i != segments.Length - 1)
            {
                return false;
            }

            if (segment.Contains('*', StringComparison.Ordinal) && segment != "*" && segment != "**")
            {
                return false;
            }

            if (segment.Contains('?', StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }

    private static string[] Split(string path) =>
        // RemoveEmptyEntries makes a trailing slash not a distinct operation:
        // /reports/ is /reports.
        path.Split('/', StringSplitOptions.RemoveEmptyEntries);
}
