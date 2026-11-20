using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// Response scrubbing options bound from <c>CredProx:Scrubbing</c>: the safety net that removes an injected
/// credential from an upstream response that reflects it back (error pages, echo
/// endpoints).
/// </summary>
[Experimental("CREDPROX001")]
public sealed class CredProxScrubbingOptions
{
    /// <summary>
    /// Whether credentials injected on a request are scrubbed out of text-like upstream
    /// responses and response headers. Default <see langword="true"/>: the library's
    /// promise is that the caller never sees the credential. The scan runs only when a
    /// value was actually injected and the response content type is text-like, so
    /// everything else passes through byte-identical. Disable only when even that cost
    /// is unacceptable — reflected secrets then reach the caller.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Fail closed instead of forwarding responses the scrubber cannot inspect: a
    /// non-text or missing media type, an unknown or chained content encoding, or a
    /// body in a charset the byte matcher cannot read (<c>utf-16</c>/<c>utf-32</c>
    /// family, stateful names like <c>iso-2022-jp</c>, any unknown declared name —
    /// charsets are matched by name, case-insensitively, with one pair of surrounding
    /// double quotes stripped, and the readable ASCII-compatible charsets — <c>utf-8</c>/<c>utf8</c>,
    /// <c>us-ascii</c>/<c>ascii</c>, <c>iso-8859-1</c> through <c>iso-8859-11</c> and
    /// <c>iso-8859-13</c> through <c>iso-8859-16</c> (there is no iso-8859-12: reserved and
    /// withdrawn), and <c>windows-1250</c> through <c>windows-1258</c>, the complete published
    /// set, matched by exact name — are scrubbed like any other body) is replaced with a
    /// <c>credprox.response_uninspectable</c> problem response, on
    /// success responses and error responses alike: a refused 2xx/3xx answers
    /// <c>502</c>, a vendor 4xx/5xx keeps its status. A response with no body (empty,
    /// <c>HEAD</c>, a bodiless redirect) is never refused, and a declared non-zero
    /// <c>Content-Length</c> counts as a body except on a <c>HEAD</c>, where the method alone decides. Default <see langword="false"/>: those
    /// classes are forwarded byte-identical and one warning per route and shape names
    /// the class; a refusal instead logs one warning that says the body was REFUSED,
    /// naming the class and the route — the pass-through warning stays only on the
    /// paths that really forward. This option requires <see cref="Enabled"/>:
    /// <c>FailClosed</c> with scrubbing switched off can refuse nothing (nothing is
    /// inspected) and is rejected at startup. Turn this on when an echoed credential
    /// inside an unopened body is a worse outcome than refusing that response; bodies
    /// the matcher can read — every readable charset above included — are scrubbed,
    /// never refused, and requests that injected no credential are never refused at
    /// all. A secret that contains non-ASCII characters is matched only in its UTF-8
    /// bytes. Alias spellings such as latin1, l1, iso8859-1 and cp1252 are not on the
    /// readable list. With the fail-closed option they are refused; in the default mode
    /// their bytes are searched as-is, which finds a plain ASCII echo but is not
    /// guaranteed. Declare the canonical name. The gate reads the DECLARED charset, never
    /// the bytes: a response that misreports its charset is not detected.
    /// </summary>
    public bool FailClosed { get; set; }
}
