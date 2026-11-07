using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// Response scrubbing options bound from <c>CredProx:Scrubbing</c> (see
/// <c>docs/credprox-plan.md</c> §8.2, M20): the safety net that removes an injected
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
}
