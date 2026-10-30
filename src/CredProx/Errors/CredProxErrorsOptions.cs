using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// Options for <c>CredProx:Errors</c> (M24, plan §8.5): vendor error normalisation.
/// Bound as a plain singleton, like the scrubbing options.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class CredProxErrorsOptions
{
    /// <summary>
    /// Whether vendor 4xx/5xx text-like error bodies are rewritten into RFC 7807
    /// <c>application/problem+json</c> with the original payload embedded as the
    /// <c>vendor_detail</c> extension member. On by default; per-route opt-out via the
    /// <c>CredProx.ErrorNormalisation = "off"</c> route metadata.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Maximum vendor error body, in bytes, that is buffered for normalisation. A body
    /// beyond the cap is forwarded byte-identical (a warning is logged) — never
    /// truncated into the problem document, never buffered without bound.
    /// Default 8192.
    /// </summary>
    public long MaxNormalisedBodyBytes { get; set; } = 8192;
}
