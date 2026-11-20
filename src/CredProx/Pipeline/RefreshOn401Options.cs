using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// Options for refresh-on-401: retry once after
/// invalidating the cached token. Idempotent methods retry by default; non-idempotent
/// requests retry only when explicitly enabled and their body fits the buffer limit.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class RefreshOn401Options
{
    /// <summary>
    /// Allow retrying non-idempotent requests (POST, PATCH, …) when their body is within
    /// <see cref="MaxRetriedBodyBytes"/>. Default <see langword="false"/> (off for
    /// non-idempotent by default).
    /// </summary>
    public bool RetryNonIdempotent { get; set; }

    /// <summary>
    /// Maximum request body size that may be buffered for a retry. Bodies above this size
    /// are never retried. Default 1 MiB — the same cap the resilience retry path applies
    /// (<c>ResilienceOptions.MaxRetriedBodyBytes</c>), so both retry paths share one size rule.
    /// </summary>
    public long MaxRetriedBodyBytes { get; set; } = 1024 * 1024;
}
