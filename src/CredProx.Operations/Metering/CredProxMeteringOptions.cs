using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// Usage-metering options, bound from <c>CredProx:Metering</c> at startup (M50, ADR-0008).
/// The metering leg arms through <c>.AddOperations()</c> when this section is present —
/// the section's presence is the switch, as for the other Operations legs. LLM token
/// counting is a further per-route opt-in through
/// <see cref="CredProxMetering.UsageRouteMetadata"/>.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class CredProxMeteringOptions
{
    /// <summary>
    /// Maximum response-body bytes parsed for a token usage report on opted-in routes.
    /// Bytes beyond the window still reach the caller unchanged and usage past the window
    /// counts as unmetered — never guessed. Bounds the peek's parse memory; the caller's
    /// stream is never buffered.
    /// </summary>
    public long MaxUsageParseBytes { get; set; } = 1024 * 1024;
}
