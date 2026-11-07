using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// Audit options bound from <c>CredProx:Audit</c> (see <c>docs/credprox-plan.md</c>
/// §4 "Audit log", §5.2 "Audit"). Redaction happens in the core before any sink sees the
/// record, so a sink — built-in or plugin — never receives a value the configuration
/// marks as sensitive.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class CredProxAuditOptions
{
    private TimeSpan _sinkTimeout = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Whether audit records are produced at all. Default <see langword="true"/>; with no
    /// sink registered nothing is written either way.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// How long a single sink write may hold the completed request before the core gives
    /// up on it (logged, never surfaced to the caller). Default 5 seconds; must be
    /// positive. This is the §5.2 bound: a hung sink delays nothing the caller waits on
    /// (the record is written after the response is on the wire) and never fails it.
    /// </summary>
    public TimeSpan SinkTimeout
    {
        get => _sinkTimeout;
        set
        {
            if (value <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(value), "The audit sink timeout must be positive.");
            }

            _sinkTimeout = value;
        }
    }

    /// <summary>
    /// Request header names captured into the record's <c>headers</c> field. Empty
    /// (default) captures no headers. A captured header whose name is redacted — by
    /// <see cref="RedactHeaders"/> or the built-in sensitive set — appears masked.
    /// </summary>
    public IList<string> IncludeHeaders { get; set; } = [];

    /// <summary>
    /// Additional header names whose captured values are masked (case-insensitive), on
    /// top of the built-in sensitive set (authorization, cookie and the configured
    /// caller-key headers).
    /// </summary>
    public IList<string> RedactHeaders { get; set; } = [];

    /// <summary>
    /// Field names masked at any nesting depth of the record (case-insensitive), on top
    /// of the built-in sensitive set (password, secret, token-like and key-like names).
    /// Applies to every nested object in the record — the captured <c>headers</c> map
    /// today, and any future structured capture.
    /// </summary>
    public IList<string> RedactJsonFields { get; set; } = [];
}
