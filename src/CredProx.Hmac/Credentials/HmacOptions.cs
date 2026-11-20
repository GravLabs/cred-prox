using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// Options for the <c>Hmac</c> credential type: a shared key plus the canonical-string recipe the
/// <see cref="HmacSignFeature"/> applies at <see cref="Abstractions.Stage.Sign"/>. This is
/// a signature-style credential — the key is never attached to the request; only the
/// computed signature is.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class HmacOptions : IHasPartitionConfig
{
    /// <summary>
    /// The shared key: a <c>secret:</c> reference or a literal. Required. Never attached,
    /// logged or placed in an error message.
    /// </summary>
    public string? Secret { get; set; }

    /// <summary>The HMAC algorithm. Default <see cref="HmacAlgorithm.SHA256"/>.</summary>
    public HmacAlgorithm Algorithm { get; set; } = HmacAlgorithm.SHA256;

    /// <summary>How the raw signature is encoded. Default <see cref="HmacSignatureEncoding.HexLower"/>.</summary>
    public HmacSignatureEncoding Encoding { get; set; } = HmacSignatureEncoding.HexLower;

    /// <summary>
    /// The ordered canonical-string components. Each entry is one of <c>method</c>,
    /// <c>path</c>, <c>query</c>, <c>timestamp</c>, <c>bodyHash</c>, or
    /// <c>header:&lt;Name&gt;</c>. Required, non-empty. A <c>header:&lt;Name&gt;</c>
    /// component on a request where the header is absent contributes an empty string —
    /// and so does one present with an empty value: the two canonicalize identically,
    /// so a signature cannot tell them apart.
    /// </summary>
    public List<string> Components { get; set; } = [];

    /// <summary>
    /// The string joined between components. Default <c>"\n"</c>.
    /// A header, path or query value that carries the separator (or, for a multi-value
    /// header, carries the <c>,</c> that joins its values) makes the canonical string
    /// ambiguous — two distinct requests would sign identically — so such requests are
    /// refused with a <c>credprox.canonical_ambiguous</c> problem response instead of
    /// being signed. A separator that is legal inside header values (<c>|</c>,
    /// <c>&amp;</c>, <c>:</c>, <c>,</c>, space) therefore risks refusals on real
    /// traffic; the newline default cannot occur in a validated header value.
    /// An empty <c>Separator</c> concatenates the components outright, for vendor
    /// schemes that sign a bare concatenation. The separator check cannot apply then
    /// (every value contains the empty string), so such requests keep being signed and
    /// each credential configured this way gets one startup warning naming it; the
    /// other ambiguity refusals still apply — a multi-value header whose values carry
    /// a comma, and a signed name present on both header collections.
    /// </summary>
    public string Separator { get; set; } = "\n";

    /// <summary>How the <c>timestamp</c> component and timestamp header are formatted.
    /// Default <see cref="HmacTimestampFormat.UnixSeconds"/>.</summary>
    public HmacTimestampFormat TimestampFormat { get; set; } = HmacTimestampFormat.UnixSeconds;

    /// <summary>
    /// The request header the signature is written to (replacing any caller value).
    /// Required.
    /// </summary>
    public string? SignatureHeader { get; set; }

    /// <summary>
    /// An optional header the timestamp is also written to, so a verifier can read it
    /// without parsing the canonical string; <see langword="null"/> writes none.
    /// </summary>
    public string? TimestampHeader { get; set; }

    /// <summary>
    /// A literal written before the signature inside the signature header
    /// (for example <c>"HMAC-SHA256 "</c>); <see langword="null"/> writes the raw signature.
    /// </summary>
    public string? SchemePrefix { get; set; }

    /// <summary>
    /// Whether the outbound body is buffered so <c>bodyHash</c> can be computed.
    /// Default <see langword="false"/>: buffering conflicts with YARP streaming,
    /// so it is opt-in and required only when the recipe includes <c>bodyHash</c>.
    /// </summary>
    public bool BufferBody { get; set; }

    /// <summary>
    /// The buffered-body size cap in bytes. A body over the cap answers
    /// <c>413 credprox.body_too_large_to_sign</c> and is not forwarded. Default 1 MiB.
    /// </summary>
    public long MaxBodyBytes { get; set; } = 1024 * 1024;

    /// <summary>
    /// The partition block (<c>From</c> + <c>Allowed</c>) gating every use of the
    /// partition value for this credential; <see langword="null"/> when unpartitioned.
    /// </summary>
    public PartitionConfigOptions? Partition { get; set; }
}

/// <summary>HMAC algorithms; the algorithm is configurable per credential.</summary>
[Experimental("CREDPROX001")]
public enum HmacAlgorithm
{
    /// <summary>HMAC-SHA256.</summary>
    SHA256,

    /// <summary>HMAC-SHA384.</summary>
    SHA384,

    /// <summary>HMAC-SHA512.</summary>
    SHA512,
}

/// <summary>Signature encodings.</summary>
[Experimental("CREDPROX001")]
public enum HmacSignatureEncoding
{
    /// <summary>Lowercase hex.</summary>
    HexLower,

    /// <summary>Uppercase hex.</summary>
    HexUpper,

    /// <summary>Standard base64.</summary>
    Base64,
}

/// <summary>Timestamp formats for the <c>timestamp</c> component and timestamp header.</summary>
[Experimental("CREDPROX001")]
public enum HmacTimestampFormat
{
    /// <summary>Unix seconds.</summary>
    UnixSeconds,

    /// <summary>ISO 8601 round-trip UTC (for example <c>2026-10-15T10:00:00Z</c> form).</summary>
    Iso8601Utc,
}
