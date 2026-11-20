namespace CredProx;

/// <summary>
/// Raised by <see cref="HmacSigner.BuildCanonicalString"/> when a component it would
/// join resolves to an ambiguous value under the configuration: a header, path or
/// query value carrying the configured separator, or a value carrying the ',' that
/// joins a multi-value header's values. Such a canonical string cannot be bound to one
/// request — two distinct requests produce it and sign identically — so signing is
/// refused rather than computed. The canonical form is deliberately NOT escaped: the
/// vendor computes the same join, and escaping would break every signature it accepts.
/// The message names the offending component only, never its value.
/// </summary>
internal sealed class HmacCanonicalAmbiguousException(string message) : Exception(message);
