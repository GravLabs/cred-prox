using System.Text;

namespace CredProx;

/// <summary>
/// The one secret matcher the scrubbers share (M20, plan §8.2): compiled UTF-8 patterns
/// tried longest-first, and the batch builder that replaces every occurrence of a
/// pattern in a pending buffer with <c>[redacted]</c> (<see cref="AuditRedactor.Masked"/>)
/// up to an explicit emit boundary. <see cref="ScrubbingStream"/> (byte-stream framing)
/// and <see cref="EventScrubbingStream"/> (SSE event framing) differ only in where they
/// put that boundary.
/// </summary>
internal static class SecretScrubber
{
    internal static readonly byte[] Replacement = Encoding.UTF8.GetBytes(AuditRedactor.Masked);

    /// <summary>
    /// UTF-8 byte patterns for the registered secrets: non-empty, ordered longest
    /// first so the longest match wins wherever two patterns start at the same byte.
    /// </summary>
    internal static byte[][] CompilePatterns(IReadOnlyList<string> secrets) =>
    [
        .. secrets
            .Where(secret => !string.IsNullOrEmpty(secret))
            .Select(secret => Encoding.UTF8.GetBytes(secret))
            .Where(bytes => bytes.Length > 0)
            .OrderByDescending(bytes => bytes.Length),
    ];

    /// <summary>
    /// Scrubs <paramref name="pending"/> up to <paramref name="emitLength"/>, replacing
    /// matches in place. A match may start before the boundary and run past it — a
    /// pattern fully present in <paramref name="pending"/> is a confirmed secret — so
    /// such a match consumes its tail too. Returns the batch (whose content length is
    /// <c>BatchLength</c>; the array is over-allocated on purpose) and the
    /// <c>ConsumedThrough</c> offset of every byte represented in the batch: the caller
    /// keeps everything from there onward as the not-yet-emitted remainder.
    /// </summary>
    internal static (byte[] Batch, int BatchLength, int ConsumedThrough) ScrubBatch(
        ReadOnlySpan<byte> pending, int emitLength, byte[][] patterns, byte[] replacement)
    {
        // The batch can only grow where a secret is replaced by the marker; start
        // generous and grow on demand.
        var batch = new byte[emitLength + replacement.Length];
        var batchLength = 0;
        var lastEmitted = 0;

        // Bytes fully represented in the batch: every replacement ends at or after its
        // match end, so a match running past the emit boundary consumes its tail too.
        var consumedThrough = emitLength;

        for (var pos = 0; pos < emitLength;)
        {
            var pattern = FindMatchAt(pending, pos, patterns);
            if (pattern is null)
            {
                pos++;
                continue;
            }

            var literalLength = pos - lastEmitted;
            var needed = batchLength + literalLength + replacement.Length;
            if (needed > batch.Length)
            {
                Array.Resize(ref batch, Math.Max(needed, batch.Length * 2));
            }

            pending.Slice(lastEmitted, literalLength).CopyTo(batch.AsSpan(batchLength));
            replacement.CopyTo(batch.AsSpan(batchLength + literalLength));
            batchLength = needed;

            lastEmitted = pos + pattern.Length;
            pos = lastEmitted;
            if (lastEmitted > consumedThrough)
            {
                consumedThrough = lastEmitted;
            }
        }

        // Tail literal up to the emit boundary (negative when the last replacement ran
        // past it — those bytes are already in the batch as part of the removal).
        var tailLength = Math.Max(0, emitLength - lastEmitted);
        if (tailLength > 0)
        {
            if (batchLength + tailLength > batch.Length)
            {
                Array.Resize(ref batch, batchLength + tailLength);
            }

            pending.Slice(lastEmitted, tailLength).CopyTo(batch.AsSpan(batchLength));
            batchLength += tailLength;
        }

        return (batch, batchLength, consumedThrough);
    }

    private static byte[]? FindMatchAt(ReadOnlySpan<byte> pending, int pos, byte[][] patterns)
    {
        foreach (var pattern in patterns) // longest first: the longest match wins
        {
            if (pos + pattern.Length <= pending.Length
                && pending.Slice(pos, pattern.Length).SequenceEqual(pattern))
            {
                return pattern;
            }
        }

        return null;
    }
}
