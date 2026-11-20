using System.Buffers;
using System.Text;

namespace CredProx;

/// <summary>
/// The one secret matcher the scrubbers share: compiled UTF-8 patterns
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
    /// <remarks>
    /// The returned batch comes from <paramref name="pool"/> and is the caller's to
    /// return: consume at most <c>BatchLength</c> bytes (the rented array is at least
    /// that long and may carry other callers' bytes beyond it), then
    /// <c>Return(batch, clearArray: true)</c> once the bytes are copied or written out.
    /// </remarks>
    internal static (byte[] Batch, int BatchLength, int ConsumedThrough) ScrubBatch(
        ReadOnlySpan<byte> pending, int emitLength, byte[][] patterns, byte[] replacement, ArrayPool<byte> pool)
    {
        // The batch can only grow where a secret is replaced by the marker; start
        // generous and grow on demand.
        var batch = pool.Rent(emitLength + replacement.Length);
        var batchLength = 0;
        var lastEmitted = 0;

        // Bytes fully represented in the batch: every replacement ends at or after its
        // match end, so a match running past the emit boundary consumes its tail too.
        var consumedThrough = emitLength;
        try
        {
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
                    var grown = pool.Rent(Math.Max(needed, batch.Length * 2));
                    batch.AsSpan(0, batchLength).CopyTo(grown);
                    pool.Return(batch, clearArray: true);
                    batch = grown;
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

            // Tail literal up to the emit boundary (negative when the last replacement
            // ran past it — those bytes are already in the batch as part of the
            // removal).
            var tailLength = Math.Max(0, emitLength - lastEmitted);
            if (tailLength > 0)
            {
                if (batchLength + tailLength > batch.Length)
                {
                    var grown = pool.Rent(batchLength + tailLength);
                    batch.AsSpan(0, batchLength).CopyTo(grown);
                    pool.Return(batch, clearArray: true);
                    batch = grown;
                }

                pending.Slice(lastEmitted, tailLength).CopyTo(batch.AsSpan(batchLength));
                batchLength += tailLength;
            }

            var result = (batch, batchLength, consumedThrough);
            batch = null!; // ownership transfers to the caller; the guard below stands down
            return result;
        }
        finally
        {
            // F4: nothing in here is expected to throw, but a throw that abandoned a
            // rented buffer would hand secret-bearing bytes to the GC instead of the
            // pool. Every growth already returned the old array and repointed the
            // local, so the finally returns only the still-owned buffer — never a
            // returned one.
            if (batch != null)
            {
                pool.Return(batch, clearArray: true);
            }
        }
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

    /// <summary>
    /// Whether the window holds a <c>\uXXXX</c> escape (four hex digits, either case)
    /// worth building an unescaped view for. Without one the view would be
    /// byte-identical to the window, and the plain matcher already finds every match.
    /// </summary>
    internal static bool ContainsJsonEscape(ReadOnlySpan<byte> window)
    {
        for (var i = 0; i + 5 < window.Length; i++)
        {
            if (window[i] != (byte)'\\' || window[i + 1] != (byte)'u')
            {
                continue;
            }

            if (IsHex(window[i + 2]) && IsHex(window[i + 3]) && IsHex(window[i + 4]) && IsHex(window[i + 5]))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// The JSON-body sibling of <see cref="ScrubBatch"/>: matches every pattern through
    /// a view in which <c>\uXXXX</c> escapes — four hex digits, either case, surrogate
    /// pairs combined — are decoded to the bytes they stand for, while each replacement
    /// lands on the ORIGINAL escaped bytes: the matched view span maps back to whole
    /// source units, so an escape is never half-replaced and the body stays exactly as
    /// parseable as it arrived. Malformed escapes (<c>\u</c> without four hex digits, a
    /// lone surrogate, <c>\x</c>) are ordinary text: they decode to nothing and never
    /// throw. Same batch, boundary and pool contract as <see cref="ScrubBatch"/>.
    /// </summary>
    internal static (byte[] Batch, int BatchLength, int ConsumedThrough) ScrubBatchEscaped(
        ReadOnlySpan<byte> pending, int emitLength, byte[][] patterns, byte[] replacement, ArrayPool<byte> pool)
    {
        // The view never exceeds the window: a raw byte maps to itself and an escape
        // (six source bytes) decodes to at most four.
        var view = pool.Rent(pending.Length);
        var map = ArrayPool<int>.Shared.Rent(pending.Length);
        try
        {
            var viewLength = BuildView(pending, view, map);

            // Per-batch cap (M45 security finding R-3): the caller's floor cannot see WHICH
            // tail bytes are undecided. Raw bytes inside a trailing partial escape (or a
            // trailing high surrogate awaiting its pair) decode differently retroactively;
            // a view suffix ending at the boundary that is a strict prefix of a registered
            // value can still complete. Withhold from the earliest source position either
            // reaches — the real trailing source span. When the whole window is emitted
            // (EOF) nothing more can arrive, so the batch stays uncapped.
            var emitLimit = emitLength;
            if (emitLength < pending.Length && emitLimit > 0)
            {
                // -1 (no undecided tail) means EVERY view byte is decided: the cut is
                // the whole window. The scan below and the cap seed must use the same
                // clamped cut — an unclamped -1 degenerates the view-end scan to zero
                // and the prefix check never fires.
                var undecided = UndecidedTailStart(pending, pending.Length);
                var cut = undecided < 0 ? pending.Length : undecided;
                var viewEnd = 0; // view bytes deriving entirely from decided source
                while (viewEnd < viewLength && map[viewEnd] < cut)
                {
                    viewEnd++;
                }

                var cap = cut;
                var maxPatternLength = patterns.Length == 0 ? 0 : patterns[0].Length;
                for (var p = viewEnd - 1; p >= 0 && viewEnd - p < maxPatternLength; p--)
                {
                    foreach (var pattern in patterns)
                    {
                        if (pattern.Length > viewEnd - p
                            && pattern.AsSpan(0, viewEnd - p).SequenceEqual(view.AsSpan(p, viewEnd - p)))
                        {
                            cap = Math.Min(cap, map[p]);
                            break;
                        }
                    }
                }

                emitLimit = Math.Min(emitLimit, cap);
            }

            var batch = pool.Rent(emitLength + replacement.Length);
            var batchLength = 0;
            var lastEmitted = 0;

            // Bytes fully represented in the batch: as in ScrubBatch, a match fully
            // present in pending is confirmed even when its source span runs past the
            // emit boundary — the whole span is removed and consumed. The walk starts
            // at the capped boundary so undecided tail bytes stay in pending.
            var consumedThrough = emitLimit;
            try
            {
                // pos walks the view; a replacement starts only when the match's FIRST
                // source byte lies before the emit boundary.
                for (var pos = 0; pos < viewLength && map[pos] < emitLimit;)
                {
                    var pattern = FindMatchAt(view.AsSpan(0, viewLength), pos, patterns);
                    if (pattern is null)
                    {
                        pos++;
                        continue;
                    }

                    var sourceStart = map[pos];
                    var sourceEnd = pos + pattern.Length < viewLength
                        ? map[pos + pattern.Length]
                        : pending.Length;

                    var literalLength = sourceStart - lastEmitted;
                    var needed = batchLength + literalLength + replacement.Length;
                    if (needed > batch.Length)
                    {
                        var grown = pool.Rent(Math.Max(needed, batch.Length * 2));
                        batch.AsSpan(0, batchLength).CopyTo(grown);
                        pool.Return(batch, clearArray: true);
                        batch = grown;
                    }

                    pending.Slice(lastEmitted, literalLength).CopyTo(batch.AsSpan(batchLength));
                    replacement.CopyTo(batch.AsSpan(batchLength + literalLength));
                    batchLength = needed;

                    lastEmitted = sourceEnd;
                    pos += pattern.Length;
                    if (sourceEnd > consumedThrough)
                    {
                        consumedThrough = sourceEnd;
                    }
                }

                // Tail literal up to the emit boundary (negative when the last
                // replacement ran past it — those bytes are already removed).
                var tailLength = Math.Max(0, emitLimit - lastEmitted);
                if (tailLength > 0)
                {
                    if (batchLength + tailLength > batch.Length)
                    {
                        var grown = pool.Rent(batchLength + tailLength);
                        batch.AsSpan(0, batchLength).CopyTo(grown);
                        pool.Return(batch, clearArray: true);
                        batch = grown;
                    }

                    pending.Slice(lastEmitted, tailLength).CopyTo(batch.AsSpan(batchLength));
                    batchLength += tailLength;
                }

                var result = (batch, batchLength, consumedThrough);
                batch = null!; // ownership transfers to the caller; the finally stands down
                return result;
            }
            finally
            {
                if (batch != null)
                {
                    pool.Return(batch, clearArray: true);
                }
            }
        }
        finally
        {
            // The view carried decoded response bytes — cleared on return, same
            // discipline as the batch and pending buffers. The map is offsets.
            pool.Return(view, clearArray: true);
            ArrayPool<int>.Shared.Return(map);
        }
    }

    /// <summary>
    /// Start of the undecided raw tail ending at <paramref name="end"/>: a trailing partial
    /// <c>\uXXXX</c> escape, chained through at most one trailing complete high-surrogate
    /// escape whose pairing is still open. Bytes from the result on can decode differently
    /// once more source arrives; -1 when the tail is fully decided.
    /// </summary>
    private static int UndecidedTailStart(ReadOnlySpan<byte> pending, int end)
    {
        var tail = PartialEscapeStart(pending, end);
        var chainEnd = tail >= 0 ? tail : end;
        if (chainEnd >= 6
            && pending[chainEnd - 6] == (byte)'\\' && pending[chainEnd - 5] == (byte)'u'
            && IsHex(pending[chainEnd - 4]) && IsHex(pending[chainEnd - 3])
            && IsHex(pending[chainEnd - 2]) && IsHex(pending[chainEnd - 1])
            && HexValue(pending[chainEnd - 4], pending[chainEnd - 3], pending[chainEnd - 2], pending[chainEnd - 1]) is >= 0xD800 and <= 0xDBFF)
        {
            // High surrogate right before the tail: it pairs (or fails to) with the NEXT
            // unit, so it stays undecided while that unit is undecided or absent. The unit
            // before IT is decided (pairing with a high always fails) — chain stops here.
            return chainEnd - 6;
        }

        return tail;
    }

    private static int PartialEscapeStart(ReadOnlySpan<byte> pending, int end)
    {
        // A proper prefix of '\' 'u' hex hex hex hex ending the span: up to five bytes.
        for (var start = Math.Max(end - 5, 0); start < end; start++)
        {
            if (pending[start] != (byte)'\\')
            {
                continue;
            }

            var tail = end - start;
            var looksEscape = tail == 1 || pending[start + 1] == (byte)'u';
            for (var k = 2; looksEscape && k < tail; k++)
            {
                looksEscape = IsHex(pending[start + k]);
            }

            if (looksEscape)
            {
                return start;
            }
        }

        return -1;
    }

    /// <summary>
    /// Decodes <c>\uXXXX</c> escapes in <paramref name="pending"/> into
    /// <paramref name="view"/>, recording for every view byte the window offset of the
    /// source unit that produced it: raw bytes map to themselves, a valid escape maps
    /// its one-to-four decoded bytes to the escape's offset, and a valid surrogate pair
    /// (two adjacent escapes) maps four bytes to the pair's start. Anything malformed
    /// passes through as literal bytes, one map entry each.
    /// </summary>
    /// <returns>The view length; never exceeds <c>pending.Length</c>.</returns>
    private static int BuildView(ReadOnlySpan<byte> pending, byte[] view, int[] map)
    {
        var viewLength = 0;
        var i = 0;
        while (i < pending.Length)
        {
            var b = pending[i];
            if (b == (byte)'\\' && i + 5 < pending.Length && pending[i + 1] == (byte)'u'
                && IsHex(pending[i + 2]) && IsHex(pending[i + 3]) && IsHex(pending[i + 4]) && IsHex(pending[i + 5]))
            {
                var unit = HexValue(pending[i + 2], pending[i + 3], pending[i + 4], pending[i + 5]);

                if (unit is >= 0xD800 and <= 0xDBFF && i + 11 < pending.Length
                    && pending[i + 6] == (byte)'\\' && pending[i + 7] == (byte)'u'
                    && IsHex(pending[i + 8]) && IsHex(pending[i + 9]) && IsHex(pending[i + 10]) && IsHex(pending[i + 11]))
                {
                    var pair = HexValue(pending[i + 8], pending[i + 9], pending[i + 10], pending[i + 11]);
                    if (pair is >= 0xDC00 and <= 0xDFFF)
                    {
                        var codePoint = 0x10000 + ((unit - 0xD800) << 10) + (pair - 0xDC00);
                        var written = WriteUtf8(view.AsSpan(viewLength), codePoint);
                        map.AsSpan(viewLength, written).Fill(i);
                        viewLength += written;
                        i += 12;
                        continue;
                    }
                }

                if (unit is not (>= 0xD800 and <= 0xDFFF))
                {
                    var written = WriteUtf8(view.AsSpan(viewLength), unit);
                    map.AsSpan(viewLength, written).Fill(i);
                    viewLength += written;
                    i += 6;
                    continue;
                }

                // A lone-surrogate escape is not valid JSON and decodes to no
                // character: its bytes fall through as literal text below.
            }

            view[viewLength] = b;
            map[viewLength] = i;
            viewLength++;
            i++;
        }

        return viewLength;
    }

    private static int WriteUtf8(Span<byte> destination, int codePoint)
    {
        if (codePoint < 0x80)
        {
            destination[0] = (byte)codePoint;
            return 1;
        }

        if (codePoint < 0x800)
        {
            destination[0] = (byte)(0xC0 | codePoint >> 6);
            destination[1] = (byte)(0x80 | codePoint & 0x3F);
            return 2;
        }

        if (codePoint < 0x10000)
        {
            destination[0] = (byte)(0xE0 | codePoint >> 12);
            destination[1] = (byte)(0x80 | (codePoint >> 6) & 0x3F);
            destination[2] = (byte)(0x80 | codePoint & 0x3F);
            return 3;
        }

        destination[0] = (byte)(0xF0 | codePoint >> 18);
        destination[1] = (byte)(0x80 | (codePoint >> 12) & 0x3F);
        destination[2] = (byte)(0x80 | (codePoint >> 6) & 0x3F);
        destination[3] = (byte)(0x80 | codePoint & 0x3F);
        return 4;
    }

    private static bool IsHex(byte value) =>
        value is >= (byte)'0' and <= (byte)'9'
            or >= (byte)'a' and <= (byte)'f'
            or >= (byte)'A' and <= (byte)'F';

    private static int HexValue(byte a, byte b, byte c, byte d) =>
        (Digit(a) << 12) | (Digit(b) << 8) | (Digit(c) << 4) | Digit(d);

    private static int Digit(byte value) =>
        value <= (byte)'9' ? value - '0' : (value | 0x20) - 'a' + 10;
}
