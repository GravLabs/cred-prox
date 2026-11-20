using System.Text;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// Streaming semantics of the JSON escaped-echo mode (M45 security finding R-3): the
/// escaped-mode holdback must stay per-batch honest. A caller streaming a small JSON body
/// gets its first byte while the body is still open — no byte is withheld that cannot
/// still complete a match. And a fully <c>\uXXXX</c>-escaped secret, fed with the delivery
/// boundary landing at every byte offset of its source span, is never part-emitted: raw
/// source bytes of the secret must not reach the reader before the full span is decided.
/// </summary>
public sealed class JsonEscapedStreamingTests
{
    /// <summary>
    /// Serves up to <paramref name="firstLimit"/> bytes, then reports no EOF — every read
    /// parks until <see cref="Release"/> — so the test observes exactly what the scrubber
    /// emits while the inner stream is still open.
    /// </summary>
    private sealed class GatedFeedStream(byte[] data, int firstLimit) : Stream
    {
        private readonly TaskCompletionSource _open = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _position;

        public void Release() => _open.TrySetResult();

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Flush()
        {
        }

        public override int Read(Span<byte> destination)
        {
            while (true)
            {
                var cap = _open.Task.IsCompleted ? data.Length : Math.Min(firstLimit, data.Length);
                if (_position < cap)
                {
                    var count = Math.Min(destination.Length, cap - _position);
                    data.AsSpan(_position, count).CopyTo(destination);
                    _position += count;
                    return count;
                }

                if (_open.Task.IsCompleted)
                {
                    return 0; // every byte served after Release: end of stream
                }

                _open.Task.Wait(CancellationToken.None);
            }
        }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override async ValueTask<int> ReadAsync(
            Memory<byte> destination, CancellationToken cancellationToken = default)
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var cap = _open.Task.IsCompleted ? data.Length : Math.Min(firstLimit, data.Length);
                if (_position < cap)
                {
                    var count = Math.Min(destination.Length, cap - _position);
                    data.AsSpan(_position, count).CopyTo(destination.Span);
                    _position += count;
                    return count;
                }

                if (_open.Task.IsCompleted)
                {
                    return 0; // every byte served after Release: end of stream
                }

                // Park without owning a thread: the caller's token cancels the wait.
                await _open.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    [Fact]
    public async Task EscapedMode_BodySmallerThanTheEscapedHoldback_FirstByteReachesReaderBeforeEof()
    {
        const string Secret = "ABCDEFGHIJKLMNOP";
        var body = """{"status":"ok","detail":"nothing secret here at all"}""";
        Assert.True(
            Encoding.UTF8.GetByteCount(body) < Secret.Length * 6,
            "the body must stay below six times the longest registered value");

        await using var inner = new GatedFeedStream(Encoding.UTF8.GetBytes(body), firstLimit: body.Length);
        await using var scrubbing = new ScrubbingStream(inner, [Secret], escapedEcho: true);

        var buffer = new byte[64];
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));
        int first;
        try
        {
            first = await scrubbing.ReadAsync(buffer, cts.Token);
        }
        catch (OperationCanceledException)
        {
            first = 0; // the read parked: every byte was withheld until EOF
        }

        inner.Release();
        Assert.True(first > 0, "no byte reached the reader while the body was withheld to the escaped holdback");
        Assert.Equal((byte)'{', buffer[0]);
    }

    [Fact]
    public async Task FullyEscapedSecret_FedWithBoundaryAtEveryOffset_NoSourceByteLeaksEarly()
    {
        const string Secret = "ABCDEFGHIJKLMNOP";
        var escaped = string.Concat(Secret.Select(static c => $@"\u{(int)c:x4}"));
        var prefix = "{\"k\":\"";
        var suffix = "\",\"z\":1}";
        var body = prefix + escaped + suffix;
        var bodyBytes = Encoding.UTF8.GetBytes(body);
        var secretStart = prefix.Length;
        var secretEnd = secretStart + escaped.Length;
        var expected = "{\"k\":\"[redacted]\",\"z\":1}";

        for (var first = 1; first < secretEnd; first++)
        {
            await using var inner = new GatedFeedStream(bodyBytes, firstLimit: first);
            await using var scrubbing = new ScrubbingStream(inner, [Secret], escapedEcho: true);
            using var seen = new MemoryStream();
            var buffer = new byte[4096];
            using (var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(250)))
            {
                try
                {
                    while (true)
                    {
                        var n = await scrubbing.ReadAsync(buffer, cts.Token);
                        if (n == 0)
                        {
                            break;
                        }

                        seen.Write(buffer, 0, n);
                    }
                }
                catch (OperationCanceledException)
                {
                    // The scrubber withheld the tail while the inner stream stayed open:
                    // withholding is the safe direction; only emitted bytes can leak.
                }
            }

            var streamed = seen.ToArray();
            for (var i = secretStart; i + 6 <= secretEnd; i++)
            {
                Assert.False(
                    ContainsSlice(streamed, bodyBytes.AsSpan(i, 6)),
                    $"delivery boundary {first}: raw escaped source at {i} reached the reader before the span was decided");
            }

            inner.Release();
            await scrubbing.CopyToAsync(seen);
            Assert.Equal(expected, Encoding.UTF8.GetString(seen.ToArray()));
        }
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    public async Task ShortRegisteredValue_EscapedEchoAcrossTheEmitBoundary_NoRawEscapeByteLeaks(int length)
    {
        var secret = new string(Enumerable.Range('A', length).Select(static i => (char)i).ToArray());
        var escaped = string.Concat(secret.Select(static c => $@"\u{(int)c:x4}"));
        var body = "{\"k\":\"" + escaped + "\"}";
        var bodyBytes = Encoding.UTF8.GetBytes(body);
        var expected = """{"k":"[redacted]"}""";

        // The escaped-mode holdback bump is load-bearing exactly when the LONGEST registered
        // value is short: the raw floor (maxPatternLength - 1) then falls below the 5-byte
        // trailing PARTIAL escape (\', 'u', three hexits) that the no-full-escape fast path
        // streams out before any match is decided. Lengths 1..5 sit under that bound, 6 and 7
        // above it — the sweep that keeps a "simplify the floor" change from silently
        // reopening a real escaped-echo disclosure (the final body would carry the value,
        // escaped). Every boundary that cuts through the escape, per cell.
        for (var first = 1; first < bodyBytes.Length && first <= 18; first++)
        {
            await using var inner = new GatedFeedStream(bodyBytes, firstLimit: first);
            await using var scrubbing = new ScrubbingStream(inner, [secret], escapedEcho: true);
            using var seen = new MemoryStream();
            var buffer = new byte[4096];
            using (var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(250)))
            {
                try
                {
                    while (true)
                    {
                        var n = await scrubbing.ReadAsync(buffer, cts.Token);
                        if (n == 0)
                        {
                            break;
                        }

                        seen.Write(buffer, 0, n);
                    }
                }
                catch (OperationCanceledException)
                {
                    // The tail is withheld while the inner stream stays open: withholding is
                    // the safe direction; only emitted bytes can leak.
                }
            }

            // Neither endpoint of the body — the {"k":" prefix or the "} suffix — contains a
            // backslash, so a backslash in the pre-EOF stream can only be escape source
            // bytes that reached the reader before the decision.
            Assert.False(
                seen.ToArray().Contains((byte)'\\'),
                $"value '{secret}', boundary {first}: raw escaped source reached the reader before the span was decided");

            inner.Release();
            await scrubbing.CopyToAsync(seen);
            Assert.Equal(expected, Encoding.UTF8.GetString(seen.ToArray()));
        }
    }

    private static bool ContainsSlice(byte[] haystack, ReadOnlySpan<byte> needle)
    {
        for (var j = 0; j + needle.Length <= haystack.Length; j++)
        {
            if (haystack.AsSpan(j, needle.Length).SequenceEqual(needle))
            {
                return true;
            }
        }

        return false;
    }
}
