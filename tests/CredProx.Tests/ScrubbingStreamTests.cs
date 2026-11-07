using System.Text;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// §5.2 "Response scrubbing (M20, §8.2)": the streaming matcher must find and replace
/// every injected value wherever it lands — one write, many writes, split at any byte,
/// split inside a UTF-8 sequence — while everything else flows through untouched.
/// </summary>
public sealed class ScrubbingStreamTests
{
    /// <summary>Feeds its bytes a fixed number at a time, exercising every boundary.</summary>
    private sealed class ChunkFeedStream : Stream
    {
        private readonly byte[] _data;
        private readonly int _chunk;
        private int _position;

        public ChunkFeedStream(string data, int chunk)
        {
            _data = Encoding.UTF8.GetBytes(data);
            _chunk = chunk;
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> destination)
        {
            var count = Math.Min(_chunk, Math.Min(destination.Length, _data.Length - _position));
            _data.AsSpan(_position, count).CopyTo(destination);
            _position += count;
            return count;
        }

        public override ValueTask<int> ReadAsync(Memory<byte> destination, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(Read(destination.Span));

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private static async Task<string> ReadAllAsync(string body, int chunk, IReadOnlyList<string> secrets)
    {
        await using var inner = new ChunkFeedStream(body, chunk);
        await using var scrubbing = new ScrubbingStream(inner, secrets);
        using var result = new MemoryStream();
        await scrubbing.CopyToAsync(result);
        return Encoding.UTF8.GetString(result.ToArray());
    }

    [Fact]
    public async Task WholeBodyInOneRead_ReplacesEveryOccurrence()
    {
        var scrubbed = await ReadAllAsync(
            "error: key ABC123 rejected for ABC123",
            chunk: 4096,
            secrets: ["ABC123"]);

        Assert.Equal("error: key [redacted] rejected for [redacted]", scrubbed);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(7)]
    [InlineData(63)]
    [InlineData(64)]
    public async Task SecretSplitAcrossAnyChunkBoundary_StillFound(int chunk)
    {
        var scrubbed = await ReadAllAsync(
            "before SUPERSECRET-9f2a after",
            chunk,
            ["SUPERSECRET-9f2a"]);

        Assert.Equal("before [redacted] after", scrubbed);
        Assert.DoesNotContain("SECRET", scrubbed, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AdjacentMatches_AllReplaced()
    {
        var scrubbed = await ReadAllAsync("T1T2", 1, ["T"]);

        Assert.Equal("[redacted]1[redacted]2", scrubbed);
    }

    [Fact]
    public async Task OverlappingPatterns_LongestWins()
    {
        // "abc" contains "ab": a left-to-right, longest-first scan must remove the
        // whole secret, not leave the remainder of a shorter match behind.
        var scrubbed = await ReadAllAsync("xabcx", 2, ["ab", "abc"]);

        // The shorter pattern is not applied in turn: no leftover "c" outside the marker.
        Assert.Equal("x[redacted]x", scrubbed);
    }

    [Fact]
    public async Task TwoSecrets_BothReplaced_EvenWhenSplitDifferently()
    {
        var scrubbed = await ReadAllAsync("a=AAA-token b=BBB-token done", 5, ["AAA-token", "BBB-token"]);

        Assert.Equal("a=[redacted] b=[redacted] done", scrubbed);
    }

    [Fact]
    public async Task MultiByteUtf8Secret_SplitMidCharacter_StillFound()
    {
        var scrubbed = await ReadAllAsync("ключ: ключ-секрет here", 3, ["ключ-секрет"]);

        Assert.Equal("ключ: [redacted] here", scrubbed);
    }

    [Fact]
    public async Task NoMatch_BodyPassesThroughByteIdentical()
    {
        const string body = "plain error, nothing echoed: {\"status\":\"failed\"}";

        var scrubbed = await ReadAllAsync(body, 9, ["NEVER-PRESENT"]);

        Assert.Equal(body, scrubbed);
    }

    [Fact]
    public async Task EmptyPatterns_DefensivelyPassThrough()
    {
        // The feature gates on a non-empty registry; the stream's own net is pass-through.
        var scrubbed = await ReadAllAsync("bytes", 2, [""]);

        Assert.Equal("bytes", scrubbed);
    }

    [Fact]
    public async Task LargeBody_WithTinyDestinationBuffers_StreamsFully()
    {
        // 100 KB with the secret near the middle, read 7 bytes at a time: proves the
        // hold-back buffer rotates instead of growing per byte.
        var filler = new string('x', 50_000);
        var body = filler + "TOKEN-mid-0123456789" + filler;

        await using var inner = new ChunkFeedStream(body, 512);
        await using var scrubbing = new ScrubbingStream(inner, ["TOKEN-mid-0123456789"]);
        using var result = new MemoryStream();
        var buffer = new byte[7];
        int read;
        while ((read = await scrubbing.ReadAsync(buffer)) > 0)
        {
            result.Write(buffer, 0, read);
        }

        var scrubbed = Encoding.UTF8.GetString(result.ToArray());
        Assert.DoesNotContain("TOKEN", scrubbed, StringComparison.Ordinal);
        Assert.Equal(filler + "[redacted]" + filler, scrubbed);
    }

    [Fact]
    public void SyncReadPath_Works()
    {
        using var inner = new ChunkFeedStream("echo SECRET end", 4);
        using var scrubbing = new ScrubbingStream(inner, ["SECRET"]);
        using var result = new MemoryStream();
        scrubbing.CopyTo(result);

        Assert.Equal("echo [redacted] end", Encoding.UTF8.GetString(result.ToArray()));
    }

    // ---- the registry (§8.2 design): raw and encoded forms, per request ----

    [Fact]
    public void Registry_GetOrCreate_IsOncePerContext()
    {
        var context = new Microsoft.AspNetCore.Http.DefaultHttpContext();

        var first = CredProxInjectedSecrets.GetOrCreate(context);
        var second = CredProxInjectedSecrets.GetOrCreate(context);

        Assert.Same(first, second);
        Assert.False(first.HasAny);
    }

    [Fact]
    public void Registry_RegistersRawAndUrlEncodedForm()
    {
        var registry = CredProxInjectedSecrets.GetOrCreate(
            new Microsoft.AspNetCore.Http.DefaultHttpContext());

        registry.Register("a b/c?d");

        Assert.Contains("a b/c?d", registry.Values, StringComparer.Ordinal);
        Assert.Contains(Uri.EscapeDataString("a b/c?d"), registry.Values, StringComparer.Ordinal);
        Assert.True(registry.HasAny);
    }

    [Fact]
    public void Registry_DedupesAndIgnoresEmpty()
    {
        var registry = CredProxInjectedSecrets.GetOrCreate(
            new Microsoft.AspNetCore.Http.DefaultHttpContext());

        registry.Register("same");
        registry.Register("same");
        registry.Register(null);
        registry.Register(string.Empty);

        Assert.Equal(["same"], registry.Values);
    }
}
