using System.Text;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The M22 SSE framing: events are scrubbed and emitted whole, as soon as they are
/// complete — streaming never waits on the next event — while a secret split across an
/// event boundary is the documented residue. Cap degradation keeps memory bounded and
/// never lets a secret through.
/// </summary>
public sealed class EventScrubbingStreamTests
{
    private const string Marker = "[redacted]";

    /// <summary>Feeds the payload in fixed-size chunks, async and sync alike.</summary>
    private sealed class ChunkFeedStream : Stream
    {
        private readonly byte[] _data;
        private readonly int _chunkSize;
        private int _position;

        public ChunkFeedStream(byte[] data, int chunkSize)
        {
            _data = data;
            _chunkSize = chunkSize;
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => _data.Length;

        public override long Position
        {
            get => _position;
            set => throw new NotSupportedException();
        }

        public override int Read(Span<byte> destination)
        {
            var count = Math.Min(Math.Min(_chunkSize, _data.Length - _position), destination.Length);
            _data.AsSpan(_position, count).CopyTo(destination);
            _position += count;
            return count;
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            Read(buffer.AsSpan(offset, count));

        public override ValueTask<int> ReadAsync(Memory<byte> destination, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(Read(destination.Span));

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    /// <summary>
    /// Delivers <see cref="FirstSegment"/> freely; every read past it waits on
    /// <see cref="Release"/> — so a scrubber that buffers past a complete event hangs,
    /// and the incrementality test times out loudly.
    /// </summary>
    private sealed class GatedStream : Stream
    {
        private byte[] _first;
        private readonly byte[] _rest;
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private bool _firstDelivered;
        private int _restPosition;

        public GatedStream(byte[] first, byte[] rest)
        {
            _first = first;
            _rest = rest;
        }

        public void Release() => _release.SetResult();

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(Span<byte> destination)
        {
            // Span cannot alias the Memory the async path needs; the copy is its cost.
            var buffer = new byte[destination.Length];
            var read = ReadAsync(buffer).AsTask().GetAwaiter().GetResult();
            buffer.AsSpan(0, read).CopyTo(destination);
            return read;
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            Read(buffer.AsSpan(offset, count));

        public override async ValueTask<int> ReadAsync(Memory<byte> destination, CancellationToken cancellationToken = default)
        {
            if (!_firstDelivered)
            {
                _firstDelivered = true;
                var count = Math.Min(_first.Length, destination.Length);
                _first.AsSpan(0, count).CopyTo(destination.Span);
                if (count < _first.Length)
                {
                    _firstDelivered = false;
                    _first = _first[count..];
                }

                return count;
            }

            await _release.Task.WaitAsync(TimeSpan.FromSeconds(5), cancellationToken);
            var rest = Math.Min(_rest.Length - _restPosition, destination.Length);
            _rest.AsSpan(_restPosition, rest).CopyTo(destination.Span);
            _restPosition += rest;
            return rest; // 0 once the rest is drained — upstream EOF
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private static string Scrub(
        string content, string[] secrets, int feedChunk = int.MaxValue, int readBuffer = 1024)
    {
        using var inner = new ChunkFeedStream(Encoding.UTF8.GetBytes(content), feedChunk == int.MaxValue ? content.Length + 1 : feedChunk);
        using var stream = new EventScrubbingStream(inner, secrets);
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    [Fact]
    public void NoMatch_ByteIdentical()
    {
        var content = "event: message\ndata: hello\n\ndata: world\n\n";
        Assert.Equal(content, Scrub(content, ["secret-value"]));
    }

    [Fact]
    public void SecretInsideEvent_Redacted()
    {
        Assert.Equal(
            $"data: token={Marker}\n\n",
            Scrub("data: token=secret-value\n\n", ["secret-value"]));
    }

    [Fact]
    public void MultipleEvents_EachScrubbed()
    {
        Assert.Equal(
            $"a: {Marker}\n\nb: {Marker}\n\n",
            Scrub("a: s1\n\nb: s2\n\n", ["s1", "s2"]));
    }

    [Fact]
    public void SecretSplitAcrossEvents_IsTheDocumentedResidue()
    {
        // Each event is matched on its own bytes: the halves stay byte-identical.
        var content = "data: abc\n\ndata: def\n\n";
        Assert.Equal(content, Scrub(content, ["abcdef"]));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(7)]
    [InlineData(128)]
    public void DelimiterAndPayloadArbitraryReadSplits(int feedChunk)
    {
        var content = $"data: secret-value\n\nevent: x\ndata: tail\n\n";
        Assert.Equal(
            $"data: {Marker}\n\nevent: x\ndata: tail\n\n",
            Scrub(content, ["secret-value"], feedChunk));
    }

    [Theory]
    [InlineData("\n\n")]
    [InlineData("\n\r\n")]
    [InlineData("\r\n\r\n")]
    [InlineData("\r\r\n")]
    public void AllSpecEventDelimiters_TerminateAnEvent(string delimiter)
    {
        var content = $"data: secret-value{delimiter}event: next{delimiter}";
        var expected = $"data: {Marker}{delimiter}event: next{delimiter}";
        Assert.Equal(expected, Scrub(content, ["secret-value"]));
        Assert.Equal(expected, Scrub(content, ["secret-value"], feedChunk: 2));
    }

    [Fact]
    public async Task FirstEventEmittedWhileUpstreamStillBlocked()
    {
        // The M22 guarantee in one test: event 1 (scrubbed) must flow before ANY byte of
        // event 2 is readable. A hold-back byte-stream implementation would block here.
        var gated = new GatedStream(
            Encoding.UTF8.GetBytes("data: secret-value\n\n"),
            Encoding.UTF8.GetBytes("tail\n\n"));
        using var stream = new EventScrubbingStream(gated, ["secret-value"]);

        var buffer = new byte[64];
        var first = stream.ReadAsync(buffer).AsTask();
        var winner = await Task.WhenAny(first, Task.Delay(2000));
        Assert.Same(first, winner); // the read completed while the gate was still closed
        var firstText = Encoding.UTF8.GetString(buffer, 0, await first);
        Assert.Equal($"data: {Marker}\n\n", firstText);

        gated.Release();
        var rest = await new StreamReader(stream, Encoding.UTF8).ReadToEndAsync();
        Assert.Equal("tail\n\n", rest);
    }

    [Fact]
    public void UnterminatedFinalEvent_FlushedAtEof()
    {
        Assert.Equal($"data: {Marker}", Scrub("data: secret-value", ["secret-value"]));
    }

    [Fact]
    public void MultiByteUtf8_SurvivesByteLevelSplits()
    {
        var content = "data: привет secret-value мир\n\n";
        Assert.Equal(
            $"data: привет {Marker} мир\n\n",
            Scrub(content, ["secret-value"], feedChunk: 3));
    }

    [Fact]
    public void SecretWithNonAscii_ScrubbedAcrossSplits()
    {
        Assert.Equal(
            $"echo {Marker}\n\n",
            Scrub("echo ключ-секрет\n\n", ["ключ-секрет"], feedChunk: 2));
    }

    [Fact]
    public void AdjacentSecrets_WithinEvent()
    {
        Assert.Equal(
            $"data: {Marker}.{Marker}\n\n",
            Scrub("data: aa.bb\n\n", ["aa", "bb"]));
    }

    [Fact]
    public void OverlappingPatterns_LongestWins()
    {
        Assert.Equal(
            $"data: {Marker}\n\n",
            Scrub("data: abcd\n\n", ["abc", "abcd"]));
    }

    [Fact]
    public void EmptyStream_ReadsEmpty()
    {
        Assert.Equal(string.Empty, Scrub(string.Empty, ["secret-value"]));
    }

    [Fact]
    public void EventLargerThanCap_DegradesWithoutLeaking()
    {
        // 100 KB with no terminator: the cap forces hold-back-semantics emission. The
        // secret must still be removed and everything else survive byte-identical.
        var filler = new string('x', 50_000);
        var content = $"data: {filler}secret-value{filler}";
        var result = Scrub(content, ["secret-value"], feedChunk: 4096, readBuffer: 1024);

        Assert.DoesNotContain("secret-value", result, StringComparison.Ordinal);
        Assert.Equal($"data: {filler}{Marker}{filler}", result);
    }

    [Fact]
    public void SecretStraddlingCapEmitBoundary_StillRemoved()
    {
        // Put the secret exactly where the degraded hold-back emits its safe prefix —
        // a match crossing that cut is confirmed only after the next fill.
        var filler = new string('x', 60_000);
        var content = filler + "secret-value" + new string('y', 10_000);
        var result = Scrub(content, ["secret-value"], feedChunk: 8192, readBuffer: 4096);

        Assert.DoesNotContain("secret-value", result, StringComparison.Ordinal);
        Assert.Equal($"{filler}{Marker}{new string('y', 10_000)}", result);
    }

    [Fact]
    public void SyncReadPath_ProducesSameBytes()
    {
        var content = $"data: s1\n\ndata: clean\n\ndata: s2\n\n";
        using var inner = new ChunkFeedStream(Encoding.UTF8.GetBytes(content), 5);
        using var stream = new EventScrubbingStream(inner, ["s1", "s2"]);
        using var memory = new MemoryStream();
        var buffer = new byte[11];
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            memory.Write(buffer, 0, read);
        }

        Assert.Equal(
            $"data: {Marker}\n\ndata: clean\n\ndata: {Marker}\n\n",
            Encoding.UTF8.GetString(memory.ToArray()));
    }

    [Fact]
    public void NoSecrets_PassThrough()
    {
        var content = "data: whatever\n\n";
        Assert.Equal(content, Scrub(content, []));
    }
}
