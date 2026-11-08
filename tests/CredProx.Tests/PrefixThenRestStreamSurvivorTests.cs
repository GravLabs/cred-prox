using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage of <see cref="PrefixThenRestStream"/>: the dispose path is the
/// one behaviour the passthrough wrapper owes its callers (§5.2 byte-identical forwarding
/// includes cleaning up the vendor stream), and mutation triage found no witness.
/// </summary>
public sealed class PrefixThenRestStreamSurvivorTests
{
    private sealed class TrackingStream : MemoryStream
    {
        public bool WasDisposed { get; private set; }

        public TrackingStream(byte[] buffer)
            : base(buffer)
        {
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                WasDisposed = true;
            }

            base.Dispose(disposing);
        }
    }

    [Fact]
    public void Dispose_DisposesBothInnerStreams()
    {
        var rest = new TrackingStream("tail"u8.ToArray());
        var wrapper = new PrefixThenRestStream("head"u8.ToArray(), rest);

        wrapper.Dispose();

        Assert.True(rest.WasDisposed); // the vendor stream must not outlive the wrapper
    }

    [Fact]
    public void Dispose_ThenReadWithUndrainedPrefix_ThrowsObjectDisposed()
    {
        var wrapper = new PrefixThenRestStream("head"u8.ToArray(), new MemoryStream());
        wrapper.Dispose();

        // The prefix stream is disposed with the wrapper: a post-dispose read must fail,
        // never replay bytes through a half-released wrapper.
        Assert.Throws<ObjectDisposedException>(() => wrapper.Read(new byte[1], 0, 1));
    }

    [Fact]
    public async Task ZeroLengthProbe_LeavesPrefixIntact()
    {
        // Pinned while at it (the copy loop opens with this probe): a 0-byte read must
        // consume nothing from either segment.
        var wrapper = new PrefixThenRestStream("head"u8.ToArray(), new MemoryStream("tail"u8.ToArray()));
        Assert.Equal(0, await wrapper.ReadAsync(Memory<byte>.Empty));
        var buffer = new byte[8];
        var total = 0;
        int read;
        while ((read = await wrapper.ReadAsync(buffer.AsMemory(total))) > 0)
        {
            total += read;
        }

        Assert.Equal("headtail"u8.ToArray(), buffer.AsSpan(0, total).ToArray());
    }
}
