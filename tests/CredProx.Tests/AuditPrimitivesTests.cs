using System.Text;
using CredProx;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage of the audit primitives: the always-masked header and JSON-field
/// defaults (each name is a secret-bearing shape the §5.2 list pins), the byte-counting
/// response wrapper, and the audit sink-timeout guard.
/// </summary>
public sealed class AuditPrimitivesTests
{
    // ---- AuditRedactor defaults ----

    [Theory]
    [InlineData("Authorization")]
    [InlineData("Proxy-Authorization")]
    [InlineData("Cookie")]
    [InlineData("Set-Cookie")]
    [InlineData("WWW-Authenticate")]
    [InlineData("X-CredProx-Key")]
    public void DefaultRedactHeaders_AlwaysMask(string name)
    {
        Assert.Contains(name, AuditRedactor.DefaultRedactHeaders);
        Assert.Contains(name.ToLowerInvariant(), AuditRedactor.DefaultRedactHeaders); // case-insensitive set
    }

    [Theory]
    [InlineData("password")]
    [InlineData("secret")]
    [InlineData("token")]
    [InlineData("access_token")]
    [InlineData("refresh_token")]
    [InlineData("client_secret")]
    [InlineData("api_key")]
    [InlineData("apikey")]
    [InlineData("certificate")]
    [InlineData("private_key")]
    public void DefaultRedactJsonFields_AlwaysMask(string name)
    {
        Assert.Contains(name, AuditRedactor.DefaultRedactJsonFields);
    }

    [Fact]
    public void Redact_NullFields_Throws()
    {
        Assert.Throws<ArgumentNullException>(
            () => AuditRedactor.Redact(null!, AuditRedactor.DefaultRedactHeaders, AuditRedactor.DefaultRedactJsonFields));
    }

    // ---- CountingResponseBodyStream ----

    [Fact]
    public void CountingStream_WriteOnlyShape()
    {
        using var counting = new CountingResponseBodyStream(new MemoryStream());

        Assert.False(counting.CanRead);
        Assert.False(counting.CanSeek);
        Assert.True(counting.CanWrite);
        Assert.Equal(0, counting.BytesWritten);

        Assert.Throws<NotSupportedException>(() => counting.Length);
        Assert.Throws<NotSupportedException>(() => counting.Position);
        Assert.Throws<NotSupportedException>(() => counting.Position = 0);
        Assert.Throws<NotSupportedException>(() => counting.Read(new byte[1], 0, 1));
        Assert.Throws<NotSupportedException>(() => counting.Seek(0, SeekOrigin.Begin));
        Assert.Throws<NotSupportedException>(() => counting.SetLength(1));
    }

    [Fact]
    public async Task CountingStream_EveryWritePathCounts()
    {
        var inner = new MemoryStream();
        using (var counting = new CountingResponseBodyStream(inner))
        {
            counting.Write(new byte[] { 9, 9, 1, 2, 3 }, offset: 2, count: 3);
            Assert.Equal(3, counting.BytesWritten);

            counting.Write(new byte[] { 4, 5 }.AsSpan());
            Assert.Equal(5, counting.BytesWritten);

            await counting.WriteAsync(new byte[] { 6, 7, 8 }, 0, 3, CancellationToken.None);
            Assert.Equal(8, counting.BytesWritten);

            await counting.WriteAsync(new Memory<byte>(new byte[] { 9 }), CancellationToken.None);
            Assert.Equal(9, counting.BytesWritten);

            counting.WriteByte(0);
            Assert.Equal(10, counting.BytesWritten);

            await counting.FlushAsync();
            counting.Flush();
        }

        // The bytes passed through; the wrapper is not the inner stream's owner.
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 }, inner.ToArray());
    }

    [Fact]
    public async Task CountingStream_DisposeAndDisposeAsync_LeaveInnerOpen()
    {
        var inner = new ProbeStream();
        var counting = new CountingResponseBodyStream(inner);

        counting.Dispose();
        await counting.DisposeAsync();

        Assert.False(inner.Disposed);
        inner.WriteByte(7); // still usable by its real owner
    }

    private sealed class ProbeStream : MemoryStream
    {
        public bool Disposed { get; private set; }

        protected override void Dispose(bool disposing)
        {
            Disposed = true;
            base.Dispose(disposing);
        }
    }

    // ---- CredProxAuditOptions ----

    [Fact]
    public void SinkTimeout_MustBePositive()
    {
        var options = new CredProxAuditOptions { SinkTimeout = TimeSpan.FromSeconds(7) };
        Assert.Equal(TimeSpan.FromSeconds(7), options.SinkTimeout);

        var zero = Assert.Throws<ArgumentOutOfRangeException>(() => options.SinkTimeout = TimeSpan.Zero);
        Assert.Equal("value", zero.ParamName);
        Assert.Contains("The audit sink timeout must be positive.", zero.Message, StringComparison.Ordinal);

        Assert.Throws<ArgumentOutOfRangeException>(() => options.SinkTimeout = TimeSpan.FromMilliseconds(-1));
    }
}
