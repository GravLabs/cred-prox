using Xunit;

namespace CredProx.SampleSmokes;

// The E9 HmacSigning smoke, cell by cell — the same checks the sample's old --smoke
// made, unchanged in meaning, driven from outside the host over real sockets.
// Filter with --filter Sample=HmacSigning.
[Collection("HmacSigning")]
public sealed class HmacSigningSmokeTests
{
    private readonly HmacSigningFixture _host;

    public HmacSigningSmokeTests(HmacSigningFixture host) => _host = host;

    [Fact]
    [Trait("Sample", "HmacSigning")]
    public async Task SignedPost_IndependentVerifierAccepts()
    {
        // The config-driven canonical recipe must match an independent verifier of the
        // documented layout: method, path, unix seconds, sha256-hex(body), HMAC-SHA256.
        var (status, body) = await _host.PostSignedAsync("/api/verify", "{\"order\":42}");

        Assert.Equal(200, status);
        Assert.Contains("signature valid", body, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Sample", "HmacSigning")]
    public async Task BodyOverCap_413BeforeForwarding()
    {
        // The signer-small credential's MaxBodyBytes is 16; a 100-byte body is refused
        // with the documented code before anything is forwarded.
        var (status, body) = await _host.PostSignedAsync("/small/verify", new string('x', 100));

        Assert.Equal(413, status);
        Assert.Contains("credprox.body_too_large_to_sign", body, StringComparison.Ordinal);
    }
}
