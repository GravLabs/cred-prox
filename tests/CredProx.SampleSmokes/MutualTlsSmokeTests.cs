using Xunit;

namespace CredProx.SampleSmokes;

// The E3 MutualTls smoke, cell by cell — the same check the sample's old --smoke made,
// unchanged in meaning, driven from outside the sample against the same nginx.
// Filter with --filter Sample=MutualTls.
[Collection("MutualTls")]
public sealed class MutualTlsSmokeTests
{
    private readonly MutualTlsFixture _stub;

    public MutualTlsSmokeTests(MutualTlsFixture stub) => _stub = stub;

    [Fact]
    [Trait("Sample", "MutualTls")]
    public async Task Nginx_EchoesTheClientCertificateSubject()
    {
        // nginx requires a client certificate and echoes its subject: seeing the client
        // the sample generated proves the mTLS connection carried the key-per-file secret.
        var (status, body) = await _stub.GetRootAsync();

        Assert.Equal(200, status);
        Assert.Contains(MutualTlsFixture.ClientSubject, body, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Sample", "MutualTls")]
    public async Task ConnectionWithoutClientCert_IsRefused()
    {
        // The negative witness that keeps the echo cell from being vacuous: nginx
        // answers 400 to a TLS connection carrying no client certificate, so the
        // 200 above is granted only to a connection that presented the key-per-file
        // material — not because the listener admits anyone.
        Assert.Equal(400, await _stub.GetNginxWithoutClientCertAsync());
    }
}
