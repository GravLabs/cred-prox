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
}
