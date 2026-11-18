using Xunit;

namespace CredProx.SampleSmokes;

// The E1 QuickStart smoke, cell by cell — the two checks the sample's old smoke script
// made against the WireMock stand-in, unchanged in meaning, driven from outside the
// sample. Filter with --filter Sample=QuickStart.
[Collection("QuickStart")]
public sealed class QuickStartSmokeTests
{
    private readonly QuickStartFixture _stub;

    public QuickStartSmokeTests(QuickStartFixture stub) => _stub = stub;

    [Fact]
    [Trait("Sample", "QuickStart")]
    public async Task CallerEcho_ShowsTheCredentialRedacted()
    {
        // The injected key is scrubbed from the echo body the caller
        // sees; the caller-side proof is the redaction, not the value.
        var (status, body) = await _stub.GetEchoAsync();

        Assert.Equal(200, status);
        Assert.Contains("redacted", body, StringComparison.Ordinal);
        Assert.DoesNotContain("demo-static-key", body, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Sample", "QuickStart")]
    public async Task StubJournal_SeesTheAttachedKey()
    {
        // The stub's own request journal proves the credential actually left the proxy —
        // the redaction above says nothing about what the upstream received.
        await _stub.GetEchoAsync();
        var journal = await _stub.GetJournalAsync();

        Assert.Contains("demo-static-key", journal, StringComparison.Ordinal);
    }
}
