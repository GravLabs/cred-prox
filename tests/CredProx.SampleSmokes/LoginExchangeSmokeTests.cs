using Xunit;

namespace CredProx.SampleSmokes;

// The E12 LoginExchange smoke, cell by cell — the same three checks the sample's old
// --smoke made, unchanged in meaning, driven from outside the sample against the same
// stub. Each cell resets the stub's journal so the partition checks are independent;
// the old script got that for free from running its steps in order.
// Filter with --filter Sample=LoginExchange.
[Collection("LoginExchange")]
public sealed class LoginExchangeSmokeTests
{
    private readonly LoginExchangeFixture _stub;

    public LoginExchangeSmokeTests(LoginExchangeFixture stub) => _stub = stub;

    [Fact]
    [Trait("Sample", "LoginExchange")]
    public async Task UatPartition_AttachesItsOwnSession()
    {
        // The stub's echo of the Authorization header is scrubbed before
        // the caller sees it, so attachment is proven two ways: the caller's body carries
        // the redaction, the stub's journal carries the raw session — and only uat's.
        await _stub.ResetJournalAsync();

        var (status, body) = await _stub.GetTimeoffAsync("uat");
        var journal = await _stub.GetJournalAsync();

        Assert.Equal(200, status);
        Assert.Contains("Authorization = [redacted]", body, StringComparison.Ordinal);
        Assert.Contains("sess-uat-svc", journal, StringComparison.Ordinal);
        Assert.DoesNotContain("sess-staging-svc", journal, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Sample", "LoginExchange")]
    public async Task StagingPartition_RunsItsOwnLogin()
    {
        // A different partition, its own login, its own session.
        await _stub.ResetJournalAsync();

        var (status, body) = await _stub.GetTimeoffAsync("staging");
        var journal = await _stub.GetJournalAsync();

        Assert.Equal(200, status);
        Assert.Contains("Authorization = [redacted]", body, StringComparison.Ordinal);
        Assert.Contains("sess-staging-svc", journal, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Sample", "LoginExchange")]
    public async Task ProdPartition_IsBlockedBeforeAnyVendorCall()
    {
        // The Partition allow-list refuses prod before anything reaches the vendor:
        // the journal — the stub's own record — shows no prod login and no vendor
        // call. The 400 body then names the machine token.
        await _stub.ResetJournalAsync();

        var (status, body) = await _stub.GetTimeoffAsync("prod");
        var journal = await _stub.GetJournalAsync();

        Assert.DoesNotContain("/acme/prod/login", journal, StringComparison.Ordinal);
        Assert.DoesNotContain("/acme/api/v1/timeoff", journal, StringComparison.Ordinal);
        Assert.Equal(400, status);
        Assert.Contains("credprox.partition_not_allowed", body, StringComparison.Ordinal);
    }
}
