using Xunit;

namespace CredProx.SampleSmokes;

// The E18 CallerApiKey smoke, cell by cell — the same checks the sample's old --smoke
// made, unchanged in meaning, driven from outside the sample against the same stub.
// Filter with --filter Sample=CallerApiKey.
[Collection("CallerApiKey")]
public sealed class CallerApiKeySmokeTests
{
    private readonly CallerApiKeyFixture _stub;

    public CallerApiKeySmokeTests(CallerApiKeyFixture stub) => _stub = stub;

    [Fact]
    [Trait("Sample", "CallerApiKey")]
    public async Task MissingKey_IsRefused()
    {
        var (status, _) = await _stub.GetDataAsync(key: null);

        Assert.Equal(401, status);
    }

    [Fact]
    [Trait("Sample", "CallerApiKey")]
    public async Task WrongKey_GetsTheSameRefusal_AndNothingAboutItIsEchoed()
    {
        var (status, body) = await _stub.GetDataAsync(CallerApiKeyFixture.WrongKey);

        Assert.Equal(401, status);
        Assert.DoesNotContain(CallerApiKeyFixture.WrongKey, body, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Sample", "CallerApiKey")]
    public async Task AcceptedKey_IsProxied()
    {
        var (status, _) = await _stub.GetDataAsync(CallerApiKeyFixture.GoodKey);

        Assert.Equal(200, status);
    }

    [Fact]
    [Trait("Sample", "CallerApiKey")]
    public async Task KeyHeader_NeverReachesTheUpstream()
    {
        // The stub's own record: every request that arrived at /api/data carried neither
        // the caller's X-API-Key nor the default X-CredProx-Key header.
        await _stub.ResetJournalAsync();
        var (status, _) = await _stub.GetDataAsync(CallerApiKeyFixture.GoodKey);
        Assert.Equal(200, status);

        var headers = await _stub.HeadersAtDataAsync();

        Assert.NotEmpty(headers);
        Assert.All(headers, names =>
        {
            Assert.DoesNotContain("X-API-Key", names);
            Assert.DoesNotContain("X-CredProx-Key", names);
        });
    }
}
