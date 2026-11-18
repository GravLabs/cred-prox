using Xunit;

namespace CredProx.SampleSmokes;

// Offline cells for the GitHub App sample: the stand-in verifies the minted app JWT with
// an independent implementation (RS256 plus iss/aud/exp/jti), exactly as GitHub's
// verifier does, so an "ok" witness means the whole JwtAssertion BearerExchange flow
// worked — mint, exchange, cache, attach. The refused cells cover the two ways the flow
// can be broken by configuration: no signing key, or a key the vendor rejects.
[Collection("GitHubApp")]
public class GitHubAppSmokeTests(GitHubAppFixture fixture)
{
    [Fact]
    [Trait("Sample", "GitHubApp")]
    public async Task ExchangedInstallationToken_ReachesTheVendorRaw()
    {
        var host = fixture.StartHost();
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(GitHubAppFixture.HostUrl) };
        var body = await client.GetStringAsync("/github/exact");

        // "ok" means the stand-in verified the app JWT AND saw the bearer-prefixed
        // installation token byte-exactly on the API call.
        Assert.Equal("ok", body);
    }

    [Fact]
    [Trait("Sample", "GitHubApp")]
    public async Task ReflectedInstallationToken_IsScrubbedCallerSide()
    {
        var host = fixture.StartHost();
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(GitHubAppFixture.HostUrl) };
        var response = await client.GetAsync("/github/repos/octocat/hello-world");
        var body = await response.Content.ReadAsStringAsync();

        Assert.True(response.IsSuccessStatusCode, $"echo failed: {(int)response.StatusCode} {body}\n{host.Stderr}");
        Assert.DoesNotContain(GitHubAppFixture.InstallationToken, body, StringComparison.Ordinal);
        Assert.Contains("Bearer [redacted]", body, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Sample", "GitHubApp")]
    public async Task InstallationToken_IsCachedAcrossRequests()
    {
        var host = fixture.StartHost();
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(GitHubAppFixture.HostUrl) };
        var before = await fixture.TokenEndpointCallsAsync();
        using var first = await client.GetAsync("/github/repos/octocat/hello-world");
        using var second = await client.GetAsync("/github/repos/octocat/hello-world");
        var after = await fixture.TokenEndpointCallsAsync();

        Assert.True(first.IsSuccessStatusCode && second.IsSuccessStatusCode);
        Assert.Equal(1, after - before); // the app JWT is re-minted only at the exchange, the token is cached
    }

    [Fact]
    [Trait("Sample", "GitHubApp")]
    public async Task EmptySigningKey_RefusedWithAStaticProblem_NoValuesLeak()
    {
        // The bare shipped host: the secret reference resolves to the committed empty
        // value, so startup passes and every request answers the credential problem.
        var host = fixture.StartHost(withSigningKey: false);
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(GitHubAppFixture.HostUrl) };
        var response = await client.GetAsync("/github/repos/octocat/hello-world");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(502, (int)response.StatusCode);
        Assert.Contains("credprox.credential_unavailable", body, StringComparison.Ordinal);
        var output = host.Stdout + host.Stderr;
        Assert.DoesNotContain(GitHubAppFixture.InstallationToken, output, StringComparison.Ordinal);
        Assert.DoesNotContain("PRIVATE KEY", output, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Sample", "GitHubApp")]
    public async Task WrongSigningKey_VendorStandInRefusesTheExchange()
    {
        // A key the app never registered: the stand-in rejects the JWT (as GitHub would,
        // with 401 on the token endpoint), and the caller gets the static credential
        // problem — never the vendor's error body, never the key.
        var host = fixture.StartHost(new Dictionary<string, string>
        {
            ["CredProx__Secrets__github-app-signing-key"] = fixture.OtherSigningKeyPem,
        });
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(GitHubAppFixture.HostUrl) };
        var response = await client.GetAsync("/github/repos/octocat/hello-world");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(502, (int)response.StatusCode);
        Assert.Contains("credprox.credential_unavailable", body, StringComparison.Ordinal);
        var output = host.Stdout + host.Stderr;
        Assert.DoesNotContain("PRIVATE KEY", output, StringComparison.Ordinal);
    }
}
