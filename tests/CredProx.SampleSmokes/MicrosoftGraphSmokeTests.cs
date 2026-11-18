using Xunit;

namespace CredProx.SampleSmokes;

// Offline cells for the MicrosoftGraph sample. The secretless (managed-identity) style
// cannot be driven offline — Azure Identity refuses any authority that is not a real
// cloud endpoint — so the cells cover the client-secret style end to end against the
// WireMock stand-ins, plus the startup refusals that tell an operator what to fix.
[Collection("MicrosoftGraph")]
public class MicrosoftGraphSmokeTests(MicrosoftGraphFixture fixture)
{
    [Fact]
    [Trait("Sample", "MicrosoftGraph")]
    public async Task ClientSecretStyle_WithPlaceholders_RefusesNamingEveryMissingValue()
    {
        var host = fixture.StartHost("OAuth");

        Assert.True(await fixture.ExitedWithinAsync(host, 30),
            $"the placeholder run should refuse to start; stderr:\n{host.Stderr}");
        Assert.Equal(1, host.Process.ExitCode);
        Assert.Contains("CredProx__Credentials__graph__TokenEndpoint (replace <tenant-id>)", host.Stderr);
        Assert.Contains("CredProx__Credentials__graph__ClientId", host.Stderr);
        Assert.Contains("CredProx__Secrets__graph-client-secret", host.Stderr);
        Assert.Contains("README.md", host.Stderr);
        Assert.Contains("ASPNETCORE_ENVIRONMENT=ManagedIdentity", host.Stderr);
    }

    [Fact]
    [Trait("Sample", "MicrosoftGraph")]
    public async Task NoStyleSelected_RefusesWithTheSameGuidance()
    {
        var host = fixture.StartHost(environment: null);

        Assert.True(await fixture.ExitedWithinAsync(host, 30),
            $"the default run (no style file) should refuse to start; stderr:\n{host.Stderr}");
        Assert.Equal(1, host.Process.ExitCode);
        Assert.Contains("missing required values", host.Stderr);
        Assert.Contains("ASPNETCORE_ENVIRONMENT=ManagedIdentity", host.Stderr);
    }

    [Fact]
    [Trait("Sample", "MicrosoftGraph")]
    public async Task ClientSecretStyle_EndToEnd_RealTokenAtVendor_ScrubbedEcho_CachedToken()
    {
        var host = fixture.StartHost("OAuth", MicrosoftGraphFixture.StubOverrides());
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(MicrosoftGraphFixture.HostUrl) };
        using var first = await client.GetAsync("/graph/v1.0/me");
        Assert.Equal(200, (int)first.StatusCode);

        // The echo stub renders the Authorization header the vendor received; CredProx
        // scrubs its own token secret out of the bytes flowing back to the caller, so
        // the caller sees the masked form while the vendor's journal holds the truth.
        var body = await first.Content.ReadAsStringAsync();
        Assert.Contains("graph saw: Bearer [redacted]", body);

        using var second = await client.GetAsync("/graph/v1.0/users");
        Assert.Equal(200, (int)second.StatusCode);

        var journal = await fixture.Vendor.GetStringAsync("/__admin/requests");
        Assert.Contains("Bearer mg-stub-token", journal);

        // Two graph calls, one token call: the cache served the second request.
        Assert.Equal(1, await fixture.TokenEndpointCallsAsync());
    }
}
