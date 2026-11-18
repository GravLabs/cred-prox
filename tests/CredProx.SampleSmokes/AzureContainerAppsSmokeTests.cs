using Xunit;

namespace CredProx.SampleSmokes;

// Offline cell for the AzureContainerApps sample: the gateway host on its bare shipped
// config (the config-secrets path) and the vendor stand-in behind the proxy. The Key
// Vault + managed identity path is the same stock provider the shipped MicrosoftGraph
// sample runs, proven live by the live-gate harness (tools/aca-live-harness).
[Collection("AzureContainerApps")]
public class AzureContainerAppsSmokeTests(AzureContainerAppsFixture fixture)
{
    [Fact]
    [Trait("Sample", "AzureContainerApps")]
    public async Task ConfigFedVendorKey_ReachesTheVendor_ScrubbedForTheCaller_AbsentFromTheConsole()
    {
        var host = fixture.StartHost();
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(AzureContainerAppsFixture.HostUrl) };
        using var request = new HttpRequestMessage(HttpMethod.Get, "/acme/thing");
        request.Headers.Add("X-API-Key", AzureContainerAppsFixture.CallerKey);
        using var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(200, (int)response.StatusCode);

        // The vendor received the configured key as a bearer header — the credential
        // placement is the proxy's, not the caller's.
        var seenByVendor = (await fixture.Stub.GetStringAsync("/__last-auth")).Trim();
        Assert.Equal("Bearer " + AzureContainerAppsFixture.DemoVendorKey, seenByVendor);

        // The caller sees the echo already redacted, and no credential value anywhere:
        // neither the vendor key nor the caller's own key.
        Assert.Contains("[redacted]", body);
        Assert.DoesNotContain(AzureContainerAppsFixture.DemoVendorKey, body);
        Assert.DoesNotContain(AzureContainerAppsFixture.CallerKey, body);

        // The host's own console carries no credential value either.
        Assert.DoesNotContain(AzureContainerAppsFixture.DemoVendorKey, host.Stdout + host.Stderr);
        Assert.DoesNotContain(AzureContainerAppsFixture.CallerKey, host.Stdout + host.Stderr);
    }
}
