using Xunit;

namespace CredProx.SampleSmokes;

// Offline cells for the CustomPlugin sample: the plugin host drives the full proxy path
// against the vendor stand-in — login, cached session id, custom header attach — exactly
// as a built-in credential would, and the conformance suite the plugin ships runs here
// as a cell: the same facts `dotnet test` runs in a plugin author's own project.
[Collection("CustomPlugin")]
public class CustomPluginSmokeTests(CustomPluginFixture fixture)
{
    [Fact]
    [Trait("Sample", "CustomPlugin")]
    public async Task PluginMintedSessionId_ReachesTheVendorExact()
    {
        var host = fixture.StartHost();
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(CustomPluginFixture.HostUrl) };
        var body = await client.GetStringAsync("/vendor/exact");

        // "ok" means the vendor login succeeded and the session id arrived on the API
        // call byte-exactly in the plugin's own header.
        Assert.Equal("ok", body);
    }

    [Fact]
    [Trait("Sample", "CustomPlugin")]
    public async Task ReflectedSessionId_IsScrubbedCallerSide()
    {
        var host = fixture.StartHost();
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(CustomPluginFixture.HostUrl) };
        var response = await client.GetAsync("/vendor/echo");
        var body = await response.Content.ReadAsStringAsync();

        Assert.True(response.IsSuccessStatusCode, $"echo failed: {(int)response.StatusCode} {body}\n{host.Stderr}");
        Assert.DoesNotContain(CustomPluginFixture.SessionId, body, StringComparison.Ordinal);
        Assert.Contains("[redacted]", body, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Sample", "CustomPlugin")]
    public async Task SessionId_IsCachedAcrossRequests()
    {
        var host = fixture.StartHost();
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(CustomPluginFixture.HostUrl) };
        var before = await fixture.LoginCallsAsync();
        using var first = await client.GetAsync("/vendor/echo");
        using var second = await client.GetAsync("/vendor/echo");
        var after = await fixture.LoginCallsAsync();

        Assert.True(first.IsSuccessStatusCode && second.IsSuccessStatusCode);
        Assert.Equal(1, after - before); // the core's caching serves the plugin: one login, many calls
    }

    [Fact]
    [Trait("Sample", "CustomPlugin")]
    public async Task WrongSecret_RefusedWithAStaticProblem_NoValuesLeak()
    {
        var host = fixture.StartHost(new Dictionary<string, string>
        {
            ["CredProx__Secrets__vendor-secret"] = "not-the-vendor-secret",
        });
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(CustomPluginFixture.HostUrl) };
        var response = await client.GetAsync("/vendor/echo");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(502, (int)response.StatusCode);
        Assert.Contains("credprox.credential_unavailable", body, StringComparison.Ordinal);
        var output = host.Stdout + host.Stderr;
        Assert.DoesNotContain(CustomPluginFixture.SessionId, output, StringComparison.Ordinal);
        Assert.DoesNotContain(CustomPluginFixture.VendorSecret, output, StringComparison.Ordinal);
        Assert.DoesNotContain("not-the-vendor-secret", output, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Sample", "CustomPlugin")]
    public async Task Plugin_PassesTheCredProxTestingConformanceSuite()
    {
        // The same facts a plugin author's `dotnet test` runs: acquire success,
        // single-flight, refresh-after-invalidate, per-partition isolation, value-free
        // logs, failure hygiene — plus the sample's own consent-signal fact.
        var (total, failures) = await CustomPluginFixture.RunConformanceSuiteAsync();

        Assert.True(total >= 7, $"expected the built-in suite facts plus the consent fact, found {total}");
        Assert.Empty(failures);
    }
}
