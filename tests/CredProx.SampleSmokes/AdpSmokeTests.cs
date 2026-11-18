using System.Text.Json;
using Xunit;

namespace CredProx.SampleSmokes;

// Offline cells for the ADP sample: the original certificate arrangement (one named mTLS
// connection on the token call AND the API calls, nginx enforcing it), the bearer attach +
// caller-side scrub, the measured wire shape, the certificateless refusal, the offline
// Key Vault rotation witness, and the two production-switch guards.
[Collection("ADP")]
public class AdpSmokeTests(AdpFixture fixture)
{
    [Fact]
    [Trait("Sample", "ADP")]
    public async Task ApiHop_CertificateSeen_BearerAttached_ScrubbedCallerSide()
    {
        using var host = fixture.StartHost(environment: null, certificatesPresent: true);
        await fixture.WaitForHostAsync(host);
        await fixture.ResetJournalAsync();

        using var client = new HttpClient { BaseAddress = new Uri(AdpFixture.HostUrl) };
        using var response = await client.GetAsync("/adp/api/v1/employees");
        Assert.Equal(200, (int)response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();

        // nginx injected the verified subject; the stub echoes it and the Authorization
        // header — CredProx scrubs the token out of the bytes returning to the caller.
        Assert.Contains("client = CN=client-alpha", body);
        Assert.Contains("Bearer [redacted]", body);

        var journal = await fixture.JournalAsync();
        Assert.Contains("Bearer adp-demo-token", journal);
    }

    [Fact]
    [Trait("Sample", "ADP")]
    public async Task WireShape_TokenCall_MatchesCommittedEvidence()
    {
        using var host = fixture.StartHost(environment: null, certificatesPresent: true);
        // Clear the journal BEFORE the first request so the token call of THIS host (its
        // cache is fresh) is inside the journal the comparison reads.
        await fixture.ResetJournalAsync();
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(AdpFixture.HostUrl) };
        using var response = await client.GetAsync("/adp/api/v1/employees");
        Assert.Equal(200, (int)response.StatusCode);

        // The original vendor sent POST with an empty body, the grant in the query string,
        // and Basic client auth. The pinned evidence is the committed wire-check.txt —
        // rebuilt here from the stub's own journal of THIS run and compared.
        var (url, bodyText, basic) = ReadTokenRecord(await fixture.JournalAsync());
        var recorded =
            $"token request url : {url}\n" +
            $"token request body: {bodyText}\n" +
            $"Basic client auth : {basic}\n";
        var committed = await File.ReadAllTextAsync(Path.Combine(fixture.SampleDir, "wire-check.txt"));
        Assert.StartsWith(recorded, committed, StringComparison.Ordinal);
        Assert.Equal("/auth/oauth/v2/token?grant_type=client_credentials", url);
        Assert.True(basic);
        Assert.Contains("grant_type=client_credentials", bodyText);
    }

    [Fact]
    [Trait("Sample", "ADP")]
    public async Task NginxLog_NamesTheClientCertificateOnBothHops()
    {
        using var host = fixture.StartHost(environment: null, certificatesPresent: true);
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(AdpFixture.HostUrl) };
        using var response = await client.GetAsync("/adp/api/v1/employees");
        Assert.Equal(200, (int)response.StatusCode);

        var log = await fixture.NginxLogAsync();
        Assert.Contains("CN=client-alpha | POST /auth/oauth/v2/token?grant_type=client_credentials", log);
        Assert.Contains("CN=client-alpha | GET /api/v1/employees", log);
    }

    [Fact]
    [Trait("Sample", "ADP")]
    public async Task Nginx_RefusesTheCertificatelessRequestAtTheTlsLayer()
    {
        Assert.Equal(400, await fixture.NginxCertificatelessCodeAsync());
    }

    [Fact]
    [Trait("Sample", "ADP")]
    public async Task CertificatelessStartup_RefusesCleanly_WithoutKeyMaterial()
    {
        // Content root without secrets.d: the eager certificate load must fail, name the
        // secret, and print no key material anywhere.
        using var host = fixture.StartHost(environment: null, certificatesPresent: false);

        Assert.True(await fixture.ExitedWithinAsync(host, 60),
            "the certificateless host should refuse to start");
        Assert.NotEqual(0, host.Process.ExitCode);
        var output = host.Stdout + host.Stderr;
        Assert.Contains("adpClientCert", output, StringComparison.OrdinalIgnoreCase);
        var secretHead = fixture.ReadBundle("CredProx__Secrets__adpClientCert")[..40];
        Assert.DoesNotContain("BEGIN", output, StringComparison.Ordinal);
        Assert.DoesNotContain("MII", output, StringComparison.Ordinal);
        Assert.DoesNotContain(secretHead, output, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Sample", "ADP")]
    public async Task KeyVaultStyle_OfflineRotation_ReachesNewConnectionsWithoutRestart()
    {
        await fixture.InstallKvSecretAsync(fixture.ReadBundle("CredProx__Secrets__adpClientCert"));
        using var host = fixture.StartHost("KeyVaultOffline", certificatesPresent: true);

        using var client = new HttpClient { BaseAddress = new Uri(AdpFixture.HostUrl) };
        var sawAlpha = false;
        var last = string.Empty;
        // The provider polls on its explicit 2 s ReloadInterval; the rotation-aware
        // connection registry presents the new certificate on new connections (nginx
        // keeps no idle connections, so every request re-handshakes).
        for (var attempt = 0; attempt < 90 && !(sawAlpha && last.Contains("client = CN=client-beta")); attempt++)
        {
            if (attempt == 30)
            {
                await fixture.InstallKvSecretAsync(fixture.ReadBundle("CredProx__Secrets__adpClientCert-beta"));
            }

            try
            {
                using var response = await client.GetAsync("/adp/api/v1/employees");
                last = await response.Content.ReadAsStringAsync();
            }
            catch (HttpRequestException)
            {
                // warming
            }

            if (last.Contains("client = CN=client-alpha"))
            {
                sawAlpha = true;
            }

            await Task.Delay(1000);
        }

        Assert.True(sawAlpha, $"the alpha certificate never reached a connection; last: {last}");
        Assert.Contains("client = CN=client-beta", last);
    }

    [Fact]
    [Trait("Sample", "ADP")]
    public async Task RealAdpStyle_ExportedValuesReachTheHost()
    {
        var overrides = new Dictionary<string, string>
        {
            ["CredProx__Credentials__adp__ClientId"] = "guard-client",
            ["CredProx__Secrets__adpClientSecret"] = "guard-secret",
            ["CredProx__Secrets__adpClientCert"] = fixture.ReadBundle("CredProx__Secrets__adpClientCert"),
        };
        using var host = fixture.StartHost("RealAdp", certificatesPresent: true, overrides);
        await fixture.WaitForHostAsync(host);

        // A committed placeholder shadowing an exported value was the failure this guard
        // existed for: the host starts listening and never complains about ClientId.
        Assert.Contains("Now listening on", host.Stdout, StringComparison.Ordinal);
        Assert.DoesNotContain("ClientId is required", host.Stdout + host.Stderr, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Sample", "ADP")]
    public async Task KeyVaultStyle_WithoutUri_FailsFastNamingTheSetting()
    {
        using var host = fixture.StartHost(
            "KeyVault",
            certificatesPresent: true,
            clear:
            [
                "CredProx__Credentials__adp__ClientId",
                "CredProx__Secrets__adpClientSecret",
                "CredProx__Secrets__adpClientCert",
                "KeyVault__Uri",
            ]);

        Assert.True(await fixture.ExitedWithinAsync(host, 60),
            "the Key Vault style without an endpoint should refuse to start");
        Assert.NotEqual(0, host.Process.ExitCode);
        Assert.Contains("KeyVault:Uri", host.Stdout + host.Stderr, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Sample", "ADP")]
    public async Task KeyVaultStyle_WithUri_DialsThatEndpoint()
    {
        // Proves the provider is engaged for this style: the failure must name the
        // exported (unresolvable) vault host, never a silent skip into an unresolved
        // secret: reference.
        var overrides = new Dictionary<string, string>
        {
            ["KeyVault__Uri"] = "https://credprox-guard.invalid/",
            ["CredProx__Credentials__adp__ClientId"] = "guard-client",
            ["CredProx__Secrets__adpClientSecret"] = "guard-secret",
        };
        using var host = fixture.StartHost(
            "KeyVault", certificatesPresent: true, overrides,
            clear: ["CredProx__Secrets__adpClientCert"]);

        Assert.True(await fixture.ExitedWithinAsync(host, 150),
            "the Key Vault style against an unresolvable vault should fail, not serve");
        Assert.NotEqual(0, host.Process.ExitCode);
        Assert.Contains("credprox-guard.invalid", host.Stdout + host.Stderr, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Sample", "ADP")]
    public async Task Route_IsGetOnly_PostRefused_GetProxied()
    {
        using var host = fixture.StartHost(environment: null, certificatesPresent: true);
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(AdpFixture.HostUrl) };
        using var post = await client.PostAsync("/adp/api/v1/employees", content: null);
        // Today's measured YARP behavior for a method-mismatched route is 404; 405 would
        // also be a refusal. The refusal form is YARP's choice, not this sample's.
        Assert.True((int)post.StatusCode is 404 or 405, $"POST got {(int)post.StatusCode}");

        using var get = await client.GetAsync("/adp/api/v1/employees");
        Assert.Equal(200, (int)get.StatusCode);
    }

    private static (string Url, string Body, bool Basic) ReadTokenRecord(string journalJson)
    {
        var journal = JsonDocument.Parse(journalJson);
        foreach (var record in journal.RootElement.GetProperty("requests").EnumerateArray())
        {
            var request = record.GetProperty("request");
            if (request.GetProperty("url").GetString()
                != "/auth/oauth/v2/token?grant_type=client_credentials")
            {
                continue;
            }

            var body = request.TryGetProperty("body", out var b) ? b.GetString() ?? "" : "";
            var basic = request.GetProperty("headers")
                .TryGetProperty("Authorization", out var auth)
                && (auth.GetString() ?? "").StartsWith("Basic ", StringComparison.Ordinal);
            return (request.GetProperty("url").GetString()!, body, basic);
        }

        return ("<none>", "<none>", false);
    }
}
