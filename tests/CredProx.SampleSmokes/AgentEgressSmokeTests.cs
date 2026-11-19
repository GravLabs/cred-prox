using System.Text;
using Xunit;

namespace CredProx.SampleSmokes;

// Offline cells for the AgentEgress sample: the gateway host drives the full proxy path
// against the Salesforce stand-in — per-agent caller keys, the OAuth token exchange
// behind the allow-list boundary, one shared cached token across agents, session-token
// scrubbing in the vendor's echo, and audit per agent — exactly as it would against the
// real vendor.
[Collection("AgentEgress")]
public class AgentEgressSmokeTests(AgentEgressFixture fixture)
{
    [Fact]
    [Trait("Sample", "AgentEgress")]
    public async Task KeylessAndForgedCalls_AreRefusedAtTheGateway_NoTokenIsMinted()
    {
        var host = fixture.StartHost();
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(AgentEgressFixture.HostUrl) };
        var before = await fixture.IssuancesAsync();
        using var noKey = await client.GetAsync("/salesforce/services/data/v62.0/query?q=SELECT+1");
        using var forged = await client.SendAsync(KeyedRequest(
            "/salesforce/services/data/v62.0/query?q=SELECT+1", "not-a-real-key"));
        var after = await fixture.IssuancesAsync();

        Assert.Equal(401, (int)noKey.StatusCode);
        Assert.Equal(401, (int)forged.StatusCode);
        Assert.Equal(0, after - before); // refused at the gateway; no token exchange happened
    }

    [Fact]
    [Trait("Sample", "AgentEgress")]
    public async Task CrmAgentRead_ReachesTheVendor_WithTheSessionTokenRedacted()
    {
        var host = fixture.StartHost();
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(AgentEgressFixture.HostUrl) };
        var before = await fixture.IssuancesAsync();
        var response = await client.SendAsync(KeyedRequest(
            "/salesforce/services/data/v62.0/query?q=SELECT+Name+FROM+Account", AgentEgressFixture.CrmAgentKey));
        var body = await response.Content.ReadAsStringAsync();
        var after = await fixture.IssuancesAsync();

        // 200 means the stand-in validated the bearer the gateway minted from the client
        // secret; the agent sees neither the secret nor the token — the echo arrives as
        // Bearer [redacted].
        Assert.True(response.IsSuccessStatusCode,
            $"crm query failed: {(int)response.StatusCode} {body}\n{host.Stderr}");
        Assert.Contains("\"Name\":\"Acme\"", body, StringComparison.Ordinal);
        Assert.Contains("Bearer [redacted]", body, StringComparison.Ordinal);
        Assert.DoesNotContain(AgentEgressFixture.AccessToken, body, StringComparison.Ordinal);
        Assert.DoesNotContain(AgentEgressFixture.ClientSecret, body, StringComparison.Ordinal);
        Assert.Equal(1, after - before); // one proxied call, one issuance
    }

    [Fact]
    [Trait("Sample", "AgentEgress")]
    public async Task ToolBoundaries_RefuseOffListCalls_WhileBothAgentsShareOneCachedToken()
    {
        var host = fixture.StartHost();
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(AgentEgressFixture.HostUrl) };
        var before = await fixture.IssuancesAsync();

        // The allow-list is the tool surface: the CRM agent may not open cases...
        using var blockedWrite = await client.PostAsync(
            "/salesforce/services/data/v62.0/sobjects/Case", KeyedJson("{}", AgentEgressFixture.CrmAgentKey));
        var blockedBody = await blockedWrite.Content.ReadAsStringAsync();
        Assert.Equal(403, (int)blockedWrite.StatusCode);
        Assert.Contains("credprox.operation_not_allowed", blockedBody, StringComparison.Ordinal);

        // ...and the support agent may not read — but it may open a case.
        using var blockedRead = await client.SendAsync(KeyedRequest(
            "/salesforce/services/data/v62.0/query?q=SELECT+1", AgentEgressFixture.SupportAgentKey));
        Assert.Equal(403, (int)blockedRead.StatusCode);

        var create = await client.PostAsync(
            "/salesforce/services/data/v62.0/sobjects/Case",
            KeyedJson("""{"Subject":"Printer on fire"}""", AgentEgressFixture.SupportAgentKey));
        var createBody = await create.Content.ReadAsStringAsync();
        var after = await fixture.IssuancesAsync();

        Assert.True(create.IsSuccessStatusCode,
            $"support create failed: {(int)create.StatusCode} {createBody}\n{host.Stderr}");
        Assert.Contains("\"500xx00000A1b23AAB\"", createBody, StringComparison.Ordinal);
        Assert.Contains("Bearer [redacted]", createBody, StringComparison.Ordinal);
        Assert.DoesNotContain(AgentEgressFixture.AccessToken, createBody, StringComparison.Ordinal);

        // Two agents, one credential: still exactly one issuance between them.
        Assert.Equal(1, after - before);
    }

    [Fact]
    [Trait("Sample", "AgentEgress")]
    public async Task Audit_RecordsCallsPerAgent_NoCredentialValueAnywhere()
    {
        var host = fixture.StartHost();
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(AgentEgressFixture.HostUrl) };
        using var crmRead = await client.SendAsync(KeyedRequest(
            "/salesforce/services/data/v62.0/query?q=SELECT+1", AgentEgressFixture.CrmAgentKey));
        using var crmWrite = await client.PostAsync(
            "/salesforce/services/data/v62.0/sobjects/Case", KeyedJson("{}", AgentEgressFixture.CrmAgentKey));
        using var supportRead = await client.SendAsync(KeyedRequest(
            "/salesforce/services/data/v62.0/query?q=SELECT+1", AgentEgressFixture.SupportAgentKey));
        using var supportWrite = await client.PostAsync(
            "/salesforce/services/data/v62.0/sobjects/Case",
            KeyedJson("""{"Subject":"Printer on fire"}""", AgentEgressFixture.SupportAgentKey));
        Assert.True(
            crmRead.IsSuccessStatusCode && (int)crmWrite.StatusCode == 403
            && (int)supportRead.StatusCode == 403 && supportWrite.IsSuccessStatusCode,
            $"setup calls failed: crmRead={(int)crmRead.StatusCode} crmWrite={(int)crmWrite.StatusCode} supportRead={(int)supportRead.StatusCode} supportWrite={(int)supportWrite.StatusCode}\n{host.Stderr}");

        // Audit records land on the gateway's console (Information under CredProx.Audit).
        // Each audit line is written when its own response completes, so the two
        // support-agent lines (rejected read, proxied write) reach stdout in arbitrary
        // order: waiting for the first caller=support-agent line can pass while the
        // proxied one is still in flight, and the assert below then races it. Wait until
        // all four asserted lines are present, using the asserts' own predicates.
        static bool HasAuditLine(string stdout, string evt, string caller) =>
            stdout.Split('\n').Any(l => l.Contains(evt, StringComparison.Ordinal)
                && l.Contains(caller, StringComparison.Ordinal));
        await AgentEgressFixture.WaitUntilAsync(
            () => Task.FromResult(
                HasAuditLine(host.Stdout, "credprox.proxied_call", "caller=crm-agent")
                && HasAuditLine(host.Stdout, "credprox.proxied_call", "caller=support-agent")
                && HasAuditLine(host.Stdout, "credprox.rejected_call", "caller=crm-agent")
                && HasAuditLine(host.Stdout, "credprox.rejected_call", "caller=support-agent")),
            $"expected audit lines never all appeared:\n{host.Stdout}");
        var lines = host.Stdout.Split('\n');
        Assert.Contains(lines, l => l.Contains("credprox.proxied_call", StringComparison.Ordinal)
            && l.Contains("caller=crm-agent", StringComparison.Ordinal));
        Assert.Contains(lines, l => l.Contains("credprox.proxied_call", StringComparison.Ordinal)
            && l.Contains("caller=support-agent", StringComparison.Ordinal));
        Assert.Contains(lines, l => l.Contains("credprox.rejected_call", StringComparison.Ordinal)
            && l.Contains("caller=crm-agent", StringComparison.Ordinal));
        Assert.Contains(lines, l => l.Contains("credprox.rejected_call", StringComparison.Ordinal)
            && l.Contains("caller=support-agent", StringComparison.Ordinal));

        // "Never a credential" is proven, not assumed: no agent key, no client secret
        // and no session token in anything the host printed.
        var output = host.Stdout + host.Stderr;
        Assert.DoesNotContain(AgentEgressFixture.ClientSecret, output, StringComparison.Ordinal);
        Assert.DoesNotContain(AgentEgressFixture.AccessToken, output, StringComparison.Ordinal);
        Assert.DoesNotContain(AgentEgressFixture.CrmAgentKey, output, StringComparison.Ordinal);
        Assert.DoesNotContain(AgentEgressFixture.SupportAgentKey, output, StringComparison.Ordinal);
    }

    private static StringContent KeyedJson(string json, string agentKey)
    {
        var content = new StringContent(json, Encoding.UTF8, "application/json");
        content.Headers.Add("X-CredProx-Key", agentKey);
        return content;
    }

    private static HttpRequestMessage KeyedRequest(string path, string agentKey)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Add("X-CredProx-Key", agentKey);
        return request;
    }
}
