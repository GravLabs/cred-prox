using System.Text.Json;
using Xunit;

namespace CredProx.SampleSmokes;

// The E19 AgentTokens smoke, cell by cell — the same checks the sample's old --smoke
// argument ran, unchanged in meaning, driven from outside the sample against the same
// stubs. Filter with --filter Sample=AgentTokens.
[Collection("AgentTokens")]
public sealed class AgentTokensSmokeTests
{
    private readonly AgentTokensFixture _stub;

    public AgentTokensSmokeTests(AgentTokensFixture stub) => _stub = stub;

    [Fact]
    [Trait("Sample", "AgentTokens")]
    public async Task StubIssuer_AcceptsTheGeneratedPublicKey()
    {
        var response = await _stub.RegisterPublicKeyAsync();

        Assert.True(
            response.IsSuccessStatusCode,
            $"registering the generated public JWK with the stub issuer -> {(int)response.StatusCode}, want 2xx");
    }

    [Fact]
    [Trait("Sample", "AgentTokens")]
    public async Task StubIssuer_ServesTheGeneratedKey()
    {
        using var servedKeys = JsonDocument.Parse(await _stub.IssuerAdmin.GetStringAsync("/jwks"));
        var servedKid = servedKeys.RootElement.GetProperty("keys")[0].GetProperty("kid").GetString();

        Assert.Equal(AgentTokensFixture.GeneratedKid, servedKid);
    }

    [Fact]
    [Trait("Sample", "AgentTokens")]
    public async Task FreshToken_SingleStringRole_IsProxied()
    {
        // The one-element-claim shape some issuers emit; CredProx reads it the same.
        var token = _stub.Issue("demo-agent-client", "docs-read", _stub.Now, "tok-ok");

        Assert.Equal(200, await _stub.GetWithTokenAsync(token));
    }

    [Fact]
    [Trait("Sample", "AgentTokens")]
    public async Task FreshToken_RoleAsArray_IsProxied()
    {
        // The shape Entra writes; admits identically.
        var token = _stub.Issue("demo-agent-client", new[] { "docs-read" }, _stub.Now, "tok-array");

        Assert.Equal(200, await _stub.GetWithTokenAsync(token));
    }

    [Fact]
    [Trait("Sample", "AgentTokens")]
    public async Task MultiRoleArray_NamingTheRule_IsProxied()
    {
        // One role names the caller's rule; the extra role names nothing and adds nothing.
        var token = _stub.Issue("demo-agent-client", new[] { "billing-admin", "docs-read" }, _stub.Now, "tok-multi-ok");

        Assert.Equal(200, await _stub.GetWithTokenAsync(token));
    }

    [Fact]
    [Trait("Sample", "AgentTokens")]
    public async Task MultiRoleArray_NamingNoRule_IsRefused()
    {
        // A wider roles claim never widens what is admitted — it is still an intersection.
        var token = _stub.Issue("demo-agent-client", new[] { "billing-admin", "ops" }, _stub.Now, "tok-multi-deny");

        Assert.Equal(403, await _stub.GetWithTokenAsync(token));
    }

    [Fact]
    [Trait("Sample", "AgentTokens")]
    public async Task UnlistedRole_IsRefused()
    {
        // Valid caller, rule not in scope — the same refusal the allow-list gives a key caller.
        var token = _stub.Issue("demo-agent-client", "billing-admin", _stub.Now, "tok-role");

        Assert.Equal(403, await _stub.GetWithTokenAsync(token));
    }

    [Fact]
    [Trait("Sample", "AgentTokens")]
    public async Task MissingRolesClaim_IsRefused()
    {
        // No roles at all -> nothing intersects the named rule.
        var token = _stub.Issue("demo-agent-client", null, _stub.Now, "tok-norole");

        Assert.Equal(403, await _stub.GetWithTokenAsync(token));
    }

    [Fact]
    [Trait("Sample", "AgentTokens")]
    public async Task UnlistedClient_IsNotACaller()
    {
        // A validly signed token for an app nobody listed is not a caller.
        var token = _stub.Issue("rogue-client", "docs-read", _stub.Now, "tok-rogue");

        Assert.Equal(401, await _stub.GetWithTokenAsync(token));
    }

    [Fact]
    [Trait("Sample", "AgentTokens")]
    public async Task TokenOlderThanMaxTokenAge_IsRefused()
    {
        // Issued 2 h ago, still inside its own expiry, limit 15 min: revocation-by-staleness.
        var token = _stub.Issue("demo-agent-client", "docs-read", _stub.Now.AddHours(-2), "tok-stale");

        Assert.Equal(401, await _stub.GetWithTokenAsync(token));
    }

    [Fact]
    [Trait("Sample", "AgentTokens")]
    public async Task ForwardedRequest_CarriesNoAuthorization()
    {
        // Admit one request from THIS cell so the journal proof does not depend on cell
        // order, then read the upstream stub's journal.
        var token = _stub.Issue("demo-agent-client", "docs-read", _stub.Now, "tok-journal");
        Assert.Equal(200, await _stub.GetWithTokenAsync(token));

        using var journal = JsonDocument.Parse(
            await _stub.UpstreamAdmin.GetStringAsync("/__admin/requests"));
        var records = journal.RootElement.GetProperty("requests").EnumerateArray()
            .Where(r => r.GetProperty("request").GetProperty("url").GetString()?.StartsWith("/docs") == true)
            .ToList();
        var leaked = records.Any(r =>
            r.GetProperty("request").GetProperty("headers").TryGetProperty("Authorization", out _));

        Assert.True(records.Count > 0, "the upstream journal holds no /docs records");
        Assert.False(leaked, "the caller's bearer token reached the upstream");
    }
}
