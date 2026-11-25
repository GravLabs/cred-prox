using Azure.Core;
using Azure.Identity;
using Xunit;
using Xunit.Abstractions;

namespace CredProx.LiveTests;

// The M46 unit-3 proof against real Entra: the shipped AgentTokens sample, with
// only the overrides its README names (Authority, Audience, the configured
// TokenClientIds entry — plus the disclosed stand-in repoint for the placeholder
// docs.example.com destination), accepts a REAL Entra-issued app token for the
// run-registered API, maps it to the configured caller and forwards it; and
// refuses with 401 credprox.caller_unauthenticated a token for a client that
// carries the very same app role but is not configured. The refusal never
// reaches the stand-in upstream, so it is CredProx's own decision, not a vendor
// artifact. The three app registrations and both secrets belong to this run and
// are deleted again by the runner — never standing material.
[Collection("AgentTokens")]
[Trait("Layer", "Live")]
public sealed class AgentTokensLiveTests
{
    private readonly AgentTokensFixture _fixture;
    private readonly ITestOutputHelper _output;

    public AgentTokensLiveTests(AgentTokensFixture fixture, ITestOutputHelper output)
    {
        _fixture = fixture;
        _output = output;
    }

    [AgentTokensLiveFact]
    public async Task RealEntraTokens_MappedCallerPasses_UnconfiguredClientIsRefused()
    {
        var probe = AgentTokensEnv.Probe();
        Assert.True(probe.Available, probe.SkipReason);
        var shapeProblems = AgentTokensEnv.ValueProblems(probe.Values);
        Assert.True(shapeProblems.Count == 0, string.Join("; ", shapeProblems));
        var tenant = probe.Values["TENANT_ID"];

        var (mappedId, mappedSecret, unmappedId, unmappedSecret) = AgentTokensFixture.ReadScratchApps();
        // The audience is minted with the resource app (api://<its appId>), so
        // it arrives through the scratch handoff rather than a constant here.
        var audience = AgentTokensFixture.ReadScratchAudience();
        var secrets = new List<string> { mappedSecret, unmappedSecret };

        _fixture.StartStandIn();
        var env = new Dictionary<string, string>
        {
            ["CredProx__CallerToken__Authority"] =
                $"https://login.microsoftonline.com/{tenant}/v2.0",
            ["CredProx__CallerToken__Audience"] = audience,
            ["CredProx__Callers__doc-reader__TokenClientIds__0"] = mappedId,
            // disclosed deviation: the shipped destination is the docs.example.com
            // placeholder; the upstream is not the thing under proof, so it is
            // repointed to the loopback stand-in.
            ["CredProx__Destinations__upstream__Template"] = AgentTokensFixture.StandInUrl,
            ["ReverseProxy__Clusters__upstream__Destinations__upstream__Address"] =
                AgentTokensFixture.StandInUrl + "/",
        };
        var host = _fixture.StartHost(env, secrets);
        await _fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(AgentTokensFixture.LiveHostUrl) };

        // The stand-in counter is collection-wide (shared fixture): take where it
        // stands NOW so this cell asserts its own traffic, whatever ran before it.
        var docsBefore = _fixture.DocsRequestCount;

        // A real token, minted by the CONFIGURED client against the run-registered
        // API. If Entra refuses to mint or validate, this cell fails with the
        // sanitized error — no fallback path.
        var mappedToken = await MintTokenAsync(tenant, audience, mappedId, mappedSecret);
        using var mapped = await GetWithBearerAsync(client, "/docs/readme", mappedToken);
        var mappedBody = await mapped.Content.ReadAsStringAsync();
        var mappedStatus = (int)mapped.StatusCode;
        Assert.True(
            mappedStatus == 200,
            $"the mapped caller was not accepted with 200 but with {mappedStatus}; sanitized host output:\n" +
            SecretLeakScanner.Sanitize(host.Stdout + host.Stderr, secrets));
        Assert.Contains(AgentTokensFixture.StandInMarker, mappedBody, StringComparison.Ordinal);
        Assert.Equal(docsBefore + 1, _fixture.DocsRequestCount);
        // The sample's README: "The caller's bearer token never reaches the upstream:
        // CredProx strips Authorization". A real Entra token must not leave the proxy.
        Assert.False(_fixture.SawBearerToken, "the caller's bearer token reached the upstream stand-in");

        // The same role, the same tenant, an UNCONFIGURED client id: refused 401
        // as CredProx's own problem document — and the stand-in's counter did not
        // move, so the refusal happened before any upstream was touched.
        var unmappedToken = await MintTokenAsync(tenant, audience, unmappedId, unmappedSecret);
        using var unmapped = await GetWithBearerAsync(client, "/docs/readme", unmappedToken);
        var unmappedBody = await unmapped.Content.ReadAsStringAsync();
        var unmappedStatus = (int)unmapped.StatusCode;
        Assert.True(
            unmappedStatus == 401,
            $"the unconfigured client was not refused with 401 but with {unmappedStatus}; sanitized host output:\n" +
            SecretLeakScanner.Sanitize(host.Stdout + host.Stderr, secrets));
        Assert.Contains("problem+json", unmapped.Content.Headers.ContentType?.MediaType ?? "", StringComparison.Ordinal);
        Assert.Contains("credprox.caller_unauthenticated", unmappedBody, StringComparison.Ordinal);
        Assert.Equal(docsBefore + 1, _fixture.DocsRequestCount);

        // Nothing minted or loaded may appear in the visible output: the scanner
        // catches both the loaded secrets and any eyJ JWT shape.
        Assert.Empty(SecretLeakScanner.FindLeaks(host.Stdout + host.Stderr, secrets));
        Assert.Empty(SecretLeakScanner.FindLeaks(mappedBody + unmappedBody, secrets));

        // Numbers only — no ids, no tenant, no token — for the runner's PASS line.
        _output.WriteLine(
            $"OBSERVED agenttokens_mapped={mappedStatus} agenttokens_unmapped={unmappedStatus}");
    }

    private static async Task<string> MintTokenAsync(string tenant, string audience, string clientId, string secret)
    {
        var credential = new ClientSecretCredential(
            tenantId: tenant,
            clientId: clientId,
            clientSecret: secret);
        var context = new TokenRequestContext([$"{audience}/.default"]);
        try
        {
            var token = await credential.GetTokenAsync(context, CancellationToken.None);
            return token.Token;
        }
        catch (AuthenticationFailedException ex)
        {
            // The library's message names the client and the AADSTS reason, never
            // the secret; sanitize anyway — this text goes into a test failure.
            throw new InvalidOperationException(
                $"Entra refused to mint a token for a run-created client: {SecretLeakScanner.Sanitize(ex.Message, [secret])}",
                ex);
        }
    }

    private static async Task<HttpResponseMessage> GetWithBearerAsync(HttpClient client, string path, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + token);
        return await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, CancellationToken.None);
    }
}
