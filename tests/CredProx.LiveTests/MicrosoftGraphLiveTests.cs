using Xunit;
using Xunit.Abstractions;

namespace CredProx.LiveTests;

// The M46 unit-3 proof against real Entra and Microsoft Graph, run WITHOUT any
// admin consent (owner decision 2026-11-22): the shipped MicrosoftGraph sample
// host, with ONLY the overrides its README names (TokenEndpoint + ClientId +
// the secret via the CredProx secrets key for the OAuth style;
// ASPNETCORE_ENVIRONMENT alone for the secretless style), answers the
// client-credentials style with Graph's own 403 Authorization_RequestDenied —
// the run-created app holds no application permission, so that 403 is the
// proof that a real app-only token was issued, attached, and accepted by Graph
// as a token — and answers the CLI-identity style with a real 200. The OAuth
// client id and secret belong to an app registration this run created and will
// delete — never a standing secret; the TokenCredential style uses the
// machine's az CLI identity and stores nothing.
[Collection("MicrosoftGraph")]
[Trait("Layer", "Live")]
public sealed class MicrosoftGraphLiveTests
{
    private readonly MicrosoftGraphFixture _fixture;
    private readonly ITestOutputHelper _output;

    public MicrosoftGraphLiveTests(MicrosoftGraphFixture fixture, ITestOutputHelper output)
    {
        _fixture = fixture;
        _output = output;
    }

    [GraphLiveFact]
    public async Task Graph_ClientCredentialsAndCliIdentityBothReachGraph()
    {
        var probe = GraphEnv.Probe();
        Assert.True(probe.Available, probe.SkipReason);
        var shapeProblems = GraphEnv.ValueProblems(probe.Values);
        Assert.True(shapeProblems.Count == 0, string.Join("; ", shapeProblems));
        var tenant = probe.Values["TENANT_ID"];

        var (clientId, clientSecret) = MicrosoftGraphFixture.ReadScratchApp();
        var secrets = new List<string> { clientSecret };

        // Style A — Entra client credentials, app-only, and the run-created app
        // holds NO application permission: no grant, no consent (owner decision
        // 2026-11-22). The destination stays exactly as shipped:
        // graph.microsoft.com. The noun is /users?$top=1 because application
        // tokens carry no signed-in user for /me. What is proven here is the
        // token's journey: the tenant issued a real app-only token, CredProx
        // attached it, and Graph accepted it as a token and refused it for
        // holding no permission — Graph's own 403. The discriminator is strict:
        // a 401 (InvalidAuthenticationToken) means no valid token reached Graph,
        // and a CredProx problem document means the request never left; either
        // one fails the cell.
        var envA = new Dictionary<string, string>
        {
            ["ASPNETCORE_ENVIRONMENT"] = "OAuth",
            ["CredProx__Credentials__graph__TokenEndpoint"] =
                $"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
            ["CredProx__Credentials__graph__ClientId"] = clientId,
            ["CredProx__Secrets__graph-client-secret"] = clientSecret,
        };
        var hostA = _fixture.StartHost(envA, secrets);
        int usersStatus;
        string usersBody;
        string? graphRequestId;
        {
            await _fixture.WaitForHostAsync(hostA);
            using var client = new HttpClient { BaseAddress = new Uri(MicrosoftGraphFixture.LiveHostUrl) };
            var users = await client.GetAsync("/graph/v1.0/users?$top=1");
            usersBody = await users.Content.ReadAsStringAsync();
            usersStatus = (int)users.StatusCode;
            graphRequestId = users.Headers.TryGetValues("request-id", out var requestIds)
                ? string.Join(",", requestIds)
                : null;
            Assert.True(
                usersStatus == 403,
                $"the client-credentials users probe got {usersStatus}; the cell needs Graph's own 403 — " +
                "401 means no valid token reached Graph, and a CredProx refusal means the request never left; " +
                $"sanitized host output:\n" +
                SecretLeakScanner.Sanitize(hostA.Stdout + hostA.Stderr, secrets));
            // Graph answered, and CredProx normalised it (M24, live finding
            // 2026-11-22): a vendor 4xx comes back as credprox.vendor_error with the
            // status kept and Graph's own error embedded losslessly in
            // extensions.vendor_detail. Graph's error code there, plus Graph's
            // request-id header, is what makes the 403 attributable to Graph; any
            // other CredProx code means the request was refused before it left.
            // The parse goes through GraphEnv.ParseGraphProblem: an unparseable
            // body fails naming the expectation, never a JsonException dump, and
            // never echoing the body (09030a9 INFO). The path and the curation
            // are pinned offline - GraphProblemParseTests here and the shipped
            // normaliser's GraphShapedErrorBody cell in ErrorNormalisationFeatureTests.
            var (extensionsCode, vendorErrorCode) = GraphEnv.ParseGraphProblem(
                usersBody, usersStatus, "client-credentials users probe");
            Assert.Equal("credprox.vendor_error", extensionsCode);
            Assert.Equal("Authorization_RequestDenied", vendorErrorCode);
            Assert.False(
                string.IsNullOrEmpty(graphRequestId),
                $"the {usersStatus} carried no Graph request-id header — not a refusal answered by Graph itself");
            Assert.Empty(SecretLeakScanner.FindLeaks(hostA.Stdout + hostA.Stderr, secrets));
            Assert.Empty(SecretLeakScanner.FindLeaks(usersBody, secrets));
        }

        // Style B — TokenCredential, no stored secret: the host picks up the
        // az CLI identity through DefaultAzureCredential, delegated context, so
        // /me is the right noun here.
        var envB = new Dictionary<string, string> { ["ASPNETCORE_ENVIRONMENT"] = "ManagedIdentity" };
        var hostB = _fixture.StartHost(envB, secrets);
        int meStatus;
        {
            await _fixture.WaitForHostAsync(hostB);
            using var client = new HttpClient { BaseAddress = new Uri(MicrosoftGraphFixture.LiveHostUrl) };
            var me = await client.GetAsync("/graph/v1.0/me");
            meStatus = (int)me.StatusCode;
            Assert.True(
                meStatus == 200,
                $"Graph answered the CLI-identity /me probe with {meStatus}; sanitized host output:\n" +
                SecretLeakScanner.Sanitize(hostB.Stdout + hostB.Stderr, secrets));
            Assert.Empty(SecretLeakScanner.FindLeaks(hostB.Stdout + hostB.Stderr, secrets));
        }

        // Statuses and the Graph error code only — no ids, no tenant, no key
        // material, not even the request-id value — for the runner's PASS line.
        _output.WriteLine(
            $"OBSERVED graph_oauth={usersStatus}(Authorization_RequestDenied) graph_cli={meStatus}");
    }
}
