using System.Text;
using System.Text.Json;
using Azure.Core;
using Azure.Identity;
using Xunit;
using Xunit.Abstractions;

namespace CredProx.LiveTests;

// The foundrylocal proof against real Entra on a free local model: the shipped
// FoundryLocalAgent gate, with only the overrides its README names (Authority,
// Audience, the configured TokenClientIds entry — plus the disclosed stand-in
// repoint for the tool placeholder, while the model hop stays the real loopback
// Foundry Local server), accepts a REAL Entra-issued app token for the
// run-registered API: the mapped caller reaches the local model through the
// gateway (200 with choices) and its docs tool through the tool hop (200, one
// request the stand-in counted, the bearer never forwarded); a token for an
// unconfigured client carrying the very same app roles is refused 401 with
// CredProx's own problem document and moves nothing; and a tool no named rule
// admits is refused 403 at the gate before the tool stand-in is ever touched.
// There is no live agent-loop cell on purpose: a local model's tool-call choices
// are nondeterministic, so the loop shape is pinned offline against the measured
// replay and the live leg proves admission, refusal and the tool boundary with
// direct requests. The three app registrations and both secrets belong to the run
// and are deleted again by the runner — never standing material.
[Collection("FoundryLocal")]
[Trait("Layer", "Live")]
public sealed class FoundryLocalLiveTests
{
    private readonly FoundryLocalLiveFixture _fixture;
    private readonly ITestOutputHelper _output;

    public FoundryLocalLiveTests(FoundryLocalLiveFixture fixture, ITestOutputHelper output)
    {
        _fixture = fixture;
        _output = output;
    }

    // A local CPU model is not a cloud endpoint: the chat POST gets the same
    // generous ceiling the sample's agent uses.
    private static readonly TimeSpan ChatBudget = TimeSpan.FromSeconds(240);

    [FoundryLocalLiveFact]
    public async Task RealEntraToken_MappedCallerPassesModelAndTool_UnmappedClientIsRefused()
    {
        var probe = FoundryLocalEnv.Probe();
        Assert.True(probe.Available, probe.SkipReason);
        var shapeProblems = FoundryLocalEnv.ValueProblems(probe.Values);
        Assert.True(shapeProblems.Count == 0, string.Join("; ", shapeProblems));
        var tenant = probe.Values["TENANT_ID"];
        var (mappedId, mappedSecret, unmappedId, unmappedSecret) = FoundryLocalLiveFixture.ReadScratchApps();
        // The audience is minted with the resource app (api://<its appId>), so it
        // arrives through the scratch handoff rather than a constant here.
        var audience = FoundryLocalLiveFixture.ReadScratchAudience();
        var secrets = new List<string> { mappedSecret, unmappedSecret };

        // One shared predicate for the model: the runner preflight selected the
        // id (FOUNDRY_LOCAL_MODEL from live.env, defaulting to the sample's
        // FoundryLocal:Model), proved THAT id answers with one tiny chat, and
        // exported it. The cell uses exactly that exported id and re-checks it
        // against /v1/models - nothing anywhere picks a model by catalog order.
        var model = await ReadValidatedModelIdAsync();

        _fixture.StartStandIn();
        var env = GateEnv(tenant, audience, mappedId);
        var host = _fixture.StartHost(env, secrets);
        await _fixture.WaitForHostAsync(host);
        using var client = new HttpClient
        {
            BaseAddress = new Uri(FoundryLocalLiveFixture.LiveHostUrl),
            Timeout = ChatBudget,
        };

        // The stand-in counters are collection-wide (shared fixture): take where
        // they stand NOW so this cell asserts its own traffic.
        var docsBefore = _fixture.DocsRequestCount;
        var adminBefore = _fixture.AdminRequestCount;

        // A real token, minted by the CONFIGURED client against the run-registered
        // API. If Entra refuses to mint or validate, this cell fails with the
        // sanitized error — no fallback path.
        var mappedToken = await MintTokenAsync(tenant, audience, mappedId, mappedSecret);
        using var chat = await PostChatAsync(client, model, mappedToken);
        var chatBody = await chat.Content.ReadAsStringAsync();
        var chatStatus = (int)chat.StatusCode;
        Assert.True(
            chatStatus == 200,
            $"the mapped caller was not admitted to the local model with 200 but with {chatStatus}; sanitized host output:\n" +
            SecretLeakScanner.Sanitize(host.Stdout + host.Stderr, secrets) +
            "\nsanitized response body:\n" + SecretLeakScanner.Sanitize(chatBody, secrets));
        Assert.Contains("choices", chatBody, StringComparison.Ordinal);

        // The tool hop through the same gate, same token, named rule docs-read.
        using var tool = await GetWithBearerAsync(client, "/tools/v1/docs/lookup", mappedToken);
        var toolBody = await tool.Content.ReadAsStringAsync();
        var toolStatus = (int)tool.StatusCode;
        Assert.True(
            toolStatus == 200,
            $"the mapped caller's docs tool was not admitted with 200 but with {toolStatus}; sanitized host output:\n" +
            SecretLeakScanner.Sanitize(host.Stdout + host.Stderr, secrets) +
            "\nsanitized response body:\n" + SecretLeakScanner.Sanitize(toolBody, secrets));
        Assert.Contains(FoundryLocalLiveFixture.StandInMarker, toolBody, StringComparison.Ordinal);
        Assert.Equal(docsBefore + 1, _fixture.DocsRequestCount);
        // The README: the caller's bearer never reaches the upstream. A real Entra
        // token must not leave the proxy.
        Assert.False(_fixture.SawBearerToken, "the caller's bearer token reached the tool stand-in");

        // The same role, the same tenant, an UNCONFIGURED client id: refused 401
        // as CredProx's own problem document — and the tool counters did not
        // move, so the refusal happened before any hop was touched. (The model
        // itself keeps no counter — it is a real server, not a stand-in; the
        // refusal document is CredProx's own, which no upstream could produce.)
        var unmappedToken = await MintTokenAsync(tenant, audience, unmappedId, unmappedSecret);
        using var unmapped = await PostChatAsync(client, model, unmappedToken);
        var unmappedBody = await unmapped.Content.ReadAsStringAsync();
        var unmappedStatus = (int)unmapped.StatusCode;
        Assert.True(
            unmappedStatus == 401,
            $"the unconfigured client was not refused with 401 but with {unmappedStatus}; sanitized host output:\n" +
            SecretLeakScanner.Sanitize(host.Stdout + host.Stderr, secrets) +
            "\nsanitized response body:\n" + SecretLeakScanner.Sanitize(unmappedBody, secrets));
        Assert.Contains(
            "problem+json",
            unmapped.Content.Headers.ContentType?.MediaType ?? "",
            StringComparison.Ordinal);
        Assert.Contains("credprox.caller_unauthenticated", unmappedBody, StringComparison.Ordinal);
        Assert.Equal(docsBefore + 1, _fixture.DocsRequestCount);
        Assert.Equal(adminBefore, _fixture.AdminRequestCount);

        // Nothing minted or loaded may appear in the visible output: the scanner
        // catches both the loaded secrets and any eyJ JWT shape.
        Assert.Empty(SecretLeakScanner.FindLeaks(host.Stdout + host.Stderr, secrets));
        Assert.Empty(SecretLeakScanner.FindLeaks(chatBody + toolBody + unmappedBody, secrets));

        // Numbers only — no ids, no tenant, no token — for the runner's PASS line.
        _output.WriteLine(
            $"OBSERVED foundrylocal_model={chatStatus} foundrylocal_tool={toolStatus} foundrylocal_unmapped={unmappedStatus}");
    }

    [FoundryLocalLiveFact]
    public async Task AdminTool_NoRuleAdmitsIt_RefusedAtTheGate_BeforeTheToolServer()
    {
        var probe = FoundryLocalEnv.Probe();
        Assert.True(probe.Available, probe.SkipReason);
        var tenant = probe.Values["TENANT_ID"];
        var (mappedId, mappedSecret, _, _) = FoundryLocalLiveFixture.ReadScratchApps();
        var audience = FoundryLocalLiveFixture.ReadScratchAudience();
        var secrets = new List<string> { mappedSecret };

        _fixture.StartStandIn();
        var env = GateEnv(tenant, audience, mappedId);
        var host = _fixture.StartHost(env, secrets);
        await _fixture.WaitForHostAsync(host);
        using var client = new HttpClient
        {
            BaseAddress = new Uri(FoundryLocalLiveFixture.LiveHostUrl),
            Timeout = ChatBudget,
        };

        // The stand-in SERVES this path with a live 200 on purpose: only a
        // counter that never moved proves the 403 came from the gate, not from
        // whatever the tool server answered.
        var adminBefore = _fixture.AdminRequestCount;
        var token = await MintTokenAsync(tenant, audience, mappedId, mappedSecret);
        using var admin = await GetWithBearerAsync(client, "/tools/v1/admin/reset", token);
        var adminStatus = (int)admin.StatusCode;
        var adminBody = await admin.Content.ReadAsStringAsync();
        Assert.True(
            adminStatus == 403,
            $"the admin tool was not refused at the gate with 403 but with {adminStatus}; sanitized host output:\n" +
            SecretLeakScanner.Sanitize(host.Stdout + host.Stderr, secrets) +
            "\nsanitized response body:\n" + SecretLeakScanner.Sanitize(adminBody, secrets));
        Assert.Contains(
            "problem+json",
            admin.Content.Headers.ContentType?.MediaType ?? "",
            StringComparison.Ordinal);
        Assert.Contains("credprox.operation_not_allowed", adminBody, StringComparison.Ordinal);
        Assert.Equal(adminBefore, _fixture.AdminRequestCount);
        Assert.Empty(SecretLeakScanner.FindLeaks(host.Stdout + host.Stderr + adminBody, secrets));
        // Numbers only for the runner's PASS line. The tail aggregates every
        // OBSERVED line since post-release item 3, so this cell carries its own
        // instead of riding the first cell's — the old no-line note belonged to
        // the first-match-only grep, when a second line could hide the fuller
        // picture.
        _output.WriteLine(
            $"OBSERVED foundrylocal_admin={adminStatus} admin_calls={_fixture.AdminRequestCount - adminBefore}");
    }

    // The overrides the shipped README names, plus the disclosed tool repoint.
    // The model template and cluster address are set explicitly rather than left
    // at the shipped default so the cell and the runner's model gate dial exactly
    // the same base URL.
    private static Dictionary<string, string> GateEnv(string tenant, string audience, string mappedId) => new()
    {
        ["CredProx__CallerToken__Authority"] =
            $"https://login.microsoftonline.com/{tenant}/v2.0",
        ["CredProx__CallerToken__Audience"] = audience,
        ["CredProx__Callers__agent-app__TokenClientIds__0"] = mappedId,
        ["CredProx__Destinations__foundry__Template"] = FoundryLocalLiveFixture.ModelBaseUrl,
        ["ReverseProxy__Clusters__foundry__Destinations__foundry__Address"] =
            FoundryLocalLiveFixture.ModelBaseUrl + "/",
        // disclosed deviation: the shipped tools destination is the
        // docs.tools.example placeholder; the upstream is not the thing under
        // proof, so it is repointed to the loopback stand-in.
        ["CredProx__Destinations__docs-api__Template"] = FoundryLocalLiveFixture.StandInUrl,
        ["ReverseProxy__Clusters__docs-api__Destinations__docs-api__Address"] =
            FoundryLocalLiveFixture.StandInUrl + "/",
    };

    // The model id is never picked from the catalog here: /v1/models lists
    // catalog entries that were never downloaded (live run 2 measured the first
    // id being a not-downloaded one), so the id comes from the runner — it
    // selected FOUNDRY_LOCAL_MODEL (or the sample's configured default), proved
    // it answers with one tiny chat, and exported exactly that value. This
    // reads the export and re-checks membership, and every failure names the
    // sanitized response body, not just a status.
    private static async Task<string> ReadValidatedModelIdAsync()
    {
        var model = Environment.GetEnvironmentVariable("FOUNDRY_LOCAL_MODEL");
        Assert.False(
            string.IsNullOrWhiteSpace(model),
            "FOUNDRY_LOCAL_MODEL is not exported - scripts/live-run.sh selects the model, validates it with one tiny chat before creating anything, and exports the id it validated; a live cell must never choose a model by catalog order");
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        using var response = await http.GetAsync(FoundryLocalLiveFixture.ModelBaseUrl + "/v1/models");
        var body = await response.Content.ReadAsStringAsync();
        var status = (int)response.StatusCode;
        Assert.True(
            status == 200,
            $"/v1/models answered {status} while checking the runner-validated model '{model}'; sanitized body:\n{SecretLeakScanner.Sanitize(body, [])}");
        using var doc = JsonDocument.Parse(body);
        var ids = doc.RootElement.GetProperty("data").EnumerateArray()
            .Select(entry => entry.TryGetProperty("id", out var id) ? id.GetString() : null)
            .Where(id => !string.IsNullOrWhiteSpace(id))
            .ToList();
        Assert.True(
            ids.Contains(model, StringComparer.Ordinal),
            $"/v1/models does not list the runner-validated model '{model}' - the server's loaded set changed since the preflight; sanitized body:\n{SecretLeakScanner.Sanitize(body, [])}");
        return model!;
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

    private static async Task<HttpResponseMessage> PostChatAsync(HttpClient client, string model, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/gateway/v1/chat/completions");
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + token);
        var payload = JsonSerializer.Serialize(new
        {
            model,
            messages = new[] { new { role = "user", content = "ping" } },
            max_tokens = 16,
        });
        request.Content = new StringContent(payload, Encoding.UTF8, "application/json");
        return await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, CancellationToken.None);
    }

    private static async Task<HttpResponseMessage> GetWithBearerAsync(HttpClient client, string path, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + token);
        return await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, CancellationToken.None);
    }
}
