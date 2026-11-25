using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Xunit;

namespace CredProx.SampleSmokes;

/// <summary>
/// The AzureOpenAI sample's offline claims: the Entra token flows as Authorization: Bearer
/// (never api-key) and arrives at the stand-in with the exact value its managed-identity
/// endpoint issued; the per-caller Operations Paths rule is the deployment allow-list and a
/// caller outside it is refused 403 before the stand-in is touched; the stand-in's two
/// refusals (no bearer, api-key present) pin "keyless" on the wire; and the route's
/// CredProx.Metering.Usage = openai metadata counts tokens per caller.
/// </summary>
[Collection("AzureOpenAI")]
public sealed class AzureOpenAISmokeTests
{
    private const string Gpt4Path =
        "/aoai/openai/deployments/gpt-4o/chat/completions?api-version=2024-10-21";
    private const string Gpt5Path =
        "/aoai/openai/deployments/gpt-5/chat/completions?api-version=2024-10-21";

    private readonly AzureOpenAIFixture _world;

    public AzureOpenAISmokeTests(AzureOpenAIFixture world)
    {
        _world = world;
    }

    [Fact]
    [Trait("Sample", "AzureOpenAI")]
    public async Task ChatApp_Completion_SucceedsWithTheCannedEntraBearerAndNoApiKey()
    {
        var host = _world.StartHost();
        await _world.WaitForHostAsync(host);
        using var client = Client(AzureOpenAIFixture.ChatAppKey);
        var response = await client.PostAsync(Gpt4Path, Json(Body("gpt-4o")));
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.OK, $"chat call failed: {(int)response.StatusCode}\n{host.Stderr}");
        Assert.Contains("offline stand-in completion", text, StringComparison.Ordinal);
        Assert.Contains("\"total_tokens\":16", text, StringComparison.Ordinal);

        // The vendor-side witness: the bearer that arrived is exactly the token the
        // stand-in's managed-identity endpoint issued — the canned Entra token rode the
        // whole chain — and no api-key header was present.
        var last = await _world.LastChatAttemptAsync();
        Assert.Equal(
            $"Bearer {AzureOpenAIFixture.CannedBearerToken}",
            last.GetProperty("authorization").GetString());
        Assert.False(last.GetProperty("api_key_present").GetBoolean());
    }

    [Fact]
    [Trait("Sample", "AzureOpenAI")]
    public async Task ChatApp_Gpt5_403_BeforeTheStandInIsTouched()
    {
        // chat-app's Operations names gpt-4o only: the deployment rides the path, so the
        // Paths rule IS the deployment allow-list, refused at the gate.
        var host = _world.StartHost();
        await _world.WaitForHostAsync(host);
        var before = await _world.CallsAsync();
        using var client = Client(AzureOpenAIFixture.ChatAppKey);
        var response = await client.PostAsync(Gpt5Path, Json(Body("gpt-5")));
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(before, await _world.CallsAsync());
    }

    [Fact]
    [Trait("Sample", "AzureOpenAI")]
    public async Task AdminApp_Gpt5_ReachesTheStandIn()
    {
        // admin-app ships no Operations list — every deployment, the other side of the
        // allow-list claim the 403 cell pins.
        var host = _world.StartHost();
        await _world.WaitForHostAsync(host);
        var before = await _world.CallsAsync();
        using var client = Client(AzureOpenAIFixture.AdminAppKey);
        var response = await client.PostAsync(Gpt5Path, Json(Body("gpt-5")));
        Assert.True(response.StatusCode == HttpStatusCode.OK, $"admin call failed: {(int)response.StatusCode}\n{host.Stderr}");
        Assert.True(await _world.CallsAsync() > before);
    }

    [Fact]
    [Trait("Sample", "AzureOpenAI")]
    public async Task SameRequest_ChatAppWithWidenedAllowList_ReachesTheStandIn()
    {
        // The differential witness for the 403 cell: identical request and caller, the only
        // change an env override widening chat-app's Paths to the whole gateway. The request
        // now reaches the stand-in (the hit counter moved) — so the 403 dies exactly when
        // the allow-list entry dies, with no code different between the cells.
        var host = _world.StartHost(new Dictionary<string, string>
        {
            ["CredProx__Callers__chat-app__Operations__0__Paths__0"] = "/aoai/**",
        });
        await _world.WaitForHostAsync(host);
        var before = await _world.CallsAsync();
        using var client = Client(AzureOpenAIFixture.ChatAppKey);
        var response = await client.PostAsync(Gpt5Path, Json(Body("gpt-5")));
        Assert.True(response.StatusCode == HttpStatusCode.OK, $"widened call failed: {(int)response.StatusCode}\n{host.Stderr}");
        Assert.True(await _world.CallsAsync() > before);
    }

    [Fact]
    [Trait("Sample", "AzureOpenAI")]
    public async Task MissingKey_AndWrongKey_Both401_StandInUntouched()
    {
        var host = _world.StartHost();
        await _world.WaitForHostAsync(host);
        var before = await _world.CallsAsync();
        using var anonymous = Client(null);
        var missing = await anonymous.PostAsync(Gpt4Path, Json(Body("gpt-4o")));
        using var wrong = Client("not-a-key");
        var wrongKey = await wrong.PostAsync(Gpt4Path, Json(Body("gpt-4o")));
        Assert.Equal(HttpStatusCode.Unauthorized, missing.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, wrongKey.StatusCode);
        Assert.Equal(before, await _world.CallsAsync());
    }

    [Fact]
    [Trait("Sample", "AzureOpenAI")]
    public async Task StandIn_RefusesMissingBearer_AndAnyApiKey_TheKeylessWireShape()
    {
        // The two refusals straight at the stand-in — what "like an Entra-only setup"
        // means on the wire, proven independently of CredProx: no bearer is refused, a
        // request carrying api-key is refused even with a valid bearer, and only
        // bearer-without-key is served (the arm every other cell depends on is reachable).
        // The counter rides only the served arm: two refusals must leave it exactly
        // where it was and the one served call must move it by exactly one.
        var before = await _world.CallsAsync();
        using var anonymous = new HttpClient();
        var noBearer = await anonymous.PostAsync(
            $"{AzureOpenAIFixture.StubUrl}/openai/deployments/gpt-4o/chat/completions?api-version=2024-10-21",
            Json(Body("gpt-4o")));
        Assert.Equal(HttpStatusCode.Unauthorized, noBearer.StatusCode);

        using var keyed = new HttpClient();
        keyed.DefaultRequestHeaders.TryAddWithoutValidation("api-key", "any-key-at-all");
        keyed.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", AzureOpenAIFixture.CannedBearerToken);
        var withKey = await keyed.PostAsync(
            $"{AzureOpenAIFixture.StubUrl}/openai/deployments/gpt-4o/chat/completions?api-version=2024-10-21",
            Json(Body("gpt-4o")));
        Assert.Equal(HttpStatusCode.Unauthorized, withKey.StatusCode);

        using var bearerOnly = new HttpClient();
        bearerOnly.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", AzureOpenAIFixture.CannedBearerToken);
        var served = await bearerOnly.PostAsync(
            $"{AzureOpenAIFixture.StubUrl}/openai/deployments/gpt-4o/chat/completions?api-version=2024-10-21",
            Json(Body("gpt-4o")));
        Assert.True(served.StatusCode == HttpStatusCode.OK, "the stand-in's served arm must be reachable");
        Assert.Equal(before + 1, await _world.CallsAsync());
    }

    [Fact]
    [Trait("Sample", "AzureOpenAI")]
    public async Task UsageMetadata_MetersTokenCounts_OnTheConsoleExporter()
    {
        // The metering leg: with Metrics__Console=true the sample prints the CredProx
        // meter instead of exporting OTLP, and the route's CredProx.Metering.Usage
        // metadata is what arms the token counters — drop that metadata and the usage.*
        // metric lines never appear, so this cell dies on the metadata itself.
        var host = _world.StartHost(new Dictionary<string, string>
        {
            ["Metrics__Console"] = "true",
            ["OTEL_METRIC_EXPORT_INTERVAL"] = "1000",
        });
        await _world.WaitForHostAsync(host);
        using var client = Client(AzureOpenAIFixture.ChatAppKey);
        var call = await client.PostAsync(Gpt4Path, Json(Body("gpt-4o")));
        Assert.True(call.IsSuccessStatusCode, $"chat call failed: {(int)call.StatusCode}\n{host.Stderr}");
        await AzureOpenAIFixture.WaitUntilAsync(
            () => Task.FromResult(
                host.Stdout.Contains("credprox.usage.input_tokens", StringComparison.Ordinal)
                && host.Stdout.Contains("credprox.usage.output_tokens", StringComparison.Ordinal)),
            $"usage metering lines never appeared on the console exporter:\n{host.Stdout}");
        var log = host.Stdout;
        var at = log.IndexOf("credprox.usage.input_tokens", StringComparison.Ordinal);
        var window = log[at..Math.Min(at + 800, log.Length)];
        Assert.Contains("credprox.caller", window, StringComparison.Ordinal);
        Assert.Contains("chat-app", window, StringComparison.Ordinal);
        // The shipped caller key must not ride any export.
        Assert.DoesNotContain(AzureOpenAIFixture.ChatAppKey, log, StringComparison.Ordinal);
    }

    private static HttpClient Client(string? key = AzureOpenAIFixture.ChatAppKey)
    {
        var client = new HttpClient { BaseAddress = new Uri(AzureOpenAIFixture.HostUrl) };
        if (key is not null)
        {
            client.DefaultRequestHeaders.TryAddWithoutValidation("X-CredProx-Key", key);
        }

        return client;
    }

    private static string Body(string model) =>
        $$"""{"model":"{{model}}","messages":[{"role":"user","content":"hi"}]}""";

    private static StringContent Json(string body) =>
        new(body, Encoding.UTF8, "application/json");
}
