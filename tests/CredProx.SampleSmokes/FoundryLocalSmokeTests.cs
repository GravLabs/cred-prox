using System.Net;
using System.Text;
using Xunit;

namespace CredProx.SampleSmokes;

/// <summary>
/// The FoundryLocalGateway sample end-to-end against the measured-shape stand-in:
/// caller keys are the only authentication on a path whose upstream has none, the
/// per-caller allow-list refuses before the model is touched, and both OpenAI usage
/// shapes serve — inline usage on a JSON completion and the usage-only SSE event on an
/// include_usage stream. Each cell pins one shipped-config claim; the differential cell
/// at the end proves the 403 cell's kill comes from the allow-list itself.
/// </summary>
[Collection("FoundryLocalGateway")]
public sealed class FoundryLocalSmokeTests
{
    private const string ChatPath = "/gateway/v1/chat/completions";
    private readonly FoundryLocalGatewayFixture _world;

    public FoundryLocalSmokeTests(FoundryLocalGatewayFixture world)
    {
        _world = world;
    }

    [Fact]
    [Trait("Sample", "FoundryLocalGateway")]
    public async Task ChatApp_NonStreamCompletion_ReturnsTheInlineUsageBlock()
    {
        var host = _world.StartHost();
        await _world.WaitForHostAsync(host);
        var before = await _world.CallsAsync();
        using var client = Client();
        var response = await client.PostAsync(
            ChatPath, Json("""{"model":"qwen3-4b-generic-cpu:3","messages":[{"role":"user","content":"hi"}]}"""));
        var body = await response.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("chat.completion", body, StringComparison.Ordinal);
        Assert.Contains("\"prompt_tokens\":13", body, StringComparison.Ordinal);
        Assert.Contains("\"completion_tokens\":32", body, StringComparison.Ordinal);
        Assert.Equal(before + 1, await _world.CallsAsync());
    }

    [Fact]
    [Trait("Sample", "FoundryLocalGateway")]
    public async Task ChatApp_StreamWithIncludeUsage_TheUsageOnlyEventArrives()
    {
        var host = _world.StartHost();
        await _world.WaitForHostAsync(host);
        using var client = Client();
        var response = await client.PostAsync(
            ChatPath,
            Json("""{"model":"qwen3-4b-generic-cpu:3","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"hi"}]}"""));
        var body = await response.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        // The stream shape the README promises: deltas, then the usage-only event,
        // then [DONE] — the whole metered tail survives the proxy end to end.
        Assert.Contains("\"choices\":[]", body, StringComparison.Ordinal);
        Assert.Contains("\"usage\":{\"prompt_tokens\":13", body, StringComparison.Ordinal);
        Assert.Contains("[DONE]", body, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Sample", "FoundryLocalGateway")]
    public async Task UnknownCallerKey_401_BeforeTheStandInIsTouched()
    {
        var host = _world.StartHost();
        await _world.WaitForHostAsync(host);
        var before = await _world.CallsAsync();
        using var client = Client("not-a-key");
        var response = await client.PostAsync(
            ChatPath, Json("""{"model":"m","messages":[]}"""));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(before, await _world.CallsAsync());
    }

    [Fact]
    [Trait("Sample", "FoundryLocalGateway")]
    public async Task ChatApp_OutsideItsAllowList_403_BeforeTheStandInIsTouched()
    {
        var host = _world.StartHost();
        await _world.WaitForHostAsync(host);
        var before = await _world.CallsAsync();
        using var client = Client(FoundryLocalGatewayFixture.ChatAppKey);
        var response = await client.PostAsync("/gateway/admin/jobs", Json("""{}"""));
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(before, await _world.CallsAsync());
    }

    [Fact]
    [Trait("Sample", "FoundryLocalGateway")]
    public async Task OpsApp_NamesNoOperations_CallsTheChatRoute()
    {
        var host = _world.StartHost();
        await _world.WaitForHostAsync(host);
        using var client = Client(FoundryLocalGatewayFixture.OpsAppKey);
        var response = await client.PostAsync(
            ChatPath, Json("""{"model":"m","messages":[]}"""));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    [Trait("Sample", "FoundryLocalGateway")]
    public async Task UsageMetadata_MetersTokenCounts_OnTheConsoleExporter()
    {
        // The metering leg: with Metrics__Console=true the sample prints the CredProx
        // meter instead of exporting OTLP, and the route's CredProx.Metering.Usage
        // metadata is what arms the token counters — drop that metadata and the
        // usage.* metric lines never appear, so this cell dies on the metadata itself.
        var host = _world.StartHost(new Dictionary<string, string>
        {
            ["Metrics__Console"] = "true",
            ["OTEL_METRIC_EXPORT_INTERVAL"] = "1000",
        });
        await _world.WaitForHostAsync(host);
        using var client = Client();
        var call = await client.PostAsync(
            ChatPath, Json("""{"model":"qwen3-4b-generic-cpu:3","messages":[{"role":"user","content":"hi"}]}"""));
        Assert.True(call.IsSuccessStatusCode, $"chat call failed: {(int)call.StatusCode}\n{host.Stderr}");
        // Audit and meter lines land as their responses complete, in arbitrary order —
        // wait with the assert's own predicates rather than trusting one printed line.
        await FoundryLocalGatewayFixture.WaitUntilAsync(
            () => Task.FromResult(
                host.Stdout.Contains("credprox.usage.input_tokens", StringComparison.Ordinal)
                && host.Stdout.Contains("credprox.usage.output_tokens", StringComparison.Ordinal)),
            $"usage metering lines never appeared on the console exporter:\n{host.Stdout}");
        // The caller identity rides the measurements: the window after the token
        // counter's metric line must carry the caller tag (the exporter prints tag
        // lines under the metric they belong to).
        var log = host.Stdout;
        var at = log.IndexOf("credprox.usage.input_tokens", StringComparison.Ordinal);
        var window = log[at..Math.Min(at + 800, log.Length)];
        Assert.Contains("credprox.caller", window, StringComparison.Ordinal);
        Assert.Contains("chat-app", window, StringComparison.Ordinal);
        // The shipped caller key must not ride any export.
        Assert.DoesNotContain(FoundryLocalGatewayFixture.ChatAppKey, log, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Sample", "FoundryLocalGateway")]
    public async Task SameRequest_WithTheAllowListWidenedByConfig_ReachesTheStandIn()
    {
        // The differential witness for the 403 cell: identical request and caller, the
        // only change an env override that widens chat-app's allow-list to the whole
        // gateway. The request now reaches the stand-in (its 404 proves arrival, and
        // the hit counter moved) — so the 403 cell dies exactly when the allow-list
        // entry dies, and nothing in code was different between the two cells.
        var host = _world.StartHost(new Dictionary<string, string>
        {
            ["CredProx__Callers__chat-app__Operations__0__Paths__0"] = "/gateway/**",
        });
        await _world.WaitForHostAsync(host);
        var before = await _world.CallsAsync();
        using var client = Client(FoundryLocalGatewayFixture.ChatAppKey);
        var response = await client.PostAsync("/gateway/admin/jobs", Json("""{}"""));
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal(before + 1, await _world.CallsAsync());
    }

    private static HttpClient Client(string? key = FoundryLocalGatewayFixture.ChatAppKey)
    {
        var client = new HttpClient { BaseAddress = new Uri(FoundryLocalGatewayFixture.HostUrl) };
        if (key is not null)
        {
            client.DefaultRequestHeaders.TryAddWithoutValidation("X-CredProx-Key", key);
        }

        return client;
    }

    private static StringContent Json(string body) => new(body, Encoding.UTF8, "application/json");
}
