using System.Net;
using System.Text;
using Xunit;

namespace CredProx.SampleSmokes;

/// <summary>
/// The FoundryLocalCloud sample end-to-end: one front, a local route every caller may
/// take and a cloud (Anthropic) route only named callers' allow-lists reach. The route
/// a request takes is its URL and the caller's config — nothing reroutes anything, so
/// the cells pin exactly that: refusals happen at the gate (neither stand-in moves),
/// both usage formats pass their own vendor shape, and the cloud key rides only the
/// cloud hop. The differential cell at the end proves the 403's kill comes from the
/// allow-list entry itself. One further cell drives the cloud stand-in past the
/// gateway, pinning its refusal order (version, then key) as live Anthropic answers.
/// </summary>
[Collection("FoundryLocalCloud")]
public sealed class FoundryLocalCloudSmokeTests
{
    private const string LocalPath = "/gateway/v1/chat/completions";
    private const string CloudPath = "/cloud/v1/messages";
    private readonly FoundryLocalCloudFixture _world;

    public FoundryLocalCloudSmokeTests(FoundryLocalCloudFixture world)
    {
        _world = world;
    }

    [Fact]
    [Trait("Sample", "FoundryLocalCloud")]
    public async Task LocalApp_LocalRoute_ServesTheInlineUsageBlock()
    {
        var host = _world.StartHost();
        await _world.WaitForHostAsync(host);
        var before = await _world.CallsAsync();
        using var client = Client(FoundryLocalCloudFixture.LocalAppKey);
        var response = await client.PostAsync(
            LocalPath, Json("""{"model":"qwen3-4b-generic-cpu:3","messages":[{"role":"user","content":"hi"}]}"""));
        var body = await response.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("\"prompt_tokens\":13", body, StringComparison.Ordinal);
        Assert.Equal(before + 1, await _world.CallsAsync());
    }

    [Fact]
    [Trait("Sample", "FoundryLocalCloud")]
    public async Task LocalApp_CloudRoute_403_BeforeTheCloudStandInIsTouched()
    {
        // The allow-list, not the credential and not the cloud: local-app names only
        // the local route, so the cloud route is refused at the gate.
        var host = _world.StartHost();
        await _world.WaitForHostAsync(host);
        var before = await _world.CloudCallsAsync();
        using var client = Client(FoundryLocalCloudFixture.LocalAppKey);
        var response = await client.PostAsync(CloudPath, CloudJson());
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(before, await _world.CloudCallsAsync());
    }

    [Fact]
    [Trait("Sample", "FoundryLocalCloud")]
    public async Task DualApp_CloudRoute_200_TheCloudUsageBlockPassesThrough()
    {
        var host = _world.StartHost();
        await _world.WaitForHostAsync(host);
        var before = await _world.CloudCallsAsync();
        using var client = Client(FoundryLocalCloudFixture.DualAppKey);
        var response = await client.PostAsync(CloudPath, CloudJson());
        var body = await response.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("\"input_tokens\":11", body, StringComparison.Ordinal);
        Assert.Contains("\"output_tokens\":24", body, StringComparison.Ordinal);
        Assert.Equal(before + 1, await _world.CloudCallsAsync());
    }

    [Fact]
    [Trait("Sample", "FoundryLocalCloud")]
    public async Task DualApp_TakesBothRoutes_FromItsOwnAllowListAlone()
    {
        var host = _world.StartHost();
        await _world.WaitForHostAsync(host);
        using var client = Client(FoundryLocalCloudFixture.DualAppKey);
        var local = await client.PostAsync(
            LocalPath, Json("""{"model":"m","messages":[{"role":"user","content":"hi"}]}"""));
        var cloud = await client.PostAsync(CloudPath, CloudJson());
        Assert.Equal(HttpStatusCode.OK, local.StatusCode);
        Assert.Equal(HttpStatusCode.OK, cloud.StatusCode);
    }

    [Fact]
    [Trait("Sample", "FoundryLocalCloud")]
    public async Task UnknownCallerKey_CloudRoute_401_BeforeTheCloudStandInIsTouched()
    {
        var host = _world.StartHost();
        await _world.WaitForHostAsync(host);
        var before = await _world.CloudCallsAsync();
        using var client = Client("not-a-key");
        var response = await client.PostAsync(CloudPath, CloudJson());
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(before, await _world.CloudCallsAsync());
    }

    [Fact]
    [Trait("Sample", "FoundryLocalCloud")]
    public async Task BothRoutes_MeterTokenCounts_OnTheConsoleExporter()
    {
        // One caller, both routes, one meter: each route's CredProx.Metering.Usage
        // metadata arms its vendor's reader, so one local and one cloud call must both
        // surface token counters carrying the caller tag. Drop either metadata and the
        // usage.* lines lose a series - this cell is the witness for both arms.
        var host = _world.StartHost(new Dictionary<string, string>
        {
            ["Metrics__Console"] = "true",
            ["OTEL_METRIC_EXPORT_INTERVAL"] = "1000",
        });
        await _world.WaitForHostAsync(host);
        using var client = Client(FoundryLocalCloudFixture.DualAppKey);
        var local = await client.PostAsync(
            LocalPath, Json("""{"model":"qwen3-4b-generic-cpu:3","messages":[{"role":"user","content":"hi"}]}"""));
        var cloud = await client.PostAsync(CloudPath, CloudJson());
        Assert.True(
            local.IsSuccessStatusCode && cloud.IsSuccessStatusCode,
            $"setup calls failed: local={(int)local.StatusCode} cloud={(int)cloud.StatusCode}\n{host.Stderr}");
        await FoundryLocalCloudFixture.WaitUntilAsync(
            () => Task.FromResult(
                host.Stdout.Contains("credprox.usage.input_tokens", StringComparison.Ordinal)
                && host.Stdout.Contains("credprox.usage.output_tokens", StringComparison.Ordinal)),
            $"usage metering lines never appeared on the console exporter:\n{host.Stdout}");
        var log = host.Stdout;
        var at = log.IndexOf("credprox.usage.input_tokens", StringComparison.Ordinal);
        var window = log[at..Math.Min(at + 1600, log.Length)];
        Assert.Contains("credprox.caller", window, StringComparison.Ordinal);
        Assert.Contains("dual-app", window, StringComparison.Ordinal);
        // The shipped keys — caller and cloud — must not ride any export or log line.
        var output = log + host.Stderr;
        Assert.DoesNotContain(FoundryLocalCloudFixture.DualAppKey, output, StringComparison.Ordinal);
        Assert.DoesNotContain(FoundryLocalCloudFixture.CloudDemoKey, output, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Sample", "FoundryLocalCloud")]
    public async Task SameRequest_CloudRouteAddedToTheAllowListByConfig_ReachesTheCloudStandIn()
    {
        // The differential witness for the 403 cell: identical request and caller, the
        // only change env entries appending the cloud route to local-app's allow-list.
        // The request now reaches the cloud stand-in authenticated (200, counter +1) —
        // the 403 dies exactly when the allow-list entry dies, and no code differed.
        var host = _world.StartHost(new Dictionary<string, string>
        {
            ["CredProx__Callers__local-app__Operations__1__Route"] = "anthropic",
            ["CredProx__Callers__local-app__Operations__1__Methods__0"] = "POST",
            ["CredProx__Callers__local-app__Operations__1__Paths__0"] = "/cloud/v1/messages/**",
        });
        await _world.WaitForHostAsync(host);
        var before = await _world.CloudCallsAsync();
        using var client = Client(FoundryLocalCloudFixture.LocalAppKey);
        var response = await client.PostAsync(CloudPath, CloudJson());
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(before + 1, await _world.CloudCallsAsync());
    }

    [Fact]
    [Trait("Sample", "FoundryLocalCloud")]
    public async Task CloudStandIn_DirectDrive_RefusesMissingVersionThenMissingKey_MovingNothing()
    {
        // The stand-in's own contract, driven past the gateway so the cloud route's
        // anthropic-version transform cannot hide anything: without the version header
        // even a valid cloud key gets 400 with Anthropic's own phrase, and the 401 for
        // a missing key only surfaces once the version is present. Neither refusal
        // touches the counter — the shape live Anthropic shows, replayed offline.
        var before = await _world.CloudCallsAsync();
        using var standIn = new HttpClient { BaseAddress = new Uri(FoundryLocalCloudFixture.CloudStubUrl) };
        using (var neitherHeader = new HttpRequestMessage(HttpMethod.Post, "/v1/messages") { Content = CloudJson() })
        {
            // bare request: the version refusal wins over the key one, so the
            // version check provably runs FIRST — swapping the two checks turns
            // this into a 401 and burns this cell.
            var refused = await standIn.SendAsync(neitherHeader);
            Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
            Assert.Contains(
                "anthropic-version: header is required",
                await refused.Content.ReadAsStringAsync(),
                StringComparison.Ordinal);
        }
        using (var noVersion = new HttpRequestMessage(HttpMethod.Post, "/v1/messages") { Content = CloudJson() })
        {
            noVersion.Headers.TryAddWithoutValidation("x-api-key", FoundryLocalCloudFixture.CloudDemoKey);
            var refused = await standIn.SendAsync(noVersion);
            Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
            Assert.Contains(
                "anthropic-version: header is required",
                await refused.Content.ReadAsStringAsync(),
                StringComparison.Ordinal);
        }
        using (var noKey = new HttpRequestMessage(HttpMethod.Post, "/v1/messages") { Content = CloudJson() })
        {
            noKey.Headers.TryAddWithoutValidation("anthropic-version", "2023-06-01");
            var refused = await standIn.SendAsync(noKey);
            Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
            Assert.Contains(
                "missing api key",
                await refused.Content.ReadAsStringAsync(),
                StringComparison.Ordinal);
        }

        Assert.Equal(before, await _world.CloudCallsAsync());
    }

    private static HttpClient Client(string? key)
    {
        var client = new HttpClient { BaseAddress = new Uri(FoundryLocalCloudFixture.HostUrl) };
        if (key is not null)
        {
            client.DefaultRequestHeaders.TryAddWithoutValidation("X-CredProx-Key", key);
        }

        return client;
    }

    private static StringContent Json(string body) => new(body, Encoding.UTF8, "application/json");

    private static StringContent CloudJson() =>
        Json("""{"model":"claude-sonnet-4-5","max_tokens":64,"messages":[{"role":"user","content":"hi"}]}""");
}
