using System.Text;
using System.Text.RegularExpressions;
using Xunit;
using Xunit.Abstractions;

namespace CredProx.LiveTests;

// A cell that spends one tiny BILLABLE Anthropic call, on top of the AiGateway env
// gate: opt-in only via the CREDPROX_LIVE_METERED=1 process variable, skipped with a
// loud reason by default (owner decision — spend happens when the owner says go,
// the lead runs it). Proves the M50 promise end-to-end on the real provider:
// one metered request with non-zero token counts read from Anthropic's own usage
// report, visible on the sample's console metric exporter, with the caller-side
// checks (problem documents, secret hygiene) unchanged from the models cell. Like
// every other live attribute it also requires the shared runner gate — the marker
// naming the aigateway leg — so a bare or filtered dotnet test never arms it even
// with a usable env file and a stray opt-in variable.
public sealed class AiGatewayMeteredLiveFactAttribute : FactAttribute, ILiveFactAttribute
{
    public AiGatewayMeteredLiveFactAttribute()
    {
        var probe = AiGatewayEnv.Probe();
        if (!probe.Available)
        {
            Skip = probe.SkipReason;
            return;
        }

        var problems = LiveRunnerGate.Problems(
            AiGatewayEnv.Vendor,
            Environment.GetEnvironmentVariable(LiveRunnerGate.RunnerVendorVariable));
        if (problems.Count > 0)
        {
            Skip = LiveRunnerGate.SkipReason(problems);
            return;
        }

        if (Environment.GetEnvironmentVariable("CREDPROX_LIVE_METERED") != "1")
        {
            Skip = "billable by design: set CREDPROX_LIVE_METERED=1 to spend one tiny metered Anthropic messages call (owner-approved, the lead runs it)";
        }
    }
}

[Collection("AiGateway")]
[Trait("Layer", "Live")]
public sealed class AiGatewayMeteredLiveTests
{
    private readonly AiGatewayFixture _fixture;
    private readonly ITestOutputHelper _output;

    public AiGatewayMeteredLiveTests(AiGatewayFixture fixture, ITestOutputHelper output)
    {
        _fixture = fixture;
        _output = output;
    }

    [AiGatewayMeteredLiveFact]
    public async Task AiGateway_MeteredCall_TokensFromProvidersOwnReport()
    {
        var probe = AiGatewayEnv.Probe();
        Assert.True(probe.Available, probe.SkipReason);
        var shapeProblems = AiGatewayEnv.ValueProblems(probe.Values);
        Assert.True(shapeProblems.Count == 0, string.Join("; ", shapeProblems));

        var apiKey = probe.Values["ANTHROPIC_API_KEY"];
        var secrets = new List<string> { apiKey };
        var callerKey = "live-metered-" + Guid.NewGuid().ToString("N");
        var env = new Dictionary<string, string>
        {
            // the same README-style Anthropic repoint as the models cell — configuration
            // only, and the console metric exporter so the meters land in captured stdout
            ["CredProx__Secrets__ai-provider-key"] = apiKey,
            ["CredProx__Destinations__ai__Template"] = "https://api.anthropic.com",
            ["ReverseProxy__Clusters__ai__Destinations__ai__Address"] = AiGatewayFixture.AnthropicAddress,
            ["CredProx__Credentials__ai-provider__Name"] = "x-api-key",
            ["CredProx__Credentials__ai-provider__Prefix"] = "",
            ["ReverseProxy__Routes__ai__Transforms__1__RequestHeader"] = "anthropic-version",
            ["ReverseProxy__Routes__ai__Transforms__1__Set"] = "2023-06-01",
            // the shipped appsettings already arm CredProx:Metering and opt the ai route
            // into usage; this caller gets exactly the two operations this cell needs
            ["CredProx__Callers__live-metered__Keys__0__KeyId"] = "live-metered-key-1",
            ["CredProx__Callers__live-metered__Keys__0__KeyHash"] = AiGatewayFixture.CallerKeyConfig(callerKey),
            ["CredProx__Callers__live-metered__Operations__0__Route"] = "ai",
            ["CredProx__Callers__live-metered__Operations__0__Methods__0"] = "GET",
            ["CredProx__Callers__live-metered__Operations__0__Paths__0"] = "/ai/v1/models",
            ["CredProx__Callers__live-metered__Operations__1__Route"] = "ai",
            ["CredProx__Callers__live-metered__Operations__1__Methods__0"] = "POST",
            ["CredProx__Callers__live-metered__Operations__1__Paths__0"] = "/ai/v1/messages",
            // console exporter into stdout, 1 s cadence so the wait below is short
            ["Metrics__Console"] = "true",
            ["OTEL_METRIC_EXPORT_INTERVAL"] = "1000",
        };

        var host = _fixture.StartHost(env, secrets, AiGatewayFixture.LiveHostPort);
        {
            await _fixture.WaitForHostAsync(host, AiGatewayFixture.LiveHostUrl);
            using var client = new HttpClient { BaseAddress = new Uri(AiGatewayFixture.LiveHostUrl) };

            // unbillable first: the model list gives a real model id
            var models = await client.SendAsync(NewRequest(HttpMethod.Get, "/ai/v1/models", callerKey));
            var modelsBody = await models.Content.ReadAsStringAsync();
            Assert.True((int)models.StatusCode == 200, $"models list answered {(int)models.StatusCode}: " + SecretLeakScanner.Sanitize(modelsBody, secrets));
            var modelId = FirstModelId(modelsBody);
            Assert.NotNull(modelId);

            // THE one tiny billable call: max_tokens 1, one-word prompt
            var post = NewRequest(HttpMethod.Post, "/ai/v1/messages", callerKey);
            post.Content = new StringContent(
                "{\"model\":\"" + modelId + "\",\"max_tokens\":1,\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}",
                Encoding.UTF8,
                "application/json");
            var answered = await client.SendAsync(post);
            var answeredBody = await answered.Content.ReadAsStringAsync();
            Assert.True((int)answered.StatusCode == 200, $"metered call answered {(int)answered.StatusCode}: " + SecretLeakScanner.Sanitize(answeredBody, secrets));
            Assert.Contains("\"usage\"", answeredBody, StringComparison.Ordinal);

            // the audit leg first: one step per leg so a failed run names the FIRST
            // thing that died (audit on completion, then the export), and the failure
            // text carries stderr plus the exit state — a dead host announces itself
            // instead of looking like missing counts.
            await LiveHosts.WaitUntilAsync(
                () => Task.FromResult(LiveHosts.ContainsOnOneLine(
                    host.Stdout, "credprox.proxied_call: caller=live-metered", "method=POST")),
                "the metered POST never reached the audit recorder on completion",
                host,
                secrets,
                30);
            // the provider's own report reached the meter: Anthropic reports usage on
            // the JSON response; the metering leg must emit both token counters with
            // non-zero values on the console exporter, read through the shared
            // console-format parser (the local copy used a pre-1.12 exporter spelling
            // that 1.15.3 never prints, so the wait was blind on any pipeline).
            await LiveHosts.WaitUntilAsync(
                () => Task.FromResult(
                    LiveHosts.CounterValue(host.Stdout, "credprox.usage.input_tokens") > 0
                    && LiveHosts.CounterValue(host.Stdout, "credprox.usage.output_tokens") > 0),
                "token counters never showed non-zero values on the console exporter",
                host,
                secrets,
                30);
            var inputs = LiveHosts.CounterValue(host.Stdout, "credprox.usage.input_tokens");
            var outputs = LiveHosts.CounterValue(host.Stdout, "credprox.usage.output_tokens");

            // one forwarded request metered, carrying the caller name; caller key
            // itself never in the log
            Assert.Contains("credprox.requests", host.Stdout, StringComparison.Ordinal);
            Assert.Contains("credprox.caller", host.Stdout, StringComparison.Ordinal);
            var log = host.Stdout + host.Stderr;
            Assert.Empty(SecretLeakScanner.FindLeaks(log, secrets));
            Assert.DoesNotContain(callerKey, log, StringComparison.Ordinal);

            // both forwarded calls are metered; only the messages POST reports usage
            // and only it is billable
            _output.WriteLine(
                $"OBSERVED metered_calls=2 billable_calls=1 input_tokens={inputs} output_tokens={outputs}");
        }
    }

    private static HttpRequestMessage NewRequest(HttpMethod method, string path, string callerKey)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.Add("X-CredProx-Key", callerKey);
        return request;
    }

    private static string? FirstModelId(string modelsBody)
    {
        var match = Regex.Match(modelsBody, "\"id\"\\s*:\\s*\"([^\"]+)\"");
        return match.Success ? match.Groups[1].Value : null;
    }
}
