using System.Text;
using Xunit;
using Xunit.Abstractions;

namespace CredProx.LiveTests;

// A cell that drives the FoundryLocalGateway sample against the real local model.
// Nothing here is billable: Foundry Local on loopback costs nothing per call. The
// gate is the shared runner marker naming the foundrylocal leg and nothing else —
// this path never touches Entra, so the run-created app handoff would be evidence
// about a route this cell does not take; the marker is runner-only by design, a
// bare or filtered dotnet test never carries it, and by the time the runner set
// it the model gate already proved the exported id answers.
public sealed class FoundryLocalGatewayLiveFactAttribute : FactAttribute, ILiveFactAttribute
{
    public FoundryLocalGatewayLiveFactAttribute()
    {
        var problems = LiveRunnerGate.Problems(
            FoundryLocalEnv.Vendor,
            Environment.GetEnvironmentVariable(LiveRunnerGate.RunnerVendorVariable));
        if (problems.Count > 0)
        {
            Skip = LiveRunnerGate.SkipReason(problems);
        }
    }
}

// The free gateway leg: a caller key passes to the REAL local model with 200 and
// a usage-bearing body, a wrong key is refused 401, an operation the caller's
// list does not name is refused 403 at the gate, and the openai usage counters
// move on the console exporter with the audit naming this caller (the M50 export
// pattern, waited and settled as in M53). The model id is the one the runner
// validated and exported — the same shared predicate the agent cell uses.
[Trait("Layer", "Live")]
public sealed class FoundryLocalGatewayLiveTests : IAsyncLifetime
{
    // The sample's own configured port; the live leg runs one host per port and
    // the cross-sample port-uniqueness guard covers the shipped config.
    private const string GatewayUrl = "http://localhost:5105";
    private const int GatewayPort = 5105;
    private readonly ITestOutputHelper _output;
    private string _callerKey = "";
    private LiveHosts.RunningHost? _host;

    public FoundryLocalGatewayLiveTests(ITestOutputHelper output) => _output = output;

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        if (_host is not null && !_host.Process.HasExited)
        {
            _host.Process.Kill(entireProcessTree: true);
            _host.Process.WaitForExit(5000);
        }
        await Task.CompletedTask;
    }

    [FoundryLocalGatewayLiveFact]
    public async Task GatewaySample_RealLocalModel_KeyPassesWrongKeyAndForeignOperationRefused()
    {
        var model = Environment.GetEnvironmentVariable("FOUNDRY_LOCAL_MODEL");
        Assert.False(
            string.IsNullOrWhiteSpace(model),
            "FOUNDRY_LOCAL_MODEL is not exported - the foundrylocal runner leg validates one model id with a tiny chat before it creates anything and exports it; this cell calls exactly that id, never a catalog pick");
        _callerKey = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
        var secrets = new List<string> { _callerKey };
        var env = new Dictionary<string, string>
        {
            ["Urls"] = GatewayUrl,
            ["Metrics__Console"] = "true",
            // the console exporter prints on a cadence and the default is 60 s - longer
            // than this cell's 30 s counter-settle window, so shorten it (the shape every
            // sibling metered live cell uses)
            ["OTEL_METRIC_EXPORT_INTERVAL"] = "1000",
            ["CredProx__Destinations__foundry__Template"] = FoundryLocalEnv.ModelBaseUrl,
            ["ReverseProxy__Clusters__foundry__Destinations__foundry__Address"] = FoundryLocalEnv.ModelBaseUrl + "/",
            ["CredProx__Callers__live-gateway__Keys__0__KeyId"] = "live-gateway-key-1",
            ["CredProx__Callers__live-gateway__Keys__0__KeyHash"] = AiGatewayFixture.CallerKeyConfig(_callerKey),
            ["CredProx__Callers__live-gateway__Operations__0__Route"] = "foundry",
            ["CredProx__Callers__live-gateway__Operations__0__Methods__0"] = "POST",
            ["CredProx__Callers__live-gateway__Operations__0__Paths__0"] = "/gateway/v1/chat/**",
        };
        var bin = LiveHosts.LocateBin(Path.Combine("samples", "FoundryLocalGateway"), "FoundryLocalGateway.dll");
        LiveHosts.EnsurePortsFree(GatewayPort);
        _host = new LiveHosts.RunningHost(LiveHosts.Start(bin, "FoundryLocalGateway.dll", env));
        var host = _host;
        using var client = new HttpClient { BaseAddress = new Uri(GatewayUrl), Timeout = TimeSpan.FromSeconds(120) };
        using var probe = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        await LiveHosts.WaitUntilAsync(
            async () =>
            {
                if (host.Process.HasExited)
                {
                    throw new InvalidOperationException(
                        $"the FoundryLocalGateway host exited early (code {host.Process.ExitCode}):\n" +
                        SecretLeakScanner.Sanitize(host.Stderr, secrets));
                }
                try
                {
                    using var _ = await probe.GetAsync(GatewayUrl + "/live-probe-not-a-route");
                    return true;
                }
                catch (HttpRequestException)
                {
                    return false;
                }
                catch (TaskCanceledException)
                {
                    return false;
                }
            },
            "the gateway host never answered its port",
            host,
            secrets,
            90);

        // The admitted call: real local model, tiny completion, usage in the body.
        var chat = NewRequest(HttpMethod.Post, "/gateway/v1/chat/completions", _callerKey);
        chat.Content = new StringContent(
            $"{{\"model\":\"{model}\",\"max_tokens\":1,\"messages\":[{{\"role\":\"user\",\"content\":\"ping\"}}]}}",
            Encoding.UTF8,
            "application/json");
        var chatResponse = await client.SendAsync(chat);
        var chatBody = await chatResponse.Content.ReadAsStringAsync();
        var chatStatus = (int)chatResponse.StatusCode;
        Assert.True(
            chatStatus == 200,
            $"the caller key was not admitted to the local model with 200 but with {chatStatus}; sanitized host output:\n" +
            SecretLeakScanner.Sanitize(host.Stdout + host.Stderr, secrets) +
            "\nsanitized response body:\n" + SecretLeakScanner.Sanitize(chatBody, secrets));
        Assert.Contains("\"usage\"", chatBody, StringComparison.Ordinal);

        // A wrong key for the same caller: refused 401, and the refusal document
        // is CredProx's own.
        var wrong = NewRequest(HttpMethod.Post, "/gateway/v1/chat/completions", _callerKey + "x");
        wrong.Content = new StringContent(
            $"{{\"model\":\"{model}\",\"max_tokens\":1,\"messages\":[{{\"role\":\"user\",\"content\":\"ping\"}}]}}",
            Encoding.UTF8,
            "application/json");
        var wrongResponse = await client.SendAsync(wrong);
        var wrongBody = await wrongResponse.Content.ReadAsStringAsync();
        var wrongStatus = (int)wrongResponse.StatusCode;
        Assert.True(
            wrongStatus == 401,
            $"the wrong caller key was not refused with 401 but with {wrongStatus}; sanitized response body:\n" +
            SecretLeakScanner.Sanitize(wrongBody, secrets));

        // The right key on an operation its list does not name (the models read
        // under the same route prefix): refused 403 at the gate.
        var foreign = await client.SendAsync(NewRequest(HttpMethod.Get, "/gateway/v1/models", _callerKey));
        var foreignBody = await foreign.Content.ReadAsStringAsync();
        var foreignStatus = (int)foreign.StatusCode;
        Assert.True(
            foreignStatus == 403,
            $"the foreign operation was not refused with 403 but with {foreignStatus}; sanitized response body:\n" +
            SecretLeakScanner.Sanitize(foreignBody, secrets));

        // Metering on the real model's own usage report, waited and settled as in
        // M53: the audit names this caller on completion, the console exporter
        // carries both openai token counters above zero.
        await LiveHosts.WaitUntilAsync(
            () => Task.FromResult(LiveHosts.ContainsOnOneLine(
                host.Stdout, "credprox.proxied_call: caller=live-gateway", "method=POST")),
            "the metered POST never reached the audit recorder on completion",
            host,
            secrets,
            30);
        await LiveHosts.WaitUntilAsync(
            () => Task.FromResult(
                LiveHosts.CounterValue(host.Stdout, "credprox.usage.input_tokens") > 0
                && LiveHosts.CounterValue(host.Stdout, "credprox.usage.output_tokens") > 0),
            "the openai usage counters never showed non-zero values on the console exporter",
            host,
            secrets,
            30);
        var inputs = LiveHosts.CounterValue(host.Stdout, "credprox.usage.input_tokens");
        var outputs = LiveHosts.CounterValue(host.Stdout, "credprox.usage.output_tokens");

        var log = host.Stdout + host.Stderr;
        Assert.Empty(SecretLeakScanner.FindLeaks(log, secrets));
        Assert.DoesNotContain(_callerKey, log, StringComparison.Ordinal);
        _output.WriteLine(
            $"OBSERVED foundrylocal_gateway_chat={chatStatus} foundrylocal_gateway_wrongkey={wrongStatus} foundrylocal_gateway_foreign={foreignStatus} input_tokens={inputs} output_tokens={outputs}");
    }

    private static HttpRequestMessage NewRequest(HttpMethod method, string path, string callerKey)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.Add("X-CredProx-Key", callerKey);
        return request;
    }
}
