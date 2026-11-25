using System.Text;
using System.Text.RegularExpressions;
using Xunit;
using Xunit.Abstractions;

namespace CredProx.LiveTests;

// A cell that spends ONE tiny billable Anthropic call through the FoundryLocalCloud
// sample's cloud route — opt-in only, like the M53 billable cell: the shared runner
// gate (marker naming the foundrylocal leg, marker-only — this path reaches Entra
// nowhere), the explicit go-ahead CREDPROX_M54_BILLABLE=1 (owner-approved for M54),
// and an ANTHROPIC_API_KEY in the live env. Any one missing skips loudly; a bare or
// filtered dotnet test never carries the marker even with the other two present.
public sealed class FoundryLocalCloudBillableLiveFactAttribute : FactAttribute, ILiveFactAttribute
{
    public FoundryLocalCloudBillableLiveFactAttribute()
    {
        var problems = LiveRunnerGate.Problems(
            FoundryLocalEnv.Vendor,
            Environment.GetEnvironmentVariable(LiveRunnerGate.RunnerVendorVariable));
        if (problems.Count > 0)
        {
            Skip = LiveRunnerGate.SkipReason(problems);
            return;
        }
        if (Environment.GetEnvironmentVariable("CREDPROX_M54_BILLABLE") != "1")
        {
            Skip = "billable by design: set CREDPROX_M54_BILLABLE=1 to spend one tiny Anthropic messages call (owner-approved for M54, the lead runs it)";
        }
        else if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("ANTHROPIC_API_KEY")))
        {
            Skip = "CREDPROX_M54_BILLABLE=1 is set but ANTHROPIC_API_KEY is missing from the live env";
        }
    }
}

// The cloud leg of the local-plus-cloud sample, all on the runner's single model
// predicate: the billable dual caller reaches Anthropic with 200 on its own
// messages call (the free models list picks the model id, as in M53), the
// local-only caller is refused 403 on the cloud route by its operation list yet
// still reaches the local route with the runner-validated model — proof the
// refusal is the route choice and not a dead path. One billable call, four
// requests total.
[Trait("Layer", "Live")]
public sealed class FoundryLocalCloudLiveTests : IAsyncLifetime
{
    // The sample's own configured port; the live leg runs one host per port and
    // the cross-sample port-uniqueness guard covers the shipped config.
    private const string CloudUrl = "http://localhost:5106";
    private const int CloudPort = 5106;
    private readonly ITestOutputHelper _output;
    private string _dualKey = "";
    private string _localKey = "";
    private LiveHosts.RunningHost? _host;

    public FoundryLocalCloudLiveTests(ITestOutputHelper output) => _output = output;

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

    [FoundryLocalCloudBillableLiveFact]
    public async Task CloudLeg_BillableCallPasses_CloudOperationRefusal_KeepsLocalRoute()
    {
        var anthropicKey = Environment.GetEnvironmentVariable("ANTHROPIC_API_KEY") ?? "";
        Assert.True(anthropicKey.Length > 0, "ANTHROPIC_API_KEY is empty in the live env");
        var model = Environment.GetEnvironmentVariable("FOUNDRY_LOCAL_MODEL");
        Assert.False(
            string.IsNullOrWhiteSpace(model),
            "FOUNDRY_LOCAL_MODEL is not exported - the foundrylocal runner leg validates and exports one local model id before it creates anything; the local-route leg of this cell calls exactly that id");
        _dualKey = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
        _localKey = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
        var secrets = new List<string> { _dualKey, _localKey, anthropicKey };
        var env = new Dictionary<string, string>
        {
            ["Urls"] = CloudUrl,
            ["CredProx__Destinations__foundry__Template"] = FoundryLocalEnv.ModelBaseUrl,
            ["ReverseProxy__Clusters__foundry__Destinations__foundry__Address"] = FoundryLocalEnv.ModelBaseUrl + "/",
            ["CredProx__Secrets__anthropic-cloud-key"] = anthropicKey,
            ["CredProx__Callers__live-cloud__Keys__0__KeyId"] = "live-cloud-key-1",
            ["CredProx__Callers__live-cloud__Keys__0__KeyHash"] = AiGatewayFixture.CallerKeyConfig(_dualKey),
            ["CredProx__Callers__live-cloud__Operations__0__Route"] = "foundry",
            ["CredProx__Callers__live-cloud__Operations__0__Methods__0"] = "POST",
            ["CredProx__Callers__live-cloud__Operations__0__Paths__0"] = "/gateway/v1/chat/**",
            ["CredProx__Callers__live-cloud__Operations__1__Route"] = "anthropic",
            ["CredProx__Callers__live-cloud__Operations__1__Methods__0"] = "POST",
            ["CredProx__Callers__live-cloud__Operations__1__Paths__0"] = "/cloud/v1/messages/**",
            // the free models list on the cloud route picks the model id (as in
            // M53) so no Anthropic model name is ever a copied constant here
            ["CredProx__Callers__live-cloud__Operations__2__Route"] = "anthropic",
            ["CredProx__Callers__live-cloud__Operations__2__Methods__0"] = "GET",
            ["CredProx__Callers__live-cloud__Operations__2__Paths__0"] = "/cloud/v1/models",
            ["CredProx__Callers__live-local__Keys__0__KeyId"] = "live-local-key-1",
            ["CredProx__Callers__live-local__Keys__0__KeyHash"] = AiGatewayFixture.CallerKeyConfig(_localKey),
            ["CredProx__Callers__live-local__Operations__0__Route"] = "foundry",
            ["CredProx__Callers__live-local__Operations__0__Methods__0"] = "POST",
            ["CredProx__Callers__live-local__Operations__0__Paths__0"] = "/gateway/v1/chat/**",
        };
        var bin = LiveHosts.LocateBin(Path.Combine("samples", "FoundryLocalCloud"), "FoundryLocalCloud.dll");
        LiveHosts.EnsurePortsFree(CloudPort);
        _host = new LiveHosts.RunningHost(LiveHosts.Start(bin, "FoundryLocalCloud.dll", env));
        var host = _host;
        using var client = new HttpClient { BaseAddress = new Uri(CloudUrl), Timeout = TimeSpan.FromSeconds(120) };
        using var probe = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        await LiveHosts.WaitUntilAsync(
            async () =>
            {
                if (host.Process.HasExited)
                {
                    throw new InvalidOperationException(
                        $"the FoundryLocalCloud host exited early (code {host.Process.ExitCode}):\n" +
                        SecretLeakScanner.Sanitize(host.Stderr, secrets));
                }
                try
                {
                    using var _ = await probe.GetAsync(CloudUrl + "/live-probe-not-a-route");
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
            "the cloud sample host never answered its port",
            host,
            secrets,
            90);

        // The free models list picks the Anthropic model id (no tokens, nothing
        // billable — the M53 discipline).
        var models = await client.SendAsync(Keyed(HttpMethod.Get, "/cloud/v1/models", _dualKey));
        var modelsBody = await models.Content.ReadAsStringAsync();
        var modelsStatus = (int)models.StatusCode;
        Assert.True(
            modelsStatus == 200,
            $"the cloud models list answered {modelsStatus} instead of 200; sanitized response body:\n" +
            SecretLeakScanner.Sanitize(modelsBody, secrets));
        var modelMatch = Regex.Match(modelsBody, "\"id\"\\s*:\\s*\"([^\"]+)\"");
        Assert.True(
            modelMatch.Success,
            $"the cloud models list carried no model id; sanitized response body:\n" +
            SecretLeakScanner.Sanitize(modelsBody, secrets));

        // THE one tiny billable call: max_tokens 1, one-word prompt.
        var billable = Keyed(HttpMethod.Post, "/cloud/v1/messages", _dualKey);
        billable.Content = new StringContent(
            $"{{\"model\":\"{modelMatch.Groups[1].Value}\",\"max_tokens\":1,\"messages\":[{{\"role\":\"user\",\"content\":\"hi\"}}]}}",
            Encoding.UTF8,
            "application/json");
        var billableResponse = await client.SendAsync(billable);
        var billableBody = await billableResponse.Content.ReadAsStringAsync();
        var billableStatus = (int)billableResponse.StatusCode;
        Assert.True(
            billableStatus == 200,
            $"the dual caller's billable cloud call answered {billableStatus}; sanitized host output:\n" +
            SecretLeakScanner.Sanitize(host.Stdout + host.Stderr, secrets) +
            "\nsanitized response body:\n" + SecretLeakScanner.Sanitize(billableBody, secrets));
        Assert.Contains("\"usage\"", billableBody, StringComparison.Ordinal);

        // The local-only caller on the cloud route: its operation list does not
        // name the cloud route, so the gate itself refuses 403 - config chose
        // that, nothing upstream did.
        var refused = Keyed(HttpMethod.Post, "/cloud/v1/messages", _localKey);
        refused.Content = new StringContent(
            "{\"model\":\"none\",\"max_tokens\":1,\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}",
            Encoding.UTF8,
            "application/json");
        var refusedResponse = await client.SendAsync(refused);
        var refusedBody = await refusedResponse.Content.ReadAsStringAsync();
        var refusedStatus = (int)refusedResponse.StatusCode;
        Assert.True(
            refusedStatus == 403,
            $"the local-only caller was not refused on the cloud route with 403 but with {refusedStatus}; sanitized response body:\n" +
            SecretLeakScanner.Sanitize(refusedBody, secrets));

        // ...and the same caller still reaches the local route with the
        // runner-validated model - the refusal is this route, not this caller
        // being dead weight.
        var local = Keyed(HttpMethod.Post, "/gateway/v1/chat/completions", _localKey);
        local.Content = new StringContent(
            $"{{\"model\":\"{model}\",\"max_tokens\":1,\"messages\":[{{\"role\":\"user\",\"content\":\"ping\"}}]}}",
            Encoding.UTF8,
            "application/json");
        var localResponse = await client.SendAsync(local);
        var localBody = await localResponse.Content.ReadAsStringAsync();
        var localStatus = (int)localResponse.StatusCode;
        Assert.True(
            localStatus == 200,
            $"the local-only caller did not reach the local route with 200 but with {localStatus}; sanitized response body:\n" +
            SecretLeakScanner.Sanitize(localBody, secrets));

        var log = host.Stdout + host.Stderr;
        Assert.Empty(SecretLeakScanner.FindLeaks(log, secrets));
        Assert.DoesNotContain(_dualKey, log, StringComparison.Ordinal);
        Assert.DoesNotContain(_localKey, log, StringComparison.Ordinal);
        Assert.DoesNotContain(anthropicKey, log, StringComparison.Ordinal);
        _output.WriteLine(
            $"OBSERVED foundrylocal_cloud_billable={billableStatus} foundrylocal_cloud_refused={refusedStatus} foundrylocal_cloud_local={localStatus}");
    }

    private static HttpRequestMessage Keyed(HttpMethod method, string path, string callerKey)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.Add("X-CredProx-Key", callerKey);
        return request;
    }
}
