using System.Text;
using System.Text.RegularExpressions;
using Xunit;
using Xunit.Abstractions;

namespace CredProx.LiveTests;

// The azureopenai live leg: the sample host AS SHIPPED, its destination repointed at
// the owner's real resource, its Entra token taken through the unchanged
// DefaultAzureCredential chain (the az sign-in the runner already proved) — no stub
// steering, no API key anywhere. One tiny chat is the run's only billable call; its
// usage object is what the route's openai metering format parses offline. The second
// half spends nothing: a deployment the shipped chat-app rule does not admit must be
// refused 403 at the gate before a single byte reaches the resource — the differential
// that proves the 200 rode the allow-list, not an open door.
[Trait("Layer", "Live")]
public sealed class AzureOpenAILiveTests : IAsyncLifetime
{
    // The sample's own configured port; the live leg runs one host per port and the
    // cross-sample port-uniqueness guard covers the shipped config.
    private const string HostUrl = "http://localhost:5108";
    private const int HostPort = 5108;

    // The sample's shipped throwaway demo caller key (its hash ships in the sample's
    // own appsettings); the chat-app caller's Operations rule is the deployment
    // allow-list. Demo value, not a secret — but still sanitized from host output.
    private const string ChatAppKey = "azureopenai-demo-chat-key-1";

    // The chat's one named request version. The body sends max_completion_tokens,
    // which the API version lifecycle guide shows arrived in 2024-09-01-preview -
    // a release older than that cannot carry the body this cell ships. 2024-10-21
    // is the GA release of the data-plane inference specification that the
    // reference page names. The cap is documented on the current chat view (learn
    // renders that page for the dated view value), so what proves THIS release
    // accepts the body is the first live run, which dials exactly this version.
    // It is also the release the runner's probe dials.
    private const string ChatApiVersion = "2024-10-21";

    private readonly ITestOutputHelper _output;
    private LiveHosts.RunningHost? _host;

    public AzureOpenAILiveTests(ITestOutputHelper output) => _output = output;

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

    [AzureOpenAILiveFact]
    public async Task LiveChat_OneTinyCall_ShipsUsage_NonAdmittedDeploymentRefused()
    {
        var endpoint = Environment.GetEnvironmentVariable("AZURE_OPENAI_ENDPOINT") ?? "";
        Assert.True(
            AzureOpenAIEnv.IsPlausibleEndpoint(endpoint),
            "AZURE_OPENAI_ENDPOINT is missing or wrong-shape in the live env - the runner exports it to its own azureopenai leg only");
        var deployment = Environment.GetEnvironmentVariable("AZURE_OPENAI_DEPLOYMENT") ?? "gpt-4o";
        var secrets = new List<string> { ChatAppKey };
        var env = new Dictionary<string, string>
        {
            ["Urls"] = HostUrl,
            ["CredProx__Destinations__azureopenai__Template"] = endpoint,
            ["ReverseProxy__Clusters__azureopenai__Destinations__azureopenai__Address"] = endpoint.TrimEnd('/') + "/",
            // The shipped chat-app rule admits only gpt-4o; without this override any
            // AZURE_OPENAI_DEPLOYMENT the runner exports is 403'd by the very rule the
            // cell claims to dial through (the offline 403 half of this cell proves the
            // gate enforces that rule). The refused call stays OUTSIDE the override, so
            // the 403 half still proves the allow-list decided, not this entry.
            ["CredProx__Callers__chat-app__Operations__0__Paths__0"] = $"/aoai/openai/deployments/{deployment}/**",
        };
        var bin = LiveHosts.LocateBin(Path.Combine("samples", "AzureOpenAI"), "AzureOpenAI.dll");
        LiveHosts.EnsurePortsFree(HostPort);
        _host = new LiveHosts.RunningHost(LiveHosts.Start(bin, "AzureOpenAI.dll", env));
        var host = _host;
        using var client = new HttpClient { BaseAddress = new Uri(HostUrl), Timeout = TimeSpan.FromSeconds(120) };
        using var probe = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        await LiveHosts.WaitUntilAsync(
            async () =>
            {
                if (host.Process.HasExited)
                {
                    throw new InvalidOperationException(
                        $"the AzureOpenAI host exited early (code {host.Process.ExitCode}):\n" +
                        SecretLeakScanner.Sanitize(host.Stderr, secrets));
                }

                try
                {
                    // readiness must not authenticate or proxy: not a route.
                    using var _ = await probe.GetAsync(HostUrl + "/readiness-probe");
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
            "the AzureOpenAI host never answered its port",
            host,
            secrets,
            90);

        // The model live.env names today is a reasoning model. Microsoft's Azure
        // OpenAI reasoning how-to lists max_tokens as unsupported for that family
        // and bills reasoning tokens INSIDE max_completion_tokens, so the cap has
        // to leave room for them. Which reasoning_effort values a given model
        // accepts is UNVERIFIED, so the cell omits the field entirely: omission
        // is always accepted, and the cap bounds the cost on its own. A cap that
        // still ends up too short answers 200 with a usage line and possibly
        // empty content - nothing here reads the content, so the asserts hold
        // whichever way the reasoning goes. The shape is pinned offline in
        // AzureOpenAIScaffoldTests.
        var body = """{"messages":[{"role":"user","content":"ping"}],"max_completion_tokens":2000}""";
        var chat = await client.SendAsync(
            Keyed(HttpMethod.Post, $"/aoai/openai/deployments/{deployment}/chat/completions?api-version={ChatApiVersion}", ChatAppKey, body));
        var chatBody = await chat.Content.ReadAsStringAsync();
        var chatStatus = (int)chat.StatusCode;
        Assert.True(
            chatStatus == 200,
            $"the tiny chat answered {chatStatus} instead of 200; sanitized response body:\n" +
            SecretLeakScanner.Sanitize(chatBody, secrets));
        var usageMatch = Regex.Match(chatBody, "\"total_tokens\"\\s*:\\s*([0-9]+)");
        Assert.True(
            usageMatch.Success && int.Parse(usageMatch.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture) > 0,
            "the response carries no usage.total_tokens > 0 - the metered shape the openai usage format parses; sanitized:\n" +
            SecretLeakScanner.Sanitize(chatBody, secrets));

        // The half that spends nothing: a deployment the chat-app rule does not admit
        // is refused 403 at the gate — before the dialer, so the resource never sees
        // it. Pairs with the 200 above to prove the allow-list decided, not luck.
        var refused = await client.SendAsync(
            Keyed(HttpMethod.Post, $"/aoai/openai/deployments/credprox-not-admitted/chat/completions?api-version={ChatApiVersion}", ChatAppKey, body));
        var refusedStatus = (int)refused.StatusCode;
        Assert.True(
            refusedStatus == 403,
            $"the non-admitted deployment answered {refusedStatus} instead of 403 at the gate:\n" +
            SecretLeakScanner.Sanitize(await refused.Content.ReadAsStringAsync(), secrets));
        // The runner builds this vendor's PASS line by grepping the leg log for
        // "OBSERVED " — without this line a spent run records FAIL after the
        // spend. Numbers only, the same sanitising rule the other vendors'
        // live cells use.
        _output.WriteLine(
            $"OBSERVED azureopenai_chat={chatStatus} azureopenai_refused={refusedStatus} total_tokens={usageMatch.Groups[1].Value}");
    }

    private static HttpRequestMessage Keyed(HttpMethod method, string path, string key, string? json = null)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.TryAddWithoutValidation("X-CredProx-Key", key);
        if (json is not null)
        {
            request.Content = new StringContent(json, Encoding.UTF8, "application/json");
        }

        return request;
    }
}
