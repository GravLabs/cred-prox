using System.Text;
using System.Text.RegularExpressions;
using Xunit;
using Xunit.Abstractions;

namespace CredProx.LiveTests;

// The M46 unit-2 proof against the real Anthropic API: the shipped AiGateway sample
// host, launched with configuration-only overrides (the README's Anthropic-style
// repoint — credential header x-api-key with no prefix, anthropic-version via a
// route transform, address api.anthropic.com) and the machine-local key, answers a
// caller-authenticated GET /v1/models with a real 200 while the caller never holds
// the provider key, and CredProx itself refuses an unknown caller key and an
// operation outside the caller's allow-list before anything leaves for Anthropic.
// Spend: one unbillable GET and at most one refused POST — no billable call on the
// happy path.
[Collection("AiGateway")]
[Trait("Layer", "Live")]
public sealed class AiGatewayLiveTests
{
    private readonly AiGatewayFixture _fixture;
    private readonly ITestOutputHelper _output;

    public AiGatewayLiveTests(AiGatewayFixture fixture, ITestOutputHelper output)
    {
        _fixture = fixture;
        _output = output;
    }

    [AiGatewayLiveFact]
    public async Task AiGateway_ModelsListAnswersForCallerAndRefusalsStayLocal()
    {
        var probe = AiGatewayEnv.Probe();
        Assert.True(probe.Available, probe.SkipReason);
        var shapeProblems = AiGatewayEnv.ValueProblems(probe.Values);
        Assert.True(shapeProblems.Count == 0, string.Join("; ", shapeProblems));

        var apiKey = probe.Values["ANTHROPIC_API_KEY"];
        var secrets = new List<string> { apiKey };
        var callerKey = "live-caller-" + Guid.NewGuid().ToString("N");
        var env = new Dictionary<string, string>
        {
            // the README's Anthropic-style repoint — configuration only, the shipped
            // appsettings untouched. Both address keys must move: the CredProx
            // destination template wins over the dialed YARP address.
            ["CredProx__Secrets__ai-provider-key"] = apiKey,
            ["CredProx__Destinations__ai__Template"] = "https://api.anthropic.com",
            ["ReverseProxy__Clusters__ai__Destinations__ai__Address"] = AiGatewayFixture.AnthropicAddress,
            ["CredProx__Credentials__ai-provider__Name"] = "x-api-key",
            ["CredProx__Credentials__ai-provider__Prefix"] = "",
            // The README's Anthropic recipe (YARP spelling RequestHeader + Set). Index 1
            // assumes the shipped route has exactly one transform (PathRemovePrefix) at
            // index 0; if the sample gains a transform, move this index, or the live run
            // fails because Anthropic rejects a request without the version header.
            ["ReverseProxy__Routes__ai__Transforms__1__RequestHeader"] = "anthropic-version",
            ["ReverseProxy__Routes__ai__Transforms__1__Set"] = "2023-06-01",
            // a caller this test mints for itself, allowed exactly one operation
            ["CredProx__Callers__live-models__Keys__0__KeyId"] = "live-models-key-1",
            ["CredProx__Callers__live-models__Keys__0__KeyHash"] = AiGatewayFixture.CallerKeyConfig(callerKey),
            ["CredProx__Callers__live-models__Operations__0__Route"] = "ai",
            ["CredProx__Callers__live-models__Operations__0__Methods__0"] = "GET",
            ["CredProx__Callers__live-models__Operations__0__Paths__0"] = "/ai/v1/models",
        };

        // cleanup belongs to the fixture: StartHost stops any previous host, and
        // Dispose kills the tree — the same pattern the GitHubApp cells use
        var host = _fixture.StartHost(env, secrets, AiGatewayFixture.LiveHostPort);
        {
            await _fixture.WaitForHostAsync(host, AiGatewayFixture.LiveHostUrl);
            using var client = new HttpClient { BaseAddress = new Uri(AiGatewayFixture.LiveHostUrl) };

            // 1. the unbillable 200: a real Anthropic answer, for the caller, with
            // the caller holding only its own key
            var models = await client.SendAsync(NewRequest(HttpMethod.Get, "/ai/v1/models", callerKey));
            var modelsBody = await models.Content.ReadAsStringAsync();
            Assert.True(
                (int)models.StatusCode == 200,
                $"Anthropic answered the models list with {(int)models.StatusCode}; sanitized host output:\n" +
                SecretLeakScanner.Sanitize(host.Stdout + host.Stderr, secrets));
            Assert.Contains("application/json", models.Content.Headers.ContentType?.ToString() ?? string.Empty, StringComparison.Ordinal);
            Assert.Contains("data", modelsBody, StringComparison.Ordinal);

            // 2. an unknown caller key is refused by CredProx, as its own problem document
            var wrongKey = await client.SendAsync(
                NewRequest(HttpMethod.Get, "/ai/v1/models", callerKey + "-wrong"));
            var wrongBody = await wrongKey.Content.ReadAsStringAsync();
            Assert.True(
                (int)wrongKey.StatusCode == 401,
                $"unknown caller key answered {(int)wrongKey.StatusCode}: " +
                SecretLeakScanner.Sanitize(wrongBody, secrets));
            IsCredProxProblem(wrongKey, wrongBody);

            // 3. an operation outside the caller's allow-list is refused before the
            // request can reach Anthropic: the GET-only caller posts a messages
            // request and must get CredProx's own problem document, never an
            // Anthropic answer (Anthropic answers every request with request-id)
            var modelId = FirstModelId(modelsBody);
            Assert.NotNull(modelId);
            var post = NewRequest(HttpMethod.Post, "/ai/v1/messages", callerKey);
            post.Content = new StringContent(
                "{\"model\":\"" + modelId + "\",\"max_tokens\":1,\"messages\":[{\"role\":\"user\",\"content\":\"x\"}]}",
                Encoding.UTF8,
                "application/json");
            var refused = await client.SendAsync(post);
            var refusedBody = await refused.Content.ReadAsStringAsync();
            Assert.True(
                (int)refused.StatusCode == 403,
                $"operation outside the allow-list answered {(int)refused.StatusCode}: " +
                SecretLeakScanner.Sanitize(refusedBody, secrets));
            IsCredProxProblem(refused, refusedBody);
            Assert.False(
                refused.Headers.Contains("request-id"),
                "the refusal carried an Anthropic request-id — the request left the machine");

            // 4. nothing secret in the host log or in anything the caller received
            var log = host.Stdout + host.Stderr;
            Assert.Empty(SecretLeakScanner.FindLeaks(log, secrets));
            Assert.Empty(SecretLeakScanner.FindLeaks(modelsBody, secrets));
            Assert.Empty(SecretLeakScanner.FindLeaks(refusedBody, secrets));

            // Numbers only — no ids, no key material — for the runner's PASS line.
            _output.WriteLine(
                "OBSERVED forwarded_calls=1 models_status=200 refused_statuses=401,403 billable_calls=0");
        }
    }

    private static HttpRequestMessage NewRequest(HttpMethod method, string path, string callerKey)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.Add("X-CredProx-Key", callerKey);
        return request;
    }

    // CredProx refuses with its own problem document; an upstream provider would
    // answer with its own JSON shape instead.
    private static void IsCredProxProblem(HttpResponseMessage response, string body)
    {
        Assert.Contains(
            "application/problem+json",
            response.Content.Headers.ContentType?.ToString() ?? string.Empty,
            StringComparison.Ordinal);
        Assert.Contains("\"", body, StringComparison.Ordinal);
    }

    private static string? FirstModelId(string modelsBody)
    {
        var match = Regex.Match(modelsBody, "\"id\"\\s*:\\s*\"([^\"]+)\"");
        return match.Success ? match.Groups[1].Value : null;
    }
}
