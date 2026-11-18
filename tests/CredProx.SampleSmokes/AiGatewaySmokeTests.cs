using System.Diagnostics;
using System.Text;
using Xunit;

namespace CredProx.SampleSmokes;

// Offline cells for the AiGateway sample: the gateway host drives the full proxy path
// against the provider stand-in — caller keys in, injected provider key out, per-caller
// allow-lists and budgets, cluster throttle, streaming SSE passthrough, response
// scrubbing and audit — exactly as it would against a real provider.
[Collection("AiGateway")]
public class AiGatewaySmokeTests(AiGatewayFixture fixture)
{
    [Fact]
    [Trait("Sample", "AiGateway")]
    public async Task KeylessCall_IsRefusedAtTheGateway_ProviderNeverCalled()
    {
        var host = fixture.StartHost();
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(AiGatewayFixture.HostUrl) };
        var before = await fixture.CallsAsync();
        var response = await client.PostAsync("/ai/v1/chat/completions", Json());
        var after = await fixture.CallsAsync();

        Assert.Equal(401, (int)response.StatusCode);
        Assert.Equal(0, after - before); // refused at the gateway; nothing reached the provider
    }

    [Fact]
    [Trait("Sample", "AiGateway")]
    public async Task InjectedProviderKey_IsWitnessedAtTheProvider_RedactedForTheCaller()
    {
        var host = fixture.StartHost();
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(AiGatewayFixture.HostUrl) };
        var response = await client.PostAsync("/ai/v1/chat/completions", KeyedJson(AiGatewayFixture.ChatAppKey));
        var body = await response.Content.ReadAsStringAsync();

        // The stand-in only answers 200 when it saw the injected bearer key; the response
        // scrubber removes that same key from the echo the caller receives.
        Assert.True(response.IsSuccessStatusCode, $"chat call failed: {(int)response.StatusCode} {body}\n{host.Stderr}");
        Assert.Contains("Bearer [redacted]", body, StringComparison.Ordinal);
        Assert.DoesNotContain(AiGatewayFixture.ProviderKey, body, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Sample", "AiGateway")]
    public async Task SseStream_DeliversEventsAsWritten_AndScrubbedPerEvent()
    {
        var host = fixture.StartHost();
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(AiGatewayFixture.HostUrl) };
        var start = Stopwatch.GetTimestamp();
        using var response = await client.SendAsync(
            KeyedRequest("/ai/v1/messages", AiGatewayFixture.ChatAppKey, accept: "text/event-stream"),
            HttpCompletionOption.ResponseHeadersRead);
        var firstEventMs = -1.0;
        var secondEventMs = -1.0;
        var firstDataLine = "";
        if (response.IsSuccessStatusCode)
        {
            await using var stream = await response.Content.ReadAsStreamAsync();
            using var reader = new StreamReader(stream, Encoding.UTF8);
            var seenData = 0;
            while (await reader.ReadLineAsync() is { } line)
            {
                if (!line.StartsWith("data: ", StringComparison.Ordinal))
                {
                    continue;
                }

                seenData++;
                var ms = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
                if (seenData == 1)
                {
                    firstEventMs = ms;
                    firstDataLine = line;
                }
                else
                {
                    secondEventMs = ms;
                    break;
                }
            }
        }

        Assert.True(
            response.IsSuccessStatusCode && response.Content.Headers.ContentType?.MediaType == "text/event-stream",
            $"SSE call expected 200 text/event-stream, got {(int)response.StatusCode} {response.Content.Headers.ContentType}\n{host.Stderr}");
        // The provider flushes event 1 immediately and event 2 400 ms later. A buffering
        // proxy — or a scrubber waiting on the whole body — delivers both together.
        Assert.True(firstEventMs >= 0 && firstEventMs < 300,
            $"first SSE event expected < 300 ms (streaming), got {firstEventMs:0} ms — the response was buffered");
        Assert.True(secondEventMs - firstEventMs >= 200,
            $"second SSE event expected >= 200 ms after the first (provider delay 400 ms), got {secondEventMs - firstEventMs:0} ms");
        // Event 1 echoes the Authorization header the provider saw: inside the stream the
        // caller must already see it redacted, not the key.
        Assert.Contains("Bearer [redacted]", firstDataLine, StringComparison.Ordinal);
        Assert.DoesNotContain(AiGatewayFixture.ProviderKey, firstDataLine, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Sample", "AiGateway")]
    public async Task ChatCaller_OnFilesRouteIsForbidden_OpsCallerPasses()
    {
        var host = fixture.StartHost();
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(AiGatewayFixture.HostUrl) };
        var blocked = await client.PostAsync("/ai/v1/files", KeyedJson(AiGatewayFixture.ChatAppKey));
        var blockedBody = await blocked.Content.ReadAsStringAsync();
        Assert.Equal(403, (int)blocked.StatusCode);
        Assert.Contains("credprox.operation_not_allowed", blockedBody, StringComparison.Ordinal);

        // Let the cluster's 2-permits/s window refill so the ops call measures the
        // allow-list, not the limiter (the 403 above needed no permit).
        await Task.Delay(1100);
        var allowed = await client.PostAsync("/ai/v1/files", KeyedJson(AiGatewayFixture.OpsAppKey));
        var allowedBody = await allowed.Content.ReadAsStringAsync();
        Assert.True(allowed.IsSuccessStatusCode,
            $"ops call on /ai/v1/files failed: {(int)allowed.StatusCode} {allowedBody}\n{host.Stderr}");
        Assert.Contains("Bearer [redacted]", allowedBody, StringComparison.Ordinal);
        Assert.DoesNotContain(AiGatewayFixture.ProviderKey, allowedBody, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Sample", "AiGateway")]
    public async Task ClusterThrottle_RefusesPartOfABurst()
    {
        var host = fixture.StartHost();
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(AiGatewayFixture.HostUrl) };
        await Task.Delay(1100); // a fresh window for the burst
        var statuses = await Task.WhenAll(Enumerable.Range(0, 6).Select(async _ =>
        {
            using var response = await client.PostAsync(
                "/ai/v1/chat/completions", KeyedJson(AiGatewayFixture.OpsAppKey));
            return (int)response.StatusCode;
        }));

        Assert.True(statuses.Count(code => code == 429) >= 1,
            $"burst of 6 against 2 permits/s expected >= 1 throttled 429, got [{string.Join(",", statuses)}]\n{host.Stderr}");
    }

    [Fact]
    [Trait("Sample", "AiGateway")]
    public async Task CallerBudget_RefusesTheThirdCall_WhileOtherCallersKeepTheirs()
    {
        var host = fixture.StartHost();
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(AiGatewayFixture.HostUrl) };
        await Task.Delay(1100);
        int? thirdStatus = null;
        string? thirdBody = null;
        string? retryAfter = null;
        for (var i = 0; i < 3; i++)
        {
            using var response = await client.PostAsync(
                "/ai/v1/chat/completions", KeyedJson(AiGatewayFixture.BatchAppKey));
            if (i == 2)
            {
                thirdStatus = (int)response.StatusCode;
                thirdBody = await response.Content.ReadAsStringAsync();
                retryAfter = response.Headers.RetryAfter?.ToString();
            }
        }

        Assert.Equal(429, thirdStatus);
        Assert.Contains("credprox.caller_throttled", thirdBody, StringComparison.Ordinal);
        Assert.False(string.IsNullOrEmpty(retryAfter), $"budget 429 expected a Retry-After header, got '{retryAfter}'");

        // The budget is the caller's own: the other callers keep their full budget even
        // while batch-app is exhausted for the minute. (The 1 s cluster window refills
        // too, so this call measures per-app isolation, not the shared limiter.)
        await Task.Delay(1100);
        using var chatAfterBudget = await client.PostAsync(
            "/ai/v1/chat/completions", KeyedJson(AiGatewayFixture.ChatAppKey));
        Assert.True(chatAfterBudget.IsSuccessStatusCode,
            $"chat caller expected 200 while batch-app is exhausted, got {(int)chatAfterBudget.StatusCode}");
    }

    [Fact]
    [Trait("Sample", "AiGateway")]
    public async Task Audit_RecordsCallsByCaller_NoKeyValuesAnywhere()
    {
        var host = fixture.StartHost();
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(AiGatewayFixture.HostUrl) };
        using var chatCall = await client.PostAsync(
            "/ai/v1/chat/completions", KeyedJson(AiGatewayFixture.ChatAppKey));
        using var blockedCall = await client.PostAsync(
            "/ai/v1/files", KeyedJson(AiGatewayFixture.ChatAppKey));
        await Task.Delay(1100); // fresh cluster window so the ops call is not throttled
        using var opsCall = await client.PostAsync(
            "/ai/v1/files", KeyedJson(AiGatewayFixture.OpsAppKey));
        Assert.True(chatCall.IsSuccessStatusCode && (int)blockedCall.StatusCode == 403 && opsCall.IsSuccessStatusCode,
            $"setup calls failed: chat={(int)chatCall.StatusCode} blocked={(int)blockedCall.StatusCode} ops={(int)opsCall.StatusCode}\n{host.Stderr}");

        // Audit records land on the gateway's console (Information under CredProx.Audit).
        await AiGatewayFixture.WaitUntilAsync(
            () => Task.FromResult(host.Stdout.Contains("caller=ops-app", StringComparison.Ordinal)),
            $"audit line for ops-app never appeared:\n{host.Stdout}");

        Assert.Contains("credprox.proxied_call", host.Stdout, StringComparison.Ordinal);
        Assert.Contains("caller=chat-app", host.Stdout, StringComparison.Ordinal);
        Assert.Contains("credprox.rejected_call", host.Stdout, StringComparison.Ordinal);
        var output = host.Stdout + host.Stderr;
        Assert.DoesNotContain(AiGatewayFixture.ProviderKey, output, StringComparison.Ordinal);
        Assert.DoesNotContain(AiGatewayFixture.ChatAppKey, output, StringComparison.Ordinal);
        Assert.DoesNotContain(AiGatewayFixture.OpsAppKey, output, StringComparison.Ordinal);
        Assert.DoesNotContain(AiGatewayFixture.BatchAppKey, output, StringComparison.Ordinal);
    }

    private static StringContent Json() => new("""{"model":"demo"}""", Encoding.UTF8, "application/json");

    private static StringContent KeyedJson(string callerKey)
    {
        var content = Json();
        content.Headers.Add("X-CredProx-Key", callerKey);
        return content;
    }

    private static HttpRequestMessage KeyedRequest(string path, string callerKey, string? accept = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = Json() };
        request.Headers.Add("X-CredProx-Key", callerKey);
        if (accept is not null)
        {
            request.Headers.Accept.ParseAdd(accept);
        }

        return request;
    }
}
