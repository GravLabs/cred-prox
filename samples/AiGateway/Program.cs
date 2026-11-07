using System.Diagnostics;
using System.Text;
using CredProx;
using CredProx.Testing;

// E13 (plan §6): AI provider gateway. Internal apps call CredProx with their own caller
// API key; CredProx injects the real provider key (StaticKey header) so the apps never
// hold it, enforces per-caller operation allow-lists (chat-only vs. unrestricted),
// throttles the provider cluster, and audits every call. The provider is stubbed
// in-process (--smoke): the stub checks the injected key and answers one endpoint with
// a delayed two-event SSE stream so the smoke can prove streaming passes through
// unbuffered — the timing assertion is why the stub is in-process rather than WireMock.
// The stub also echoes the Authorization header it received, and the response scrubber
// (M20) redacts the key in that echo — including inside SSE events, which scrub
// per-event and keep flowing (M22); the caller never sees the provider key anywhere.
const string ProviderKey = "sk-credprox-gateway-demo-key";
const string ChatAppKey = "a1c7e94b2d8f4705b6e3a9c1d4f802e7";
const string OpsAppKey = "5d92f6ac1e38b7042ca6e8f19b3d57e0";
const string BatchAppKey = "credprox-e13-batch-demo-key";

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCredProxTokenCache();
builder.Services.AddCredProxConfigurationSecrets(builder.Configuration);
builder.Services.AddCredProxBuiltInCredentials();
builder.Services.AddCredProxCredentials(builder.Configuration);
builder.Services.AddCredProxCallerAuthentication(builder.Configuration);
builder.Services.AddCredProxThrottling(builder.Configuration);
builder.Services.AddCredProxAudit(builder.Configuration);
builder.Services.AddRouting();

CapturedLogSink? logSink = null;
if (args.Contains("--smoke"))
{
    logSink = new CapturedLogSink();
    builder.Logging.AddProvider(logSink);
}

builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx(builder.Configuration);

builder.WebHost.UseUrls("http://localhost:5088");

var app = builder.Build();

// The provider stand-in. Every endpoint refuses requests that did not arrive with the
// injected key — the same check a real provider makes — and echoes what it saw.
app.MapPost("/v1/chat/completions", async (HttpContext context) =>
    await EchoKeyAsync(context, """{"object":"chat.completion"}"""));

app.MapPost("/v1/files", async (HttpContext context) =>
    await EchoKeyAsync(context, """{"object":"file"}"""));

app.MapPost("/admin/models", async (HttpContext context) =>
    await EchoKeyAsync(context, """{"object":"list"}"""));

// A streaming completion: two SSE events with a delay between them, flushed as written.
// A buffering proxy would deliver both events together after ~400 ms; a streaming one
// delivers the first immediately. The smoke measures exactly that.
app.MapPost("/v1/messages", async (HttpContext context) =>
{
    var authorization = context.Request.Headers.Authorization.ToString();
    if (authorization != $"Bearer {ProviderKey}")
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsync("""{"error":{"type":"authentication_error"}}""");
        return;
    }

    context.Response.ContentType = "text/event-stream";
    context.Response.Headers.CacheControl = "no-cache";
    await context.Response.WriteAsync("event: message\ndata: {\"index\":1}\n\n");
    await context.Response.Body.FlushAsync();
    await Task.Delay(400);
    await context.Response.WriteAsync("event: message\ndata: {\"index\":2}\n\n");
    await context.Response.Body.FlushAsync();
});

app.MapReverseProxy();

if (args.Contains("--smoke"))
{
    return await RunSmokeAsync(app, logSink!);
}

app.Run();
return 0;

static async Task EchoKeyAsync(HttpContext context, string resultJson)
{
    var authorization = context.Request.Headers.Authorization.ToString();
    if (authorization != $"Bearer {ProviderKey}")
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsync("""{"error":{"type":"authentication_error"}}""");
        return;
    }

    context.Response.ContentType = "application/json";
    await context.Response.WriteAsync(
        $$"""{"result":{{resultJson}},"stub_saw_authorization":"{{authorization}}"}""");
}

static async Task<int> RunSmokeAsync(WebApplication app, CapturedLogSink logSink)
{
    using var client = new HttpClient();
    var failures = new List<string>();

    app.Start();
    var baseUri = "http://localhost:5088";

    // 1. No caller key -> 401, nothing reaches the provider.
    var noKey = await client.PostAsync($"{baseUri}/ai/v1/chat/completions", Content());
    Check(noKey.StatusCode == System.Net.HttpStatusCode.Unauthorized, $"keyless request expected 401, got {(int)noKey.StatusCode}");

    // 2. Chat caller: the stub only answers 200 when it saw the injected provider key,
    //    so 200 proves the injection — and the echoed key never reaches the caller:
    //    the response scrubber (M20) removes it from the stub's echo, and the SSE
    //    events (M22) below stay scrub-on-arrival without waiting on each other.
    var chat = await client.PostAsync($"{baseUri}/ai/v1/chat/completions", KeyedContent(ChatAppKey));
    var chatBody = await chat.Content.ReadAsStringAsync();
    Check(chat.IsSuccessStatusCode
            && chatBody.Contains("Bearer [redacted]", StringComparison.Ordinal)
            && !chatBody.Contains(ProviderKey, StringComparison.Ordinal),
        $"chat call expected 200 with the echoed key scrubbed, got {(int)chat.StatusCode}: {chatBody}");

    // 3. SSE passthrough: the first event must arrive while the provider is still
    //    mid-stream (before its 400 ms second event), proving nothing buffered.
    var sseStart = Stopwatch.GetTimestamp();
    using var sse = await client.SendAsync(
        KeyedRequest($"{baseUri}/ai/v1/messages", ChatAppKey, accept: "text/event-stream"),
        HttpCompletionOption.ResponseHeadersRead);
    var firstEventMs = -1.0;
    var secondEventMs = -1.0;
    if (sse.IsSuccessStatusCode)
    {
        await using var stream = await sse.Content.ReadAsStreamAsync();
        using var reader = new StreamReader(stream, Encoding.UTF8);
        var seenData = 0;
        while (await reader.ReadLineAsync() is { } line)
        {
            if (line.StartsWith("data: ", StringComparison.Ordinal))
            {
                seenData++;
                var ms = Stopwatch.GetElapsedTime(sseStart).TotalMilliseconds;
                if (seenData == 1)
                {
                    firstEventMs = ms;
                }
                else if (seenData == 2)
                {
                    secondEventMs = ms;
                    break;
                }
            }
        }
    }
    Check(sse.IsSuccessStatusCode && (sse.Content.Headers.ContentType?.MediaType) == "text/event-stream",
        $"SSE call expected 200 text/event-stream, got {(int)sse.StatusCode} {sse.Content.Headers.ContentType}");
    Check(firstEventMs >= 0 && firstEventMs < 300,
        $"first SSE event expected < 300 ms (streaming), got {firstEventMs:0} ms — the response was buffered");
    Check(secondEventMs - firstEventMs >= 200,
        $"second SSE event expected >= 200 ms after the first (provider delay 400 ms), got {secondEventMs - firstEventMs:0} ms");

    // 4. Allow-list: the chat caller may not touch files/admin; the ops caller may.
    var blocked = await client.PostAsync($"{baseUri}/ai/v1/files", KeyedContent(ChatAppKey));
    Check(blocked.StatusCode == System.Net.HttpStatusCode.Forbidden,
        $"chat caller on /ai/v1/files expected 403, got {(int)blocked.StatusCode}");
    var blockedBody = await blocked.Content.ReadAsStringAsync();
    Check(blockedBody.Contains("credprox.operation_not_allowed", StringComparison.Ordinal),
        $"403 expected problem code credprox.operation_not_allowed, got {blockedBody}");

    // Let the 2-permits/s window refill so this call measures the allow-list, not the
    // limiter (the 403 above needed no permit — the allow-list runs before throttling).
    await Task.Delay(1100);
    var allowed = await client.PostAsync($"{baseUri}/ai/v1/files", KeyedContent(OpsAppKey));
    var allowedBody = await allowed.Content.ReadAsStringAsync();
    Check(allowed.IsSuccessStatusCode
            && allowedBody.Contains("Bearer [redacted]", StringComparison.Ordinal)
            && !allowedBody.Contains(ProviderKey, StringComparison.Ordinal),
        $"ops caller on /ai/v1/files expected 200 with the echoed key scrubbed, got {(int)allowed.StatusCode}: {allowedBody}");

    // 5. Cluster throttle: 2 permits/s with no queue -> a burst gets 429s.
    await Task.Delay(1100);
    var burst = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => BurstAsync()));
    var throttled = burst.Count(code => code == 429);
    Check(throttled >= 1, $"burst of 6 against 2 permits/s expected >= 1 throttled 429, got {throttled}");

    // 5b. Per-caller budget (M15, plan 3.7): batch-app declares 2 permits/minute. Its
    //     third call answers 429 credprox.caller_throttled with Retry-After — the budget
    //     runs before the cluster limiter, so this 429 is the caller's own, not the
    //     cluster's — and the other callers keep their full budget (per-app isolation).
    await Task.Delay(1100);
    int? budgetThird = null;
    string? budgetBody = null;
    string? budgetRetryAfter = null;
    for (var i = 0; i < 3; i++)
    {
        using var batchCall = await client.PostAsync(
            $"{baseUri}/ai/v1/chat/completions", KeyedContent(BatchAppKey));
        if (i == 2)
        {
            budgetThird = (int)batchCall.StatusCode;
            budgetBody = await batchCall.Content.ReadAsStringAsync();
            budgetRetryAfter = batchCall.Headers.RetryAfter?.ToString();
        }
    }

    Check(budgetThird == 429 && budgetBody!.Contains("credprox.caller_throttled", StringComparison.Ordinal),
        $"batch-app third call expected 429 credprox.caller_throttled, got {budgetThird}: {budgetBody}");
    Check(!string.IsNullOrEmpty(budgetRetryAfter),
        $"budget 429 expected a Retry-After header, got '{budgetRetryAfter}'");

    await Task.Delay(1100);
    using var afterBudget = await client.PostAsync($"{baseUri}/ai/v1/chat/completions", KeyedContent(ChatAppKey));
    Check(afterBudget.IsSuccessStatusCode,
        $"chat caller expected 200 while batch-app is exhausted (per-app isolation), got {(int)afterBudget.StatusCode}");

    // 6. Audit: proxied and rejected calls recorded by caller; the provider key never
    //    appears in any log line.
    await Task.Delay(200);
    var lines = logSink.Lines;
    Check(lines.Any(l => l.Contains("credprox.proxied_call") && l.Contains("caller=chat-app", StringComparison.Ordinal)),
        "audit missing proxied_call for chat-app");
    Check(lines.Any(l => l.Contains("credprox.proxied_call") && l.Contains("caller=ops-app", StringComparison.Ordinal)),
        "audit missing proxied_call for ops-app");
    Check(lines.Any(l => l.Contains("credprox.rejected_call") && l.Contains("caller=chat-app", StringComparison.Ordinal)),
        "audit missing rejected_call for the blocked chat-app call");
    Check(!lines.Any(l => l.Contains(ProviderKey, StringComparison.Ordinal)),
        "audit/log lines leaked the provider key value");

    await app.StopAsync();

    Console.WriteLine(failures.Count == 0
        ? "SMOKE OK: caller keys, injected provider key (never echoed to the caller), SSE passthrough with per-event scrubbing, allow-list, per-caller budget, throttle and audit all verified."
        : $"SMOKE FAILED ({failures.Count}): {string.Join(" | ", failures)}");
    return failures.Count == 0 ? 0 : 1;

    void Check(bool ok, string message)
    {
        if (!ok)
        {
            failures.Add(message);
        }
    }

    async Task<int> BurstAsync()
    {
        using var response = await client.PostAsync($"{baseUri}/ai/v1/chat/completions", KeyedContent(OpsAppKey));
        return (int)response.StatusCode;
    }

    static StringContent Content() => new("""{"model":"demo"}""", Encoding.UTF8, "application/json");

    static StringContent KeyedContent(string callerKey)
    {
        var content = Content();
        content.Headers.Add("X-CredProx-Key", callerKey);
        return content;
    }

    static HttpRequestMessage KeyedRequest(string uri, string callerKey, string? accept = null)
    {
        var content = Content();
        var request = new HttpRequestMessage(HttpMethod.Post, uri) { Content = content };
        request.Headers.Add("X-CredProx-Key", callerKey);
        if (accept is not null)
        {
            request.Headers.Accept.ParseAdd(accept);
        }

        return request;
    }
}
