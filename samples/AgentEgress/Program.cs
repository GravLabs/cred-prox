using System.Text;
using CredProx;
using CredProx.Testing;

// E15 (plan §6, §8.3): AI agent egress. An MCP server / agent runtime calls Salesforce
// through CredProx with **only its own caller API key** — the OAuth client secret and the
// issued session token never leave CredProx's side of the line. Per-agent operation
// allow-lists are the tool boundaries: the CRM agent reads, the support agent opens
// cases, neither can do the other's job. All config, no vendor-specific C#.
// The Salesforce shape is stubbed in-process (--smoke): the token endpoint validates the
// FormPost client credentials and counts issuances (so the smoke can prove the agents
// share one cached token), and the data API validates the bearer session token and
// echoes it back in a debug field — the response scrubber (M20) removes it there, so
// even the session token never reaches the agent.
const string ClientId = "credproxdemo";
const string ClientSecret = "sf-demo-client-secret-never-real";
const string AccessToken = "sfdemo-access-token-0001";
const string CrmAgentKey = "credprox-e15-crm-agent-demo-key";
const string SupportAgentKey = "credprox-e15-support-agent-demo-key";

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCredProxTokenCache();
builder.Services.AddCredProxConfigurationSecrets(builder.Configuration);
builder.Services.AddCredProxBuiltInCredentials();
builder.Services.AddCredProxCredentials(builder.Configuration);
builder.Services.AddCredProxCallerAuthentication(builder.Configuration);
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

builder.WebHost.UseUrls("http://localhost:5089");

var app = builder.Build();

// A fresh issuance means a cache miss; agents sharing one credential must share one
// token. The smoke asserts this counter across both agents' calls.
var tokenIssuances = 0;

// Salesforce's token endpoint shape: form-body client credentials (FormPost),
// client_credentials grant, JSON {access_token, instance_url, token_type}.
app.MapPost("/services/oauth2/token", async (HttpContext context) =>
{
    var form = await context.Request.ReadFormAsync();
    if (form["grant_type"] != "client_credentials"
        || form["client_id"] != ClientId
        || form["client_secret"] != ClientSecret)
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync("""{"error":"invalid_client","error_description":"authentication failure"}""");
        return;
    }

    Interlocked.Increment(ref tokenIssuances);
    context.Response.ContentType = "application/json";
    await context.Response.WriteAsync(
        $$"""{"access_token":"{{AccessToken}}","instance_url":"http://localhost:5089","token_type":"Bearer"}""");
});

// The data API refuses anything without the session token — the check the real
// Salesforce makes — and records what it saw in a debug field, the way real error
// pages and echo fields reflect the credential back. The scrubber removes it before
// the agent sees it.
app.MapGet("/services/data/v62.0/query", async (HttpContext context) =>
    await EchoSessionAsync(
        context,
        """{"records":[{"attributes":{"type":"Account"},"Id":"001xx000003DWYl","Name":"Acme"}],"totalSize":1,"done":true}"""));

app.MapPost("/services/data/v62.0/sobjects/Case", async (HttpContext context) =>
    await EchoSessionAsync(
        context,
        """{"id":"500xx00000A1b23AAB","success":true,"errors":[]}"""));

app.MapReverseProxy();

if (args.Contains("--smoke"))
{
    return await RunSmokeAsync(app, logSink!, () => tokenIssuances);
}

app.Run();
return 0;

static async Task EchoSessionAsync(HttpContext context, string resultJson)
{
    var authorization = context.Request.Headers.Authorization.ToString();
    if (authorization != $"Bearer {AccessToken}")
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync("""[{"message":"Session expired or invalid","errorCode":"INVALID_SESSION_ID"}]""");
        return;
    }

    context.Response.ContentType = "application/json";
    await context.Response.WriteAsync(
        $$"""{"result":{{resultJson}},"debug_authorization":"{{authorization}}"}""");
}

static async Task<int> RunSmokeAsync(WebApplication app, CapturedLogSink logSink, Func<int> issuances)
{
    using var client = new HttpClient();
    var failures = new List<string>();

    app.Start();
    var baseUri = "http://localhost:5089";

    // 1. No agent key, and a forged key: 401 at CredProx — nothing reaches the vendor.
    using var noKey = await client.GetAsync($"{baseUri}/salesforce/services/data/v62.0/query?q=SELECT+1");
    Check(noKey.StatusCode == System.Net.HttpStatusCode.Unauthorized,
        $"keyless call expected 401, got {(int)noKey.StatusCode}");

    using var forged = await client.SendAsync(KeyedRequest(
        $"{baseUri}/salesforce/services/data/v62.0/query?q=SELECT+1", "not-a-real-key"));
    Check(forged.StatusCode == System.Net.HttpStatusCode.Unauthorized,
        $"forged key expected 401, got {(int)forged.StatusCode}");

    // 2. CRM agent reads: the token endpoint authenticated the client credentials and
    //    the data API validated the bearer — 200 proves both happened on CredProx's
    //    side. The agent sees neither the client secret nor the session token; even
    //    the debug echo arrives as Bearer [redacted] (M20 scrubbing).
    var query = await client.SendAsync(KeyedRequest(
        $"{baseUri}/salesforce/services/data/v62.0/query?q=SELECT+Name+FROM+Account", CrmAgentKey));
    var queryBody = await query.Content.ReadAsStringAsync();
    Check(query.IsSuccessStatusCode
            && queryBody.Contains("\"Name\":\"Acme\"", StringComparison.Ordinal)
            && queryBody.Contains("Bearer [redacted]", StringComparison.Ordinal)
            && !queryBody.Contains(AccessToken, StringComparison.Ordinal)
            && !queryBody.Contains(ClientSecret, StringComparison.Ordinal),
        $"crm query expected 200 with the session token scrubbed, got {(int)query.StatusCode}: {queryBody}");
    query.Dispose();

    Check(issuances() == 1, $"expected exactly one token issuance, got {issuances()}");

    // 3. Tool boundaries: the CRM agent may not open cases...
    var blockedWrite = await client.PostAsync(
        $"{baseUri}/salesforce/services/data/v62.0/sobjects/Case", KeyedContent("{}", CrmAgentKey));
    Check(blockedWrite.StatusCode == System.Net.HttpStatusCode.Forbidden,
        $"crm agent on Case expected 403, got {(int)blockedWrite.StatusCode}");
    var blockedBody = await blockedWrite.Content.ReadAsStringAsync();
    Check(blockedBody.Contains("credprox.operation_not_allowed", StringComparison.Ordinal),
        $"403 expected problem code credprox.operation_not_allowed, got {blockedBody}");
    blockedWrite.Dispose();

    // ...and the support agent may not read — but it may open a case. One shared
    // credential, two agents, still one cached token (the counter must not move).
    var blockedRead = await client.SendAsync(KeyedRequest(
        $"{baseUri}/salesforce/services/data/v62.0/query?q=SELECT+1", SupportAgentKey));
    Check(blockedRead.StatusCode == System.Net.HttpStatusCode.Forbidden,
        $"support agent on query expected 403, got {(int)blockedRead.StatusCode}");
    blockedRead.Dispose();

    var create = await client.PostAsync(
        $"{baseUri}/salesforce/services/data/v62.0/sobjects/Case",
        KeyedContent("""{"Subject":"Printer on fire"}""", SupportAgentKey));
    var createBody = await create.Content.ReadAsStringAsync();
    Check(create.IsSuccessStatusCode
            && createBody.Contains("\"500xx00000A1b23AAB\"", StringComparison.Ordinal)
            && createBody.Contains("Bearer [redacted]", StringComparison.Ordinal)
            && !createBody.Contains(AccessToken, StringComparison.Ordinal),
        $"support create expected 200 with the session token scrubbed, got {(int)create.StatusCode}: {createBody}");
    create.Dispose();

    Check(issuances() == 1,
        $"both agents share one credential — expected still one token issuance, got {issuances()}");

    // 4. Audit: proxied and rejected calls recorded per agent; no secret value, client
    //    secret or session token, in any log line.
    await Task.Delay(200);
    var lines = logSink.Lines;
    Check(lines.Any(l => l.Contains("credprox.proxied_call") && l.Contains("caller=crm-agent", StringComparison.Ordinal)),
        "audit missing proxied_call for crm-agent");
    Check(lines.Any(l => l.Contains("credprox.proxied_call") && l.Contains("caller=support-agent", StringComparison.Ordinal)),
        "audit missing proxied_call for support-agent");
    Check(lines.Any(l => l.Contains("credprox.rejected_call") && l.Contains("caller=crm-agent", StringComparison.Ordinal)),
        "audit missing rejected_call for the blocked crm-agent write");
    Check(lines.Any(l => l.Contains("credprox.rejected_call") && l.Contains("caller=support-agent", StringComparison.Ordinal)),
        "audit missing rejected_call for the blocked support-agent read");
    Check(!lines.Any(l => l.Contains(ClientSecret, StringComparison.Ordinal)),
        "audit/log lines leaked the OAuth client secret value");
    Check(!lines.Any(l => l.Contains(AccessToken, StringComparison.Ordinal)),
        "audit/log lines leaked the issued session token value");
    // Belt-and-braces for the README's "never a credential" claim: the agents' own keys
    // must be absent too, so the smoke proves it rather than resting on library internals.
    Check(!lines.Any(l => l.Contains(CrmAgentKey, StringComparison.Ordinal)),
        "audit/log lines leaked the crm-agent caller key value");
    Check(!lines.Any(l => l.Contains(SupportAgentKey, StringComparison.Ordinal)),
        "audit/log lines leaked the support-agent caller key value");

    await app.StopAsync();

    Console.WriteLine(failures.Count == 0
        ? "SMOKE OK: agent keys, per-agent tool allow-lists, one shared cached token, session token scrubbed everywhere, and audit all verified."
        : $"SMOKE FAILED ({failures.Count}): {string.Join(" | ", failures)}");
    return failures.Count == 0 ? 0 : 1;

    void Check(bool ok, string message)
    {
        if (!ok)
        {
            failures.Add(message);
        }
    }

    static StringContent KeyedContent(string json, string agentKey)
    {
        var content = new StringContent(json, Encoding.UTF8, "application/json");
        content.Headers.Add("X-CredProx-Key", agentKey);
        return content;
    }

    static HttpRequestMessage KeyedRequest(string uri, string agentKey)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Add("X-CredProx-Key", agentKey);
        return request;
    }
}
