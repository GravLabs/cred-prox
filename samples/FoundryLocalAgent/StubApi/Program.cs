// The offline stand-in for both upstreams of the FoundryLocalAgent sample, scripted by
// request CONTENT (the agent's own conversation history decides which turn answers):
// the model arm replays the measured Foundry Local OpenAI shape (no auth, inline usage)
// with three first-turn shapes chosen by model name — the plain tool call, the
// thinking-model shape (empty content beside reasoning_content, which a real local
// thinking model emits), and a tool call for the tool the caller's allow-list does not
// name. The tools arm counts hits so a cell can prove the gate, not the tool server,
// did the refusing: /__docs counts docs lookups, /__admin counts admin resets reaching
// the tool server (it must stay 0), /__modelcounts counts model turns.
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
var modelCalls = 0;
var docsCalls = 0;
var adminCalls = 0;
app.MapGet("/__modelcalls", () => modelCalls);
app.MapGet("/__docs", () => docsCalls);
app.MapGet("/__admin", () => adminCalls);

const string ToolCall = """
    {"id":"call-1","type":"function","function":{"name":"docs_lookup","arguments":"{}"}}
    """;
const string AdminCall = """
    {"id":"call-9","type":"function","function":{"name":"admin_reset","arguments":"{}"}}
    """;
const string Usage = """
    "usage":{"prompt_tokens":13,"completion_tokens":32,"total_tokens":45}
    """;

// The answer texts the stub returns carry no quotes, so direct concatenation is safe
// here; a stand-in replaying arbitrary vendor text would build the JSON with a writer.
string Final(string text) =>
    "{\"id\":\"c1\",\"object\":\"chat.completion\",\"choices\":[{\"index\":0,"
    + "\"message\":{\"role\":\"assistant\",\"content\":\"" + text + "\"},"
    + "\"finish_reason\":\"stop\"}]," + Usage + "}";

app.MapPost("/v1/chat/completions", async (HttpContext context) =>
{
    Interlocked.Increment(ref modelCalls);
    var body = await new StreamReader(context.Request.Body).ReadToEndAsync();
    context.Response.ContentType = "application/json";
    if (body.Contains("gateway_refused", StringComparison.Ordinal))
    {
        // The gate refused the tool the model asked for; the answer must show the
        // model saw the refusal as a tool error, not as a dead transport.
        await context.Response.WriteAsync(Final("cannot reset that - the gateway refused the tool"));
        return;
    }
    if (body.Contains("doc-42", StringComparison.Ordinal))
    {
        await context.Response.WriteAsync(Final("The answer is doc-42."));
        return;
    }
    if (body.Contains("\"reasoner-demo\"", StringComparison.Ordinal))
    {
        // The thinking shape: empty content beside reasoning_content, and the tool
        // call the agent must still act on.
        await context.Response.WriteAsync(
            """{"id":"c1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"","reasoning_content":"I should look this up first.","tool_calls":["""
            + ToolCall + "]}}]," + Usage + "}");
        return;
    }
    if (body.Contains("\"admin-demo\"", StringComparison.Ordinal))
    {
        await context.Response.WriteAsync(
            """{"id":"c1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"","tool_calls":["""
            + AdminCall + "]}}]," + Usage + "}");
        return;
    }
    await context.Response.WriteAsync(
        """{"id":"c1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"","tool_calls":["""
        + ToolCall + "]}}]," + Usage + "}");
});

app.MapGet("/tools/v1/docs/lookup", () =>
{
    Interlocked.Increment(ref docsCalls);
    return Results.Text("""{"result":"doc-42"}""");
});
app.MapGet("/tools/v1/admin/reset", () =>
{
    Interlocked.Increment(ref adminCalls);
    return Results.Text("""{"result":"reset-done"}""");
});
// The issuer arm: the offline stand-in for the OIDC issuer the agent's caller tokens
// are validated against. It publishes openid-configuration and a /jwks list containing
// the ONE public key the smoke fixture pushes at run start (/__publishjwk) — the
// fixture holds the private half for the run and nothing is committed. Discovery,
// signature and issuer checks are the host's real OIDC pipeline; this arm only serves
// the two documents a live issuer would.
string? publishedJwk = null;
app.MapPost("/__publishjwk", async (HttpContext context) =>
{
    publishedJwk = await new StreamReader(context.Request.Body).ReadToEndAsync();
    return Results.Ok();
});
app.MapGet("/issuer/.well-known/openid-configuration", (HttpContext context) => Results.Json(new
{
    issuer = $"{context.Request.Scheme}://{context.Request.Host}/issuer",
    jwks_uri = $"{context.Request.Scheme}://{context.Request.Host}/issuer/jwks",
}));
app.MapGet("/issuer/jwks", () => Results.Content(
    publishedJwk is null ? """{"keys":[]}""" : """{"keys":[""" + publishedJwk + "]}",
    "application/json"));
app.MapFallback(() => Results.NotFound());
app.Run();
