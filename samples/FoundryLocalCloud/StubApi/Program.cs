// The offline stand-in for BOTH upstreams of the FoundryLocalCloud sample, one process
// on two ports because the arms are distinguished by path, not by port.
// The local arm replays the measured Foundry Local shape (docs/foundry-local-notes.md):
// NO authentication anywhere — /v1/chat/completions answers with an inline usage block.
// The cloud arm replays the Anthropic Messages shape: anthropic-version is required
// FIRST (400 without it, exactly as Anthropic answers — the transform the cloud route
// carries is what keeps gateway traffic off this refusal), then x-api-key (401 without
// the demo key — the shape the sample's StaticKey credential satisfies); a JSON
// message with usage.input_tokens / usage.output_tokens, and /v1/models 405 like the
// local build. /__calls counts local-arm hits and unmatched requests; /__cloudcalls
// counts cloud-arm hits that passed both checks. An unauthenticated caller must never
// move either counter.
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
var calls = 0;
var cloudCalls = 0;
app.MapGet("/__calls", () => calls);
app.MapGet("/__cloudcalls", () => cloudCalls);
app.MapMethods("/v1/models", ["GET"], () => Results.StatusCode(StatusCodes.Status405MethodNotAllowed));
app.MapPost("/v1/chat/completions", async (HttpContext context) =>
{
    Interlocked.Increment(ref calls);
    var body = await new StreamReader(context.Request.Body).ReadToEndAsync();
    var wantsStream = body.Contains("\"stream\":true", StringComparison.Ordinal);
    var wantsUsage = body.Contains("include_usage", StringComparison.Ordinal);
    if (!wantsStream)
    {
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(
            """{"id":"chatcmpl-stub-1","object":"chat.completion","model":"qwen3-4b-generic-cpu:3","choices":[{"index":0,"message":{"role":"assistant","content":"Hello from the local model."},"finish_reason":"stop"}],"usage":{"prompt_tokens":13,"completion_tokens":32,"total_tokens":45}}""");
        return;
    }
    context.Response.ContentType = "text/event-stream";
    context.Response.Headers.CacheControl = "no-cache";
    await context.Response.WriteAsync(
        "data: " + """{"id":"chatcmpl-stub-1","object":"chat.completion.chunk","model":"qwen3-4b-generic-cpu:3","choices":[{"index":0,"delta":{"role":"assistant","content":"Hello"},"finish_reason":null}]}""" + "\n\n");
    if (wantsUsage)
    {
        await context.Response.WriteAsync(
            "data: " + """{"id":"chatcmpl-stub-1","object":"chat.completion.chunk","model":"qwen3-4b-generic-cpu:3","choices":[],"usage":{"prompt_tokens":13,"completion_tokens":32,"total_tokens":45}}""" + "\n\n");
    }
    await context.Response.WriteAsync("data: [DONE]\n\n");
    await context.Response.Body.FlushAsync();
});
app.MapPost("/v1/messages", (HttpContext context) =>
{
    if (!context.Request.Headers.TryGetValue("anthropic-version", out var version)
        || string.IsNullOrWhiteSpace(version.ToString()))
    {
        return Results.Json(
            """{"type":"error","error":{"type":"invalid_request_error","message":"anthropic-version: header is required"}}""",
            statusCode: StatusCodes.Status400BadRequest);
    }
    if (!context.Request.Headers.TryGetValue("x-api-key", out var key)
        || key.ToString() != "credprox-demo-cloud-key")
    {
        return Results.Json(
            """{"type":"error","error":{"type":"authentication_error","message":"missing api key"}}""",
            statusCode: StatusCodes.Status401Unauthorized);
    }
    Interlocked.Increment(ref cloudCalls);
    context.Response.ContentType = "application/json";
    return Results.Text(
        """{"type":"message","role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"text","text":"Hello from the cloud model."}],"usage":{"input_tokens":11,"output_tokens":24}}""");
});
app.MapFallback(() =>
{
    Interlocked.Increment(ref calls);
    return Results.NotFound();
});
app.Run();
