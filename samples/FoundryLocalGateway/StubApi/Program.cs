// The Foundry Local stand-in the offline sample cells drive, measured against the real
// loopback build's shape (docs/foundry-local-notes.md): NO authentication anywhere —
// the vendor trusts whatever reaches its loopback port, so whatever gates this port is
// the only gate the deployment has. /v1/chat/completions answers non-stream requests
// with an inline usage block and stream requests with SSE deltas; token usage on a
// stream arrives only as a final usage-only event, and only when the request asked
// stream_options.include_usage. /v1/models answers 405 exactly like the real build.
// /__calls counts every request that reaches this process — chat completions and
// unmatched paths alike (the fallback arm) — so a cell that expects the stand-in to be
// reached sees the move on any path, and an unauthenticated caller must never move it.
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

var calls = 0;

app.MapGet("/__calls", () => calls);

app.MapMethods("/v1/models", ["GET"], () => Results.StatusCode(StatusCodes.Status405MethodNotAllowed));

app.MapFallback(() =>
{
    Interlocked.Increment(ref calls);
    return Results.NotFound();
});

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
    await context.Response.Body.FlushAsync();
    await context.Response.WriteAsync(
        "data: " + """{"id":"chatcmpl-stub-1","object":"chat.completion.chunk","model":"qwen3-4b-generic-cpu:3","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}""" + "\n\n");
    if (wantsUsage)
    {
        await context.Response.WriteAsync(
            "data: " + """{"id":"chatcmpl-stub-1","object":"chat.completion.chunk","model":"qwen3-4b-generic-cpu:3","choices":[],"usage":{"prompt_tokens":13,"completion_tokens":32,"total_tokens":45}}""" + "\n\n");
    }

    await context.Response.WriteAsync("data: [DONE]\n\n");
    await context.Response.Body.FlushAsync();
});

app.Run();
