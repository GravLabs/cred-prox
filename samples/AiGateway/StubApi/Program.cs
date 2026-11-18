// The AI-provider stand-in the sample cells drive: every endpoint refuses requests that
// did not arrive with the provider key it expects (the check a real provider makes) and
// echoes what it saw, so the cells can witness the injected key at the vendor while the
// caller sees it redacted. /__calls counts hits — a keyless caller must never move it.
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

var providerKey = builder.Configuration["Stub:ProviderKey"]!;
var calls = 0;

app.MapGet("/__calls", () => calls);

app.MapPost("/v1/chat/completions", async (HttpContext context) =>
    await EchoKeyAsync(context, """{"object":"chat.completion"}"""));

app.MapPost("/v1/files", async (HttpContext context) =>
    await EchoKeyAsync(context, """{"object":"file"}"""));

app.MapPost("/admin/models", async (HttpContext context) =>
    await EchoKeyAsync(context, """{"object":"list"}"""));

// A streaming completion: two SSE events written 400 ms apart, flushed as written. A
// buffering proxy delivers both together after ~400 ms; a streaming one delivers the
// first immediately — the cell measures exactly that. The first event echoes the
// Authorization header so the caller-side cell can watch it redacted inside the stream.
app.MapPost("/v1/messages", async (HttpContext context) =>
{
    Interlocked.Increment(ref calls);
    var authorization = context.Request.Headers.Authorization.ToString();
    if (authorization != $"Bearer {providerKey}")
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsync("""{"error":{"type":"authentication_error"}}""");
        return;
    }

    context.Response.ContentType = "text/event-stream";
    context.Response.Headers.CacheControl = "no-cache";
    await context.Response.WriteAsync(
        "event: message\ndata: {\"index\":1,\"saw\":\"" + authorization + "\"}\n\n");
    await context.Response.Body.FlushAsync();
    await Task.Delay(400);
    await context.Response.WriteAsync("event: message\ndata: {\"index\":2}\n\n");
    await context.Response.Body.FlushAsync();
});

app.Run();

async Task EchoKeyAsync(HttpContext context, string resultJson)
{
    Interlocked.Increment(ref calls);
    var authorization = context.Request.Headers.Authorization.ToString();
    if (authorization != $"Bearer {providerKey}")
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsync("""{"error":{"type":"authentication_error"}}""");
        return;
    }

    context.Response.ContentType = "application/json";
    await context.Response.WriteAsync(
        $$"""{"result":{{resultJson}},"stub_saw_authorization":"{{authorization}}"}""");
}
