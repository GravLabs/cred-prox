// The Entra-only Azure OpenAI stand-in the sample cells drive. Two endpoints make the
// offline world: /metadata/identity/oauth2/token answers the managed-identity shape a
// pod-identity endpoint answers (the cells point the host's DefaultAzureCredential chain
// here with AZURE_POD_IDENTITY_AUTHORITY_HOST, so a canned Entra-style token flows exactly
// like a real one), and the chat endpoint serves only that bearer — a request without it,
// or one carrying api-key, is refused the way an Entra-only setup refuses keys. /__calls
// counts chat hits (a refused caller must never move it) and /__last echoes the headers of
// the last chat attempt, so cells witness what the vendor actually saw.
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

const string CannedToken = "aoai-offline-canned-bearer-token";
var chatCalls = 0;
var lastPath = "";
var lastAuthorization = "";
var lastApiKeySeen = "false";

app.MapGet("/__calls", () => chatCalls);
app.MapGet("/__last", () => Results.Text(
    $$"""{"path":"{{lastPath}}","authorization":"{{lastAuthorization}}","api_key_present":{{lastApiKeySeen}}}""",
    "application/json"));

app.MapGet("/metadata/identity/oauth2/token", () =>
{
    var expiresOn = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 3599;
    return Results.Text(
        $$"""{"token_type":"Bearer","expires_on":"{{expiresOn}}","ext_expires_on":"{{expiresOn}}","expires_in":"3599","access_token":"{{CannedToken}}","client_id":"00000000-0000-0000-0000-000000000000"}""",
        "application/json");
});

app.MapPost("/openai/deployments/{deployment}/chat/completions", async (HttpContext context) =>
{
    var authorization = context.Request.Headers.Authorization.ToString();
    var apiKeySeen = context.Request.Headers.TryGetValue("api-key", out var values) && values.Count > 0;
    lastPath = context.Request.Path.ToString();
    lastAuthorization = authorization;
    lastApiKeySeen = apiKeySeen ? "true" : "false";
    if (apiKeySeen || authorization != $"Bearer {CannedToken}")
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(
            """{"error":{"code":"Unauthorized","message":"Requests must use Microsoft Entra authentication."}}""");
        return;
    }
    // counted only once accepted — the header promise: a refused caller,
    // however shaped, must never move this counter:
    Interlocked.Increment(ref chatCalls);
    context.Response.ContentType = "application/json";
    await context.Response.WriteAsync(
        """{"id":"chatcmpl-standin","object":"chat.completion","created":1730000000,"model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"offline stand-in completion"},"finish_reason":"stop"}],"usage":{"prompt_tokens":9,"completion_tokens":7,"total_tokens":16}}""");
});

app.Run();
