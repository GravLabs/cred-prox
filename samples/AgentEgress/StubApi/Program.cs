// The Salesforce stand-in the sample cells drive: the token endpoint validates the
// form-posted client credentials (the check the real one makes) and counts issuances, so
// the shared-cache cell can watch them; the data API refuses anything without the bearer
// it issued and echoes what it saw, the way a verbose endpoint reflects a credential.
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

var clientId = builder.Configuration["Stub:ClientId"]!;
var clientSecret = builder.Configuration["Stub:ClientSecret"]!;
var accessToken = builder.Configuration["Stub:AccessToken"]!;
var issuances = 0;

app.MapGet("/__tokens", () => issuances);

// Salesforce's token endpoint shape: form-body client credentials (FormPost),
// client_credentials grant, JSON {access_token, instance_url, token_type}.
app.MapPost("/services/oauth2/token", async (HttpContext context) =>
{
    var form = await context.Request.ReadFormAsync();
    if (form["grant_type"] != "client_credentials"
        || form["client_id"] != clientId
        || form["client_secret"] != clientSecret)
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync("""{"error":"invalid_client","error_description":"authentication failure"}""");
        return;
    }

    Interlocked.Increment(ref issuances);
    context.Response.ContentType = "application/json";
    await context.Response.WriteAsync(
        $$"""{"access_token":"{{accessToken}}","instance_url":"http://localhost:8096","token_type":"Bearer"}""");
});

// The data API refuses anything without the session token — the check the real vendor
// makes — and records what it saw in a debug field, which the caller-side scrubber
// removes before the agent sees it.
app.MapGet("/services/data/v62.0/query", async (HttpContext context) =>
    await EchoSessionAsync(
        context,
        """{"records":[{"attributes":{"type":"Account"},"Id":"001xx000003DWYl","Name":"Acme"}],"totalSize":1,"done":true}"""));

app.MapPost("/services/data/v62.0/sobjects/Case", async (HttpContext context) =>
    await EchoSessionAsync(
        context,
        """{"id":"500xx00000A1b23AAB","success":true,"errors":[]}"""));

app.Run();

async Task EchoSessionAsync(HttpContext context, string resultJson)
{
    var authorization = context.Request.Headers.Authorization.ToString();
    if (authorization != $"Bearer {accessToken}")
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
