using System.Text.Json;

// The legacy vendor the VendorSession plugin logs into: JSON appId+secret in, a fixed
// session id out, a login counter for the cache witness, and endpoints that report which
// session header arrived — as JSON (redacted caller-side) and byte-exactly (/exact).
var builder = WebApplication.CreateBuilder(args);

var appId = builder.Configuration["Stub:AppId"] ?? "demo-app";
var secret = builder.Configuration["Stub:Secret"] ?? "demo-vendor-secret";
var sessionId = builder.Configuration["Stub:SessionId"] ?? "vsess_stub_session";
var loginCalls = 0;

var app = builder.Build();

// The vendor login endpoint: check the posted credentials, hand out the session id.
app.MapPost("/login", async (HttpContext context) =>
{
    Interlocked.Increment(ref loginCalls);
    using var body = await JsonDocument.ParseAsync(
        context.Request.Body, cancellationToken: context.RequestAborted);
    var accepted =
        body.RootElement.GetProperty("appId").GetString() == appId
        && body.RootElement.GetProperty("secret").GetString() == secret;

    if (!accepted)
    {
        return Results.Json(new { error = "invalid_credentials" }, statusCode: StatusCodes.Status401Unauthorized);
    }

    return Results.Json(new { access_token = sessionId, expires_in = 3600 });
});

// A vendor API endpoint: reports the session header it received, as JSON — the reflecting
// response the proxy's response scrubber must redact caller-side.
app.Map("/echo", (HttpContext context) =>
    Results.Json(new { sessionId = context.Request.Headers["X-Session-Id"].ToString() }));

// Answers "ok" only when the header is byte-exactly the session id — the witness that
// the raw value reached the vendor, which the redacted echo cannot show.
app.MapGet("/exact", (HttpContext context) =>
    Results.Text(
        context.Request.Headers["X-Session-Id"].ToString() == sessionId ? "ok" : "mismatch",
        "text/plain"));

// How many times login was called — the cache witness.
app.MapGet("/__logins", () => Results.Text(Volatile.Read(ref loginCalls).ToString(), "text/plain"));

app.Run();
return 0;
