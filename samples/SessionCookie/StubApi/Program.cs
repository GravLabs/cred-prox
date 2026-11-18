// The session-cookie CRM stand-in the sample cells drive: the login is a form POST
// answering Set-Cookie (the session-cookie shape), the data API refuses anything whose
// CRMSESSION is not the live session for the environment it is serving, and
// /dev/invalidate expires a session server-side the way an idle vendor session dies.
using System.Collections.Concurrent;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

var passwords = new Dictionary<string, string>(StringComparer.Ordinal)
{
    ["sandbox"] = builder.Configuration["Stub:SandboxPassword"]!,
    ["production"] = builder.Configuration["Stub:ProductionPassword"]!,
};
var sessionMarker = builder.Configuration["Stub:SessionMarker"]!;
var activeSessions = new ConcurrentDictionary<string, string>(StringComparer.Ordinal);
var issuanceCounts = new ConcurrentDictionary<string, int>(StringComparer.Ordinal);

app.MapGet("/__logins", (string partition) => issuanceCounts.GetValueOrDefault(partition));

// The vendor's own session-expiry control, for the refresh-through-the-401 cell. It
// lives on the stand-in, never on the host — a deployment copied from the sample has
// no live session-expiry endpoint to inherit.
app.MapPost("/dev/invalidate", (HttpContext context) =>
{
    activeSessions.TryRemove(context.Request.Query["partition"].ToString(), out _);
    return Results.Ok();
});

// The vendor's login: a form POST answering with Set-Cookie. Wrong credentials, or an
// environment the vendor does not host, answer 401 like the real thing.
app.MapPost("/login", async (HttpContext context) =>
{
    var partition = context.Request.Query["partition"].ToString();
    var form = await context.Request.ReadFormAsync();
    if (!passwords.TryGetValue(partition, out var password)
        || form["user"] != $"svc-{partition}"
        || form["password"] != password)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsync("denied");
        return;
    }

    var session = $"{sessionMarker}{partition}-{Guid.NewGuid():N}";
    activeSessions[partition] = session;
    issuanceCounts.AddOrUpdate(partition, 1, (_, count) => count + 1);
    context.Response.Cookies.Append("CRMSESSION", session, new CookieOptions { Path = "/" });
    await context.Response.WriteAsync("ok");
});

app.MapGet("/api/contacts", async (HttpContext context) => await GuardAsync(context));

// The stock API knows one SKU. Anything else answers 404 in the vendor's own JSON
// error shape — the raw material for the gateway's error normalisation, and exactly
// what the opted-out /crm-raw route forwards as written.
app.MapGet("/api/inventory/{sku}", async (HttpContext context, string sku) =>
    await InventoryAsync(context, sku));

app.Run();

// The data API checks the CRMSESSION against the live session for the environment it
// is serving and records the raw Cookie header it saw in a debug field, the way real
// error pages and echo fields reflect a credential back. The caller's own cookies never
// arrived at all — the gateway replaces the Cookie header instead of merging.
async Task GuardAsync(HttpContext context)
{
    var partition = context.Request.Headers["X-API-Env"].ToString();
    var cookie = context.Request.Headers.Cookie.ToString();
    var session = ParseCookieValue(cookie, "CRMSESSION");

    if (session is null
        || !activeSessions.TryGetValue(partition, out var live)
        || session != live)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync("""{"error":"INVALID_SESSION","message":"missing or expired CRMSESSION"}""");
        return;
    }

    context.Response.ContentType = "application/json";
    await context.Response.WriteAsync(
        $$"""{"result":{"records":[{"id":1,"name":"Acme ({{partition}} CRM)"}],"env":"{{partition}}"},"debug_cookie":"{{Escape(cookie)}}"}""");
}

// Same session gate as the data API; an authenticated call for a SKU the vendor does
// not stock gets the vendor's own 404.
async Task InventoryAsync(HttpContext context, string sku)
{
    var partition = context.Request.Headers["X-API-Env"].ToString();
    var session = ParseCookieValue(context.Request.Headers.Cookie.ToString(), "CRMSESSION");

    if (session is null || !activeSessions.TryGetValue(partition, out var live) || session != live)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync("""{"error":"INVALID_SESSION","message":"missing or expired CRMSESSION"}""");
        return;
    }

    context.Response.StatusCode = StatusCodes.Status404NotFound;
    context.Response.ContentType = "application/json";
    await context.Response.WriteAsync(
        $$"""{"error":"SKU_NOT_FOUND","sku":"{{sku}}","warehouse":"{{partition}}"}""");
}

static string? ParseCookieValue(string header, string name)
{
    var prefix = name + "=";
    foreach (var pair in header.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
    {
        if (pair.StartsWith(prefix, StringComparison.Ordinal))
        {
            return pair[prefix.Length..];
        }
    }

    return null;
}

static string Escape(string value) => value.Replace("\\", "\\\\").Replace("\"", "\\\"");
