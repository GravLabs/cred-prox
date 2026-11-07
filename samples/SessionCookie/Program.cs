using System.Collections.Concurrent;
using System.Text;
using CredProx;
using CredProx.Testing;

// E16 (plan §6, §8.1): the generic successor to the original Cayuse demo (plan §2) —
// an older vendor whose API speaks **session cookies**, not bearer tokens. One
// LoginExchange credential POSTs a login form, captures the Set-Cookie session value
// (Response: Cookie) and replays it on every vendor call (Location: Cookie) — pure
// config. The Cayuse facts stay as a shape: {partition} per-environment logins behind a
// strict allow-list (the F6 bug class: a crafted environment header used to swap the
// host — now a 400), per-partition accounts and secrets, and the 00:55 assumed lifetime.
// The caller authenticates with its own key and gets no cookie handling of its own: the
// Cookie header it sends is replaced wholesale (never merged), the session value it could
// echo back is scrubbed (§8.2), and the login password and session stay out of the audit.
const string ErpKey = "credprox-e16-erp-demo-key";
const string SessionMarker = "crm-session-";
const string SandboxPassword = "crm-demo-sandbox-password-never-real";
const string ProductionPassword = "crm-demo-production-password-never-real";

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

builder.WebHost.UseUrls("http://localhost:5095");

var app = builder.Build();

// The vendor's own state: per-environment accounts, the one live session cookie per
// environment, and an issuance counter per environment — the smoke asserts one login
// per environment across repeated calls (the cache), and exactly one more after the
// session is invalidated server-side (the refresh-on-401 path).
var passwords = new Dictionary<string, string>(StringComparer.Ordinal)
{
    ["sandbox"] = SandboxPassword,
    ["production"] = ProductionPassword,
};
var activeSessions = new ConcurrentDictionary<string, string>(StringComparer.Ordinal);
var issuanceCounts = new ConcurrentDictionary<string, int>(StringComparer.Ordinal);

// The vendor's login: a form POST answering with Set-Cookie — the session-cookie shape.
// Wrong credentials, or an environment the vendor does not host, answer 401 like the real thing.
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

    var session = $"{SessionMarker}{partition}-{Guid.NewGuid():N}";
    activeSessions[partition] = session;
    issuanceCounts.AddOrUpdate(partition, 1, (_, count) => count + 1);
    context.Response.Cookies.Append("CRMSESSION", session, new CookieOptions { Path = "/" });
    await context.Response.WriteAsync("ok");
});

// Smoke control (registered for --smoke runs only, review note N3): expire the
// environment's session server-side, the way an idle vendor session dies. The next
// proxied call must refresh through the 401 without the caller seeing either the 401
// or the re-login. Never part of a normal run, so a deployment copied from this
// sample cannot inherit a live session-expiry endpoint.
if (args.Contains("--smoke"))
{
    app.MapPost("/dev/invalidate", (HttpContext context) =>
    {
        activeSessions.TryRemove(context.Request.Query["partition"].ToString(), out _);
        return Results.Ok();
    });
}

app.MapGet("/api/contacts", async (HttpContext context) => await GuardAsync(context));

// The stock API knows one SKU. Anything else answers 404 in the vendor's own JSON
// error shape — exactly the body M24 error normalisation rewrites into the uniform
// problem document (and exactly what the opted-out /crm-raw route forwards as written).
app.MapGet("/api/inventory/{sku}", async (HttpContext context, string sku) => await InventoryAsync(context, sku));

app.MapReverseProxy();

if (args.Contains("--smoke"))
{
    return await RunSmokeAsync(app, logSink!, partition => issuanceCounts.GetValueOrDefault(partition));
}

app.Run();
return 0;

// The data API refuses anything whose CRMSESSION is not the live session for the
// environment it is serving — the check the real vendor makes — and records the raw
// Cookie header it saw in a debug field, the way real error pages and echo fields
// reflect a credential back. The scrubber removes the session value before the caller
// sees it; the caller's own cookies never arrived at all (replacement, not merging).
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

    // The environment is proven by the session (the lookup above only succeeds for the
    // vendor's own environments), so the data is shaped per environment from it.
    context.Response.ContentType = "application/json";
    await context.Response.WriteAsync(
        $$"""{"result":{"records":[{"id":1,"name":"Acme ({{partition}} CRM)"}],"env":"{{partition}}"},"debug_cookie":"{{Escape(cookie)}}"}""");
}

// Same session gate as the data API; an authenticated call for a SKU the vendor does
// not stock gets the vendor's own 404 — the raw material for the normalisation check.
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

static async Task<int> RunSmokeAsync(WebApplication app, CapturedLogSink logSink, Func<string, int> issuances)
{
    using var client = new HttpClient();
    var failures = new List<string>();

    app.Start();
    var baseUri = "http://localhost:5095";

    // 1. No caller key, and a forged key: 401 at CredProx — the vendor is never touched.
    using var noKey = await client.GetAsync($"{baseUri}/crm/api/contacts");
    Check(noKey.StatusCode == System.Net.HttpStatusCode.Unauthorized,
        $"keyless call expected 401, got {(int)noKey.StatusCode}");

    using var forged = await client.SendAsync(CallerRequest(
        $"{baseUri}/crm/api/contacts", "not-a-real-key", "sandbox"));
    Check(forged.StatusCode == System.Net.HttpStatusCode.Unauthorized,
        $"forged key expected 401, got {(int)forged.StatusCode}");

    // 2. Sandbox call: CredProx logged in (form POST → Set-Cookie) and replayed the
    //    session cookie; the API's 200 proves both the login and the cookie check
    //    happened on CredProx's side. The echo field arrives CRMSESSION=[redacted]
    //    (M20 scrubbing) — the session value and the login password never reach the caller.
    var first = await client.SendAsync(CallerRequest($"{baseUri}/crm/api/contacts", ErpKey, "sandbox"));
    var firstBody = await first.Content.ReadAsStringAsync();
    Check(first.IsSuccessStatusCode
            && firstBody.Contains("Acme (sandbox CRM)", StringComparison.Ordinal)
            && firstBody.Contains("CRMSESSION=[redacted]", StringComparison.Ordinal)
            && !firstBody.Contains(SessionMarker, StringComparison.Ordinal)
            && !firstBody.Contains(SandboxPassword, StringComparison.Ordinal),
        $"sandbox call expected 200 with the session scrubbed, got {(int)first.StatusCode}: {firstBody}");
    first.Dispose();

    Check(issuances("sandbox") == 1, $"expected one login for the first sandbox call, got {issuances("sandbox")}");

    // 3. The session is cached: repeated calls ride the same cookie, no second login.
    var second = await client.SendAsync(CallerRequest($"{baseUri}/crm/api/contacts", ErpKey, "sandbox"));
    second.Dispose();
    Check(issuances("sandbox") == 1,
        $"repeated sandbox call expected still one login, got {issuances("sandbox")}");

    // 4. One credential, many environments: production is a different partition, a
    //    different account and a different secret — and its own single login.
    var prod = await client.SendAsync(CallerRequest($"{baseUri}/crm/api/contacts", ErpKey, "production"));
    var prodBody = await prod.Content.ReadAsStringAsync();
    Check(prod.IsSuccessStatusCode
            && prodBody.Contains("Acme (production CRM)", StringComparison.Ordinal)
            && !prodBody.Contains(SessionMarker, StringComparison.Ordinal),
        $"production call expected 200, got {(int)prod.StatusCode}: {prodBody}");
    prod.Dispose();
    Check(issuances("production") == 1,
        $"expected one login for production, got {issuances("production")}");
    Check(issuances("sandbox") == 1,
        $"production must not disturb the sandbox session, got sandbox logins {issuances("sandbox")}");

    // 5. The caller's own cookies never ride along: the Cookie header it sends is
    //    replaced wholesale, so the vendor's echo field carries only the injected pair.
    var withCookies = await client.SendAsync(CallerRequest(
        $"{baseUri}/crm/api/contacts", ErpKey, "sandbox", cookie: "theme=dark; CRMSESSION=caller-forged"));
    var cookieBody = await withCookies.Content.ReadAsStringAsync();
    Check(withCookies.IsSuccessStatusCode
            && !cookieBody.Contains("theme=dark", StringComparison.Ordinal)
            && !cookieBody.Contains("caller-forged", StringComparison.Ordinal)
            && cookieBody.Contains("CRMSESSION=[redacted]", StringComparison.Ordinal),
        $"caller cookies must not reach the vendor, got {(int)withCookies.StatusCode}: {cookieBody}");
    withCookies.Dispose();

    // 6. The F6 bug class, closed: the environment header is an exact allow-list, not a
    //    Contains match — a crafted value near-missing an allowed one dies with 400.
    var crafted = await client.SendAsync(CallerRequest($"{baseUri}/crm/api/contacts", ErpKey, "sandbox-evil"));
    Check(crafted.StatusCode == System.Net.HttpStatusCode.BadRequest,
        $"crafted environment expected 400, got {(int)crafted.StatusCode}");
    var craftedBody = await crafted.Content.ReadAsStringAsync();
    Check(craftedBody.Contains("credprox.partition_not_allowed", StringComparison.Ordinal),
        $"400 expected credprox.partition_not_allowed, got {craftedBody}");
    crafted.Dispose();

    // 7. Server-side session expiry is invisible to the caller: the vendor's 401
    //    triggers a re-login and one retry; the caller just sees 200. Exactly one
    //    extra login for that environment.
    using (var invalidate = await client.PostAsync($"{baseUri}/dev/invalidate?partition=sandbox", null))
    {
        Check(invalidate.IsSuccessStatusCode, $"invalidate expected 200, got {(int)invalidate.StatusCode}");
    }

    var refreshed = await client.SendAsync(CallerRequest($"{baseUri}/crm/api/contacts", ErpKey, "sandbox"));
    var refreshedBody = await refreshed.Content.ReadAsStringAsync();
    Check(refreshed.IsSuccessStatusCode
            && refreshedBody.Contains("CRMSESSION=[redacted]", StringComparison.Ordinal)
            && !refreshedBody.Contains(SessionMarker, StringComparison.Ordinal),
        $"call after server-side expiry expected transparent 200, got {(int)refreshed.StatusCode}: {refreshedBody}");
    refreshed.Dispose();
    Check(issuances("sandbox") == 2,
        $"expected exactly one refresh login after invalidation, got {issuances("sandbox")}");

    // 8. Vendor error normalisation (M24, §8.5): the stock API's own 404 JSON reaches
    //    the caller as the uniform problem document — status kept, the vendor's payload
    //    preserved as vendor_detail — while the opted-out /crm-raw route forwards the
    //    vendor's bytes exactly as written.
    var vendorError = await client.SendAsync(CallerRequest(
        $"{baseUri}/crm/api/inventory/UNKNOWN-9", ErpKey, "sandbox"));
    var vendorErrorBody = await vendorError.Content.ReadAsStringAsync();
    Check((int)vendorError.StatusCode == 404
            && vendorError.Content.Headers.ContentType?.MediaType == "application/problem+json"
            && vendorErrorBody.Contains("urn:credprox:errors:vendor", StringComparison.Ordinal)
            && vendorErrorBody.Contains("credprox.vendor_error", StringComparison.Ordinal)
            && vendorErrorBody.Contains("SKU_NOT_FOUND", StringComparison.Ordinal)
            && vendorErrorBody.Contains("UNKNOWN-9", StringComparison.Ordinal),
        $"vendor 404 expected a normalised problem document, got {(int)vendorError.StatusCode}: {vendorErrorBody}");
    vendorError.Dispose();

    var rawError = await client.SendAsync(CallerRequest(
        $"{baseUri}/crm-raw/api/inventory/UNKNOWN-9", ErpKey, "sandbox"));
    var rawErrorBody = await rawError.Content.ReadAsStringAsync();
    Check((int)rawError.StatusCode == 404
            && rawError.Content.Headers.ContentType?.MediaType == "application/json"
            && rawErrorBody.Contains("SKU_NOT_FOUND", StringComparison.Ordinal)
            && !rawErrorBody.Contains("urn:credprox", StringComparison.Ordinal),
        $"opted-out route expected the vendor's own JSON, got {(int)rawError.StatusCode}: {rawErrorBody}");
    rawError.Dispose();

    // 9. Audit: the proxied calls are recorded for the caller; no session value, login
    //    password or caller key appears in any log line.
    await Task.Delay(200);
    var lines = logSink.Lines;
    Check(lines.Any(l => l.Contains("credprox.proxied_call") && l.Contains("caller=erp-integration", StringComparison.Ordinal)),
        "audit missing proxied_call for erp-integration");
    Check(!lines.Any(l => l.Contains(SessionMarker, StringComparison.Ordinal)),
        "audit/log lines leaked a session cookie value");
    Check(!lines.Any(l => l.Contains(SandboxPassword, StringComparison.Ordinal)),
        "audit/log lines leaked the sandbox login password");
    Check(!lines.Any(l => l.Contains(ProductionPassword, StringComparison.Ordinal)),
        "audit/log lines leaked the production login password");
    Check(!lines.Any(l => l.Contains(ErpKey, StringComparison.Ordinal)),
        "audit/log lines leaked the erp-integration caller key value");

    await app.StopAsync();

    Console.WriteLine(failures.Count == 0
        ? "SMOKE OK: form login replayed as session cookie, per-environment partitions and secrets, caller cookies replaced, expired session refreshed transparently, session scrubbed everywhere, vendor 404 normalised (opt-out route raw), and audit all verified."
        : $"SMOKE FAILED ({failures.Count}): {string.Join(" | ", failures)}");
    return failures.Count == 0 ? 0 : 1;

    void Check(bool ok, string message)
    {
        if (!ok)
        {
            failures.Add(message);
        }
    }

    static HttpRequestMessage CallerRequest(string uri, string callerKey, string environment, string? cookie = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Add("X-CredProx-Key", callerKey);
        request.Headers.Add("X-API-Env", environment);
        if (cookie is not null)
        {
            request.Headers.Add("Cookie", cookie);
        }

        return request;
    }
}
