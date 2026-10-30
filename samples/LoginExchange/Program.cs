using CredProx;

var builder = WebApplication.CreateBuilder(args);

// E12 (plan §6): the LoginExchange credential type against a vendor-neutral stub — a
// vendor with no OAuth at all: POST a per-environment service account, get a session
// token back. The {partition} template and the Partition allow-list make ONE credential
// serve many environments while blocking the ones not admitted. Everything is plain
// config; the WireMock mappings in wiremock/mappings stand in for the vendor.
builder.Services.AddCredProxTokenCache();
builder.Services.AddCredProxConfigurationSecrets(builder.Configuration);
builder.Services.AddCredProxBuiltInCredentials();
builder.Services.AddCredProxCredentials(builder.Configuration);
builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx(builder.Configuration);

builder.WebHost.UseUrls("http://localhost:5087");

var app = builder.Build();
app.MapReverseProxy();

if (args.Contains("--smoke"))
{
    app.Start();
    using var client = new HttpClient { BaseAddress = new Uri("http://localhost:5087") };

    // 1. UAT: the login exchange runs for the partition and the session token is
    //    attached. Since M20 (§8.2) the stub's echo of the Authorization header is
    //    scrubbed before the caller sees it, so attachment is proven two ways: the
    //    caller's body carries the redaction, and WireMock's request journal — the
    //    stub's own record of what arrived — carries the raw session.
    using var journalClient = new HttpClient();

    using var uat = new HttpRequestMessage(HttpMethod.Get, "/acme/api/v1/timeoff");
    uat.Headers.Add("X-API-Env", "uat");
    var uatResponse = await client.SendAsync(uat);
    var uatBody = await uatResponse.Content.ReadAsStringAsync();
    var uatJournal = await journalClient.GetStringAsync("http://localhost:8082/__admin/requests");
    var uatOk = uatResponse.IsSuccessStatusCode
        && uatBody.Contains("Authorization = [redacted]", StringComparison.Ordinal)
        && uatJournal.Contains("sess-uat-svc", StringComparison.Ordinal)
        && !uatJournal.Contains("sess-staging-svc", StringComparison.Ordinal); // not uat's call

    // 2. Staging: a different partition runs its own login — its own session, cached
    //    separately from uat's (the uat journal above already proved uat's call carried
    //    only its own session; this one shows staging arrived carrying staging's).
    using var staging = new HttpRequestMessage(HttpMethod.Get, "/acme/api/v1/timeoff");
    staging.Headers.Add("X-API-Env", "staging");
    var stagingResponse = await client.SendAsync(staging);
    var stagingBody = await stagingResponse.Content.ReadAsStringAsync();
    var stagingJournal = await journalClient.GetStringAsync("http://localhost:8082/__admin/requests");
    var stagingOk = stagingResponse.IsSuccessStatusCode
        && stagingBody.Contains("Authorization = [redacted]", StringComparison.Ordinal)
        && stagingJournal.Contains("sess-staging-svc", StringComparison.Ordinal);

    // 3. Prod: the partition allow-list blocks it before any vendor call.
    using var prod = new HttpRequestMessage(HttpMethod.Get, "/acme/api/v1/timeoff");
    prod.Headers.Add("X-API-Env", "prod");
    var prodResponse = await client.SendAsync(prod);
    var prodBody = await prodResponse.Content.ReadAsStringAsync();
    var prodOk = prodResponse.StatusCode == System.Net.HttpStatusCode.BadRequest
        && prodBody.Contains("credprox.partition_not_allowed", StringComparison.Ordinal);

    var ok = uatOk && stagingOk && prodOk;
    Console.WriteLine(ok
        ? "SMOKE OK: per-partition login-exchange sessions attached, prod partition blocked."
        : $"SMOKE FAILED: uat={uatOk} ({(int)uatResponse.StatusCode} {uatBody}), staging={stagingOk} ({(int)stagingResponse.StatusCode} {stagingBody}), prod-blocked={prodOk} ({(int)prodResponse.StatusCode} {prodBody})");
    return ok ? 0 : 1;
}

app.Run();
return 0;
