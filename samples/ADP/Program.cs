using CredProx;

var builder = WebApplication.CreateBuilder(args);

// Default mode talks to the WireMock stub in docker-compose.yml (no vendor account).
// --variant real repoints everything at the real ADP endpoint and moves the secrets to
// environment variables — a pure config change, no code change.
if (args.Contains("real"))
{
    builder.Configuration.AddJsonFile("appsettings.RealAdp.json", optional: false);
}

builder.Services.AddCredProxTokenCache();
builder.Services.AddCredProxConfigurationSecrets(builder.Configuration);
builder.Services.AddCredProxBuiltInCredentials();
builder.Services.AddCredProxCredentials(builder.Configuration);
builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx(builder.Configuration);

builder.WebHost.UseUrls("http://localhost:5086");

var app = builder.Build();
app.MapReverseProxy();

if (args.Contains("--smoke"))
{
    app.Start();
    using var client = new HttpClient { BaseAddress = new Uri("http://localhost:5086") };

    // ADP: OAuth client credentials fetched from the stub and attached as a bearer token.
    // Since M20 (§8.2) the bearer is scrubbed from the caller's echo, so attachment is
    // proven two ways: the caller's body carries the redaction, and WireMock's request
    // journal — the stub's own record — shows the raw bearer on the proxied request's
    // Authorization header (the token endpoint's recorded response also carries the token,
    // so a bare "journal contains the token" would prove nothing).
    var adp = await client.GetAsync("/adp/api/v1/employees");
    var adpBody = await adp.Content.ReadAsStringAsync();
    using var journalClient = new HttpClient();
    using var journal = System.Text.Json.JsonDocument.Parse(
        await journalClient.GetStringAsync("http://localhost:8081/__admin/requests"));
    var bearerArrived = journal.RootElement.GetProperty("requests").EnumerateArray().Any(record =>
        record.GetProperty("request").GetProperty("url").GetString() == "/adp/api/v1/employees"
        && record.GetProperty("request").GetProperty("headers").TryGetProperty("Authorization", out var auth)
        && auth.GetString() == "Bearer adp-demo-token");
    var adpOk = adp.IsSuccessStatusCode
        && adpBody.Contains("Bearer [redacted]", StringComparison.Ordinal)
        && bearerArrived;

    Console.WriteLine(adpOk
        ? "SMOKE OK: ADP bearer attached."
        : $"SMOKE FAILED: adp={adpOk} ({(int)adp.StatusCode} {adpBody})");
    return adpOk ? 0 : 1;
}

app.Run();
return 0;
