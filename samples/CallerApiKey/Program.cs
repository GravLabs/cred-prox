using CredProx;

var builder = WebApplication.CreateBuilder(args);

// E18: callers authenticate to the proxy with an API key, separately from whatever
// credential the proxy attaches downstream. The key is validated against a secret-backed
// store (SHA-256 hashes, constant-time compare; never a literal in a route match), and
// CredProx strips the key header before forwarding — the upstream stub never sees it.
// Missing and wrong keys get the same refusal so callers can't enumerate valid keys.
builder.Services.AddCredProxTokenCache();
builder.Services.AddCredProxConfigurationSecrets(builder.Configuration);
builder.Services.AddCredProxBuiltInCredentials();
builder.Services.AddCredProxCredentials(builder.Configuration);
builder.Services.AddCredProxCallerAuthentication(builder.Configuration);
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
    const string goodKey = "demo-caller-key-2026";
    const string wrongKey = "demo-caller-key-WRONG";

    // 1) Missing key -> 401.
    var missing = await client.GetAsync("/api/data");

    // 2) Wrong key -> the SAME 401 (indistinguishable from missing), and nothing about
    //    the presented key is echoed back.
    using (var request = new HttpRequestMessage(HttpMethod.Get, "/api/data"))
    {
        request.Headers.Add("X-API-Key", wrongKey);
        var wrong = await client.SendAsync(request);
        var wrongBody = await wrong.Content.ReadAsStringAsync();
        if (wrong.StatusCode != System.Net.HttpStatusCode.Unauthorized
            || wrongBody.Contains(wrongKey, StringComparison.Ordinal))
        {
            Console.WriteLine($"SMOKE FAILED: wrong key got {(int)wrong.StatusCode} echoing '{wrongBody}'");
            return 1;
        }
    }

    // 3) Accepted key -> proxied 200.
    using (var request = new HttpRequestMessage(HttpMethod.Get, "/api/data"))
    {
        request.Headers.Add("X-API-Key", goodKey);
        var ok = await client.SendAsync(request);
        if (!ok.IsSuccessStatusCode)
        {
            Console.WriteLine($"SMOKE FAILED: valid key rejected: {(int)ok.StatusCode}");
            return 1;
        }
    }

    if (missing.StatusCode != System.Net.HttpStatusCode.Unauthorized)
    {
        Console.WriteLine($"SMOKE FAILED: missing key got {(int)missing.StatusCode}, want 401");
        return 1;
    }

    // 4) The stub's own journal proves the key never reached the upstream — not under
    //    its own name, not under the default caller header.
    using var journalClient = new HttpClient();
    using var journal = System.Text.Json.JsonDocument.Parse(
        await journalClient.GetStringAsync("http://localhost:8081/__admin/requests"));
    var records = journal.RootElement.GetProperty("requests").EnumerateArray()
        .Where(r => r.GetProperty("request").GetProperty("url").GetString() == "/api/data")
        .ToList();
    var leaked = records.Any(r =>
    {
        var headers = r.GetProperty("request").GetProperty("headers");
        return headers.TryGetProperty("X-API-Key", out _) || headers.TryGetProperty("X-CredProx-Key", out _);
    });
    if (leaked || records.Count == 0)
    {
        Console.WriteLine($"SMOKE FAILED: key header reached the upstream (records={records.Count}, leaked={leaked})");
        return 1;
    }

    Console.WriteLine("SMOKE OK: caller key enforced (401 missing == 401 wrong, no echo) and stripped before forwarding.");
    return 0;
}

app.Run();
return 0;
