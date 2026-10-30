using CredProx;

var builder = WebApplication.CreateBuilder(args);

// The whole CredProx surface in a host: token cache, the configuration-backed secret
// source, the built-in credential types, and the credentials/destinations/connections
// bound from configuration below.
builder.Services.AddCredProxTokenCache();
builder.Services.AddCredProxConfigurationSecrets(builder.Configuration);
builder.Services.AddCredProxBuiltInCredentials();
builder.Services.AddCredProxCredentials(builder.Configuration);
builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx(builder.Configuration);

// --smoke runs against an in-process echo stand-in instead of the public service, so the
// example is verifiable offline (CI). The stand-in answers /upstream/headers with the
// headers it received — exactly what postman-echo.com/headers does.
const string SmokeEchoPath = "/upstream/headers";
if (args.Contains("--smoke"))
{
    builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
    {
        ["CredProx:Destinations:echo:Template"] = "http://localhost:5080/upstream",
        ["ReverseProxy:Clusters:echo:Destinations:echo:Address"] = "http://localhost:5080/",
    });
}

builder.WebHost.UseUrls("http://localhost:5080");

var app = builder.Build();

if (args.Contains("--smoke"))
{
    app.Map(SmokeEchoPath, (HttpContext context) =>
        context.Response.WriteAsync(System.Text.Json.JsonSerializer.Serialize(
            context.Request.Headers.ToDictionary(h => h.Key, h => h.Value.ToString()))));
}

app.MapReverseProxy();

if (args.Contains("--smoke"))
{
    app.Start();
    using var client = new HttpClient();
    var response = await client.GetAsync("http://localhost:5080/echo/headers");
    var body = await response.Content.ReadAsStringAsync();
    var ok = response.IsSuccessStatusCode && body.Contains("demo-static-key", StringComparison.Ordinal);
    Console.WriteLine(ok ? "SMOKE OK: the upstream saw the X-API-Key header CredProx attached."
        : $"SMOKE FAILED ({(int)response.StatusCode}): {body}");
    return ok ? 0 : 1;
}

app.Run();
return 0;
