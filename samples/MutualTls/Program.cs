using CredProx;

var builder = WebApplication.CreateBuilder(args);

// --variant badssl switches the upstream to the public client.badssl.com endpoint, using
// BadSSL's published test certificate. Everything else — the connection, the route — is the
// same config.
if (args.Contains("badssl"))
{
    builder.Configuration.AddJsonFile("appsettings.Badssl.json", optional: false);
}

// The client certificate bundle lives in secrets.d/ as a key-per-file entry (the file
// CredProx__Secrets__client-cert holds the PEM bundle). The provider watches the directory,
// so replacing the file rotates the certificate live — see the rotation walkthrough in the
// README.
builder.Configuration.AddKeyPerFile(
    Path.Combine(builder.Environment.ContentRootPath, "secrets.d"), optional: true);

if (builder.Configuration["CredProx:Secrets:client-cert"] is null)
{
    Console.Error.WriteLine(
        "error: the client certificate secret 'client-cert' is not configured.\n" +
        "  local variant: run ./generate-certs.sh\n" +
        "  badssl variant: download BadSSL's published certificate into secrets.d/ — see README.md");
    return 1;
}

builder.Services.AddCredProxTokenCache();
builder.Services.AddCredProxConfigurationSecrets(builder.Configuration);
builder.Services.AddCredProxBuiltInCredentials();
builder.Services.AddCredProxCredentials(builder.Configuration);
builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx(builder.Configuration);

builder.WebHost.UseUrls("http://localhost:5083");

var app = builder.Build();
app.MapReverseProxy();

if (args.Contains("--smoke"))
{
    app.Start();
    using var client = new HttpClient();
    var response = await client.GetAsync("http://localhost:5083/");
    var body = await response.Content.ReadAsStringAsync();
    var ok = response.IsSuccessStatusCode && body.Contains("CN=client-alpha", StringComparison.Ordinal);
    Console.WriteLine(ok
        ? "SMOKE OK: nginx verified the client certificate and echoed its subject."
        : $"SMOKE FAILED ({(int)response.StatusCode}): {body}");
    return ok ? 0 : 1;
}

app.Run();
return 0;
