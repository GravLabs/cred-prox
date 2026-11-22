using CredProx;

var builder = WebApplication.CreateBuilder(args);

// Two variants, pure configuration: the default upstream is the compose nginx; setting
// ASPNETCORE_ENVIRONMENT=Badssl makes the host load appsettings.Badssl.json, pointing the
// same connection and route at the public client.badssl.com endpoint.

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

// The deployable host: AddCredProx registers the core defaults (the client certificate
// above is one of the secrets they read), and YARP serves the proxy from config.
builder.Services.AddCredProx(builder.Configuration);

builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx();

var app = builder.Build();

app.MapReverseProxy();
app.Run();
return 0;
