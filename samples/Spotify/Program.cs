using CredProx;

var builder = WebApplication.CreateBuilder(args);

// Fail early and name the missing values (plan §6 quality bar) instead of failing deep
// inside a token fetch.
var missing = new List<string>();
if (string.IsNullOrEmpty(builder.Configuration["CredProx:Credentials:spotify:ClientId"]))
{
    missing.Add("CredProx__Credentials__spotify__ClientId");
}

if (string.IsNullOrEmpty(builder.Configuration["CredProx:Secrets:spotify-client-secret"]))
{
    missing.Add("CredProx__Secrets__spotify-client-secret");
}

if (missing.Count > 0)
{
    Console.Error.WriteLine(
        "error: missing required values: " + string.Join(", ", missing) + "\n" +
        "Create a free app at https://developer.spotify.com/dashboard and set them as\n" +
        "environment variables or user-secrets — see README.md.");
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

builder.WebHost.UseUrls("http://localhost:5084");

var app = builder.Build();
app.MapReverseProxy();
app.Run();
return 0;
