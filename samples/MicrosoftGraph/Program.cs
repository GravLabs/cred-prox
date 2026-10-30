using Azure.Identity;
using CredProx;
// AddCredProxAzureTokenCredential lives in Microsoft.Extensions.DependencyInjection
// (implicit using) — no extra using needed for the add-on.

var builder = WebApplication.CreateBuilder(args);

// --variant identity: no stored secret anywhere. The TokenCredential credential type takes
// an Azure TokenCredential — a user-assigned managed identity in Azure, the Azure CLI or
// VS credentials during development — and mints Graph tokens from it.
if (args.Contains("identity"))
{
    builder.Configuration.AddJsonFile("appsettings.ManagedIdentity.json", optional: false);
    builder.Services.AddCredProxAzureTokenCredential(new DefaultAzureCredential());
}
else
{
    // The client-credentials credential in its own file: CredProx rejects keys the active
    // credential Type does not declare, so the two variants keep separate declarations
    // instead of layering nulls over each other's fields.
    builder.Configuration.AddJsonFile("appsettings.OAuth.json", optional: false);

    // The variant file was added after the default env-var and command-line sources, so
    // re-add them: CredProx__* env vars (and a --CredProx:... command-line override)
    // must outrank the file's <tenant-id> placeholders.
    builder.Configuration.AddEnvironmentVariables();
    builder.Configuration.AddCommandLine(args);

    var missing = new List<string>();
    if (builder.Configuration["CredProx:Credentials:graph:TokenEndpoint"]?.Contains("<tenant-id>") ?? true)
    {
        missing.Add("CredProx__Credentials__graph__TokenEndpoint (replace <tenant-id>)");
    }

    if (string.IsNullOrEmpty(builder.Configuration["CredProx:Credentials:graph:ClientId"]))
    {
        missing.Add("CredProx__Credentials__graph__ClientId");
    }

    if (string.IsNullOrEmpty(builder.Configuration["CredProx:Secrets:graph-client-secret"]))
    {
        missing.Add("CredProx__Secrets__graph-client-secret");
    }

    if (missing.Count > 0)
    {
        Console.Error.WriteLine(
            "error: missing required values: " + string.Join(", ", missing) + "\n" +
            "Register an app in Entra ID and set them — see README.md.");
        return 1;
    }
}

// Key Vault as the secret source (plan §6 E5): CredProx reads secrets through ordinary
// IConfiguration, so the standard Azure Key Vault configuration provider plugs in here —
// add the package Azure.Extensions.AspNetCore.Configuration.Secrets and uncomment:
//
// builder.Configuration.AddAzureKeyVault(
//     new Uri("https://<your-vault>.vault.azure.net/"), new DefaultAzureCredential());
//
// A vault secret named "CredProx--Secrets--graph-client-secret" then answers the
// secret:graph-client-secret reference the base config declares, with nothing else
// to change.

builder.Services.AddCredProxTokenCache();
builder.Services.AddCredProxConfigurationSecrets(builder.Configuration);
builder.Services.AddCredProxBuiltInCredentials();
builder.Services.AddCredProxCredentials(builder.Configuration);
builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx(builder.Configuration);

builder.WebHost.UseUrls("http://localhost:5085");

var app = builder.Build();
app.MapReverseProxy();
app.Run();
return 0;
