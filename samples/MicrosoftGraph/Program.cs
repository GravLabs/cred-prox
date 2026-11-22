using Azure.Extensions.AspNetCore.Configuration.Secrets;
using Azure.Identity;
using CredProx;

// The CredProx host of the MicrosoftGraph example: both Entra credential styles live in
// one deployable host, and ASPNETCORE_ENVIRONMENT picks the style — appsettings.OAuth.json
// (client secret) or appsettings.ManagedIdentity.json (secretless managed identity).
var builder = WebApplication.CreateBuilder(args);

// Key Vault as the secret source: with KeyVault__Uri set, the standard provider plugs in
// BEFORE the missing-value check, so a vault secret CredProx--Secrets--graph-client-secret
// answers the secret:graph-client-secret reference — no secret on disk. ReloadInterval is
// explicit because the provider's default (null) never polls a rotated value.
var keyVaultUri = builder.Configuration["KeyVault:Uri"];
if (!string.IsNullOrEmpty(keyVaultUri))
{
    builder.Configuration.AddAzureKeyVault(new Uri(keyVaultUri), new DefaultAzureCredential(),
        new AzureKeyVaultConfigurationOptions { ReloadInterval = TimeSpan.FromSeconds(30) });
}

// The missing-value check guards the client-secret style; the secretless style needs none
// of it. The variant files load through the environment, after the default env-var and
// command-line sources — so CredProx__* overrides must be re-added to outrank them.
builder.Configuration.AddEnvironmentVariables();
builder.Configuration.AddCommandLine(args);
if (builder.Configuration["CredProx:Credentials:graph:Type"] != "TokenCredential")
{
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
            "Register an app in Entra ID and set them — see README.md — or run the " +
            "secretless style with ASPNETCORE_ENVIRONMENT=ManagedIdentity.");
        return 1;
    }
}

// Both credential add-ons chain always; the loaded config declares which style is
// active, and a registered but unused credential type is harmless.
builder.Services.AddCredProx(builder.Configuration)
    .AddIdentity()
    .AddAzure(new DefaultAzureCredential());

builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx();

var app = builder.Build();
app.MapReverseProxy();
app.Run();
return 0;
