using Azure.Extensions.AspNetCore.Configuration.Secrets;
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

    // Same re-add as the OAuth branch below: the variant file loads after the default
    // env-var/command-line sources, so without this CredProx__* overrides (e.g. the
    // ARM scope the live smoke battery uses) would silently lose to the file.
    builder.Configuration.AddEnvironmentVariables();
    builder.Configuration.AddCommandLine(args);

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

    // Key Vault as the secret source (plan §6 E5): with a vault URI configured, the standard
    // Azure Key Vault configuration provider plugs in BEFORE the missing-value check - a vault
    // secret named "CredProx--Secrets--graph-client-secret" then answers the
    // secret:graph-client-secret reference the config declares (the provider maps -- to :),
    // with no secret on disk and none passed by the operator. Enable with
    // KeyVault__Uri=https://<vault>.vault.azure.net/ or --KeyVault:Uri ....
    // ReloadInterval must be set EXPLICITLY for a running process to ever see a rotated
    // vault value: the provider's default is null = it never polls (a restart otherwise).
    var keyVaultUri = builder.Configuration["KeyVault:Uri"];
    if (!string.IsNullOrEmpty(keyVaultUri))
    {
        builder.Configuration.AddAzureKeyVault(new Uri(keyVaultUri), new DefaultAzureCredential(),
            new AzureKeyVaultConfigurationOptions { ReloadInterval = TimeSpan.FromSeconds(30) });
    }

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

// When KeyVault:Uri is set, the provider wired above feeds the secret through the same
// IConfiguration to AddCredProxConfigurationSecrets: secret material enters the process only
// from the real vault. Rotation = overwrite the vault secret; the new value is picked up at
// the next process start (the token cache already holds a minted token, so a same-process
// reload only bites at token refresh) - scripts/live-azure-smoke.sh phase4 proves exactly this
// overwrite -> restart -> new-value cycle against a real vault.

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
