using Azure.Extensions.AspNetCore.Configuration.Secrets;
using Azure.Identity;
using CredProx;

// The Azure Container Apps deployment host: caller keys at the internal ingress, the
// vendor credential arriving from Key Vault, the vault itself reached by the app's
// managed identity. Vendor facts are config only — README.md walks the deploy through.
var builder = WebApplication.CreateBuilder(args);

// With KeyVault__Uri set (the Container Apps run) the stock provider plugs in over the
// ambient managed identity, so a vault secret CredProx--Secrets--<name> answers the
// secret:<name> reference and nothing secret is on disk; ReloadInterval is explicit
// because the provider default (null) never polls a rotated value. Without a vault URI
// the secret: refs fall back to plain config (env/user-secrets), as in every sample.
var keyVaultUri = builder.Configuration["KeyVault:Uri"];
if (!string.IsNullOrEmpty(keyVaultUri))
{
    builder.Configuration.AddAzureKeyVault(new Uri(keyVaultUri), new DefaultAzureCredential(),
        new AzureKeyVaultConfigurationOptions { ReloadInterval = TimeSpan.FromSeconds(30) });
}

// Callers authenticate to the proxy with an API key (SHA-256 hashes, constant-time
// compare); everything else is the config-driven core.
builder.Services.AddCredProx(builder.Configuration);

builder.Services.AddHealthChecks();
builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx();

var app = builder.Build();

// Container Apps liveness/readiness probes point here (plain 200, no credential);
// proxy routes start at /acme.
app.MapHealthChecks("/health");
app.MapReverseProxy();
app.Run();
return 0;
