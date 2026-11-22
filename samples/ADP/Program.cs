using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Identity;
using Azure.Extensions.AspNetCore.Configuration.Secrets;
using Azure.Security.KeyVault.Secrets;
using CredProx;

// The CredProx host of the ADP example: one named mTLS connection presented on BOTH the
// token call and the API calls. The style is pure config — the default mode runs on the
// local nginx+WireMock stack; RealAdp / KeyVault / KeyVaultOffline pick the vendor and secret source.
var builder = WebApplication.CreateBuilder(args);

// One secret source per style. The loopback provider is the stock Azure Key Vault
// provider with only the transport swapped — the offline witness needs no Azure account.
var offlineStub = builder.Configuration["KeyVault:OfflineStub"];
var keyVaultUri = builder.Configuration["KeyVault:Uri"];
if (offlineStub is not null)
{
    var reload = builder.Configuration.GetValue<int?>("KeyVault:ReloadIntervalSeconds") ?? 2;
    builder.Configuration.AddAzureKeyVault(
        new SecretClient(
            new Uri("https://credprox-adp-sample.vault.azure.net/"),
            new NoAuthCredential(),
            new SecretClientOptions { Transport = new LoopbackVaultTransport(offlineStub) }),
        new AzureKeyVaultConfigurationOptions { ReloadInterval = TimeSpan.FromSeconds(reload) });
}
else if (keyVaultUri is not null)
{
    var seconds = builder.Configuration.GetValue<int?>("KeyVault:ReloadIntervalSeconds") ?? 30;
    builder.Configuration.AddAzureKeyVault(
        new Uri(keyVaultUri),
        new DefaultAzureCredential(),
        new AzureKeyVaultConfigurationOptions { ReloadInterval = TimeSpan.FromSeconds(seconds) });
}
else if (builder.Configuration["KeyVault:Style"] == "Azure")
{
    // Fail fast and name the fix: silently skipping the provider would die later on an
    // unresolved secret: reference and hide the real cause (a missing vault URI).
    throw new InvalidOperationException(
        "the Key Vault style needs a vault endpoint: set KeyVault:Uri (environment variable " +
        "KeyVault__Uri) to your Key Vault URL, e.g. https://<your-vault>.vault.azure.net/.");
}
else
{
    // generate-certs.sh writes the client-cert PFX bundle key-per-file style; the token
    // client secret stays a plain config secret in the default mode.
    builder.Configuration.AddKeyPerFile(
        Path.Combine(builder.Environment.ContentRootPath, "secrets.d"), optional: true);
}

// The style files load through the environment, before these sources — so exported
// overrides always win.
builder.Configuration.AddEnvironmentVariables();
builder.Configuration.AddCommandLine(args);

builder.Services.AddCredProx(builder.Configuration)
    .AddIdentity();
builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx();

var app = builder.Build();
app.MapReverseProxy();
app.Run();
return 0;

// Offline stand-in so the Key Vault provider never touches a real credential path.
internal sealed class NoAuthCredential : TokenCredential
{
    public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken cancellationToken) =>
        ValueTask.FromResult(new AccessToken("offline-stub", DateTimeOffset.UtcNow.AddHours(1)));

    public override AccessToken GetToken(TokenRequestContext context, CancellationToken cancellationToken) =>
        new("offline-stub", DateTimeOffset.UtcNow.AddHours(1));
}

// Points the real SecretClient at the loopback KV stub, keeping every request path intact
// (the stub serves /secrets/... with the vault wire shape, incl. the trailing-slash form).
internal sealed class LoopbackVaultTransport(string stubBase) : HttpPipelineTransport
{
    private static readonly HttpPipelineTransport Inner = new HttpClientTransport();
    private readonly Uri _base = new(stubBase, UriKind.Absolute);

    public override Request CreateRequest() => Inner.CreateRequest();

    public override void Process(HttpMessage message)
    {
        var saved = Rewrite(message);
        try
        {
            Inner.Process(message);
        }
        finally
        {
            Restore(message, saved);
        }
    }

    public override async ValueTask ProcessAsync(HttpMessage message)
    {
        var saved = Rewrite(message);
        try
        {
            await Inner.ProcessAsync(message).ConfigureAwait(false);
        }
        finally
        {
            Restore(message, saved);
        }
    }

    private (string? Scheme, string? Host, int Port) Rewrite(HttpMessage message)
    {
        var uri = message.Request.Uri;
        var saved = (uri.Scheme, uri.Host, uri.Port);
        uri.Scheme = _base.Scheme;
        uri.Host = _base.Host;
        uri.Port = _base.Port;
        return saved;
    }

    private static void Restore(HttpMessage message, (string? Scheme, string? Host, int Port) saved)
    {
        var uri = message.Request.Uri;
        uri.Scheme = saved.Scheme;
        uri.Host = saved.Host;
        uri.Port = saved.Port;
    }
}
