using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Identity;
using Azure.Extensions.AspNetCore.Configuration.Secrets;
using Azure.Security.KeyVault.Secrets;
using CredProx;

var builder = WebApplication.CreateBuilder(args);

// Default mode talks to the local stack in docker-compose.yml (no vendor account): nginx
// enforces mTLS (ssl_verify_client on) in front of a WireMock stub of ADP, and the client
// certificate arrives as a base64 passwordless PFX in secrets.d (generate-certs.sh) — the
// original implementation's adp-auth-cert format, fed through CredProx:Secrets.
// --variant real repoints everything at the real ADP endpoints and moves the secrets to
// environment variables or Key Vault — a pure config change, no code change.
// --variant kv sources the secrets from Azure Key Vault through the stock configuration
// provider (see README); --kv-smoke runs the same provider against a loopback stub so the
// rotation witness needs no Azure account.
bool kvMode = args.Contains("kv") || args.Contains("--kv-smoke");
if (args.Contains("real"))
{
    builder.Configuration.AddJsonFile("appsettings.RealAdp.json", optional: false);
}

if (kvMode)
{
    builder.Configuration.AddJsonFile("appsettings.KeyVault.json", optional: false);
    if (args.Contains("--kv-smoke"))
    {
        // The real Azure Key Vault configuration provider with only the transport swapped
        // to the loopback stub on :8082 (same recipe as the soak host). ReloadInterval is
        // explicit because the vendor default is null — the provider never polls without it.
        builder.Configuration.AddAzureKeyVault(
            new SecretClient(
                new Uri("https://credprox-adp-sample.vault.azure.net/"),
                new NoAuthCredential(),
                new SecretClientOptions { Transport = new LoopbackVaultTransport("http://localhost:8082") }),
            new AzureKeyVaultConfigurationOptions { ReloadInterval = TimeSpan.FromSeconds(2) });
    }
    else
    {
        var keyVaultUri = builder.Configuration["KeyVault:Uri"];
        if (string.IsNullOrEmpty(keyVaultUri))
        {
            // Fail fast and name the fix: silently skipping the provider would die later on
            // an unresolved secret: reference and hide the real cause (a missing vault URI).
            throw new InvalidOperationException(
                "--variant kv needs a vault endpoint: set KeyVault:Uri " +
                "(environment variable KeyVault__Uri) to your Key Vault URL, " +
                "e.g. https://<your-vault>.vault.azure.net/.");
        }

        var seconds = builder.Configuration.GetValue<int?>("KeyVault:ReloadIntervalSeconds") ?? 30;
        builder.Configuration.AddAzureKeyVault(
            new Uri(keyVaultUri),
            new DefaultAzureCredential(),
            new AzureKeyVaultConfigurationOptions { ReloadInterval = TimeSpan.FromSeconds(seconds) });
    }
}
else
{
    // generate-certs.sh writes the client-cert PFX bundle key-per-file style; the token
    // client secret stays a plain config secret in offline mode.
    builder.Configuration.AddKeyPerFile(
        Path.Combine(builder.Environment.ContentRootPath, "secrets.d"), optional: true);
}

builder.Services.AddCredProxTokenCache();
builder.Services.AddCredProxConfigurationSecrets(builder.Configuration);
builder.Services.AddCredProxBuiltInCredentials();
builder.Services.AddCredProxCredentials(builder.Configuration);
builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx(builder.Configuration);

builder.WebHost.UseUrls("http://localhost:5086");

var app = builder.Build();
app.MapReverseProxy();

if (args.Contains("--smoke"))
{
    app.Start();
    using var client = new HttpClient { BaseAddress = new Uri("http://localhost:5086") };

    // The API call proves three things at once: the client certificate arrived (nginx
    // injects X-Client-DN, which the stub echoes — the upstream itself names the subject),
    // the bearer is attached (stub echoes Authorization), and the bearer is scrubbed
    // caller-side (the echo shows the redaction, never the raw token).
    var adp = await client.GetAsync("/adp/api/v1/employees");
    var adpBody = await adp.Content.ReadAsStringAsync();
    using var journalClient = new HttpClient();
    using var journal = System.Text.Json.JsonDocument.Parse(
        await journalClient.GetStringAsync("http://localhost:8081/__admin/requests"));
    var records = journal.RootElement.GetProperty("requests").EnumerateArray().ToList();

    var bearerArrived = records.Any(record =>
        record.GetProperty("request").GetProperty("url").GetString() == "/api/v1/employees"
        && record.GetProperty("request").GetProperty("headers").TryGetProperty("Authorization", out var auth)
        && auth.GetString() == "Bearer adp-demo-token");
    var certSeenAtApi = adpBody.Contains("client = CN=client-alpha", StringComparison.Ordinal);

    // Wire check (M36): what CredProx actually puts on the wire for the token call,
    // recorded from the stub's own journal. The original sent POST with an empty body, the
    // grant in the query string, and Basic client auth. CredProx keeps the configured URL
    // verbatim (so the query grant goes out) and additionally sends the OAuth-standard
    // grant_type in the form body; the Basic header matches. Evidence: bin/wire-check.txt
    // (per-run), with the curated copy at samples/ADP/wire-check.txt asserted equal by smoke.
    var tokenRec = default(System.Text.Json.JsonElement);
    var tokenFound = false;
    foreach (var record in records)
    {
        if (record.GetProperty("request").GetProperty("url").GetString()
            == "/auth/oauth/v2/token?grant_type=client_credentials")
        {
            tokenRec = record;
            tokenFound = true;
        }
    }

    var (tokenUrl, tokenBody, tokenBasic) = !tokenFound
        ? ("<none>", "<none>", false)
        : (
            tokenRec.GetProperty("request").GetProperty("url").GetString()!,
            tokenRec.GetProperty("request").TryGetProperty("body", out var b) ? b.GetString() ?? "" : "",
            tokenRec.GetProperty("request").GetProperty("headers")
                .TryGetProperty("Authorization", out var ta) && (ta.GetString() ?? "").StartsWith("Basic ", StringComparison.Ordinal));
    // The per-run artifact goes under bin/ (git-ignored); the committed
    // samples/ADP/wire-check.txt is a curated copy that smoke.sh asserts this against.
    Directory.CreateDirectory("bin");
    await File.WriteAllTextAsync(Path.Combine("bin", "wire-check.txt"),
        $"token request url : {tokenUrl}\n"
        + $"token request body: {tokenBody}\n"
        + $"Basic client auth : {tokenBasic}\n"
        + "original sent     : same url (query grant_type=client_credentials), EMPTY body, Basic header\n"
        + "difference        : CredProx also sends grant_type=client_credentials in the form body\n"
        + "                  (RFC 6749 standard shape); the query parameter is kept verbatim.\n");

    var wireOk = tokenUrl == "/auth/oauth/v2/token?grant_type=client_credentials"
        && tokenBasic
        && tokenBody.Contains("grant_type=client_credentials", StringComparison.Ordinal);

    var adpOk = adp.IsSuccessStatusCode
        && adpBody.Contains("Bearer [redacted]", StringComparison.Ordinal)
        && bearerArrived
        && certSeenAtApi
        && wireOk;

    // Print what THIS run measured (the file just written) — printing the curated copy
    // would show expected evidence in a red run.
    Console.WriteLine(File.ReadAllText(Path.Combine("bin", "wire-check.txt")));
    Console.WriteLine(adpOk
        ? "SMOKE OK: ADP mTLS + bearer attached; cert seen on the API hop; wire check recorded."
        : $"SMOKE FAILED: adp={adpOk} status={(int)adp.StatusCode} body={adpBody} bearer={bearerArrived} certAtApi={certSeenAtApi} wire={wireOk}");
    return adpOk ? 0 : 1;
}

if (args.Contains("--kv-smoke"))
{
    // Offline Key Vault witness: the certificate secret is served by the loopback stub
    // (mapping installed by smoke.sh from the alpha PFX). smoke.sh swaps the stub to the
    // beta PFX mid-run (admin API, bumped attributes.updated); the provider re-reads on its
    // explicit ReloadInterval and the rotation-aware connection registry presents the new
    // certificate on new connections — no restart. nginx has keepalive off, so every
    // request is a fresh handshake and the swap is visible immediately.
    app.Start();
    using var client = new HttpClient { BaseAddress = new Uri("http://localhost:5086") };
    var sawAlpha = false;
    var last = string.Empty;
    for (var attempt = 0; attempt < 60; attempt++)
    {
        try
        {
            var r = await client.GetAsync("/adp/api/v1/employees");
            last = await r.Content.ReadAsStringAsync();
        }
        catch (Exception ex)
        {
            last = ex.Message;
        }

        if (last.Contains("client = CN=client-alpha", StringComparison.Ordinal))
        {
            sawAlpha = true;
        }

        if (sawAlpha && last.Contains("client = CN=client-beta", StringComparison.Ordinal))
        {
            Console.WriteLine("SMOKE OK: rotated Key Vault certificate reached new connections without restart.");
            return 0;
        }

        await Task.Delay(1000);
    }

    Console.WriteLine($"SMOKE FAILED: alpha seen={sawAlpha}; last response: {last}");
    return 1;
}

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
