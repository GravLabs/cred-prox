using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CredProx;

var builder = WebApplication.CreateBuilder(args);

// E8 (plan §6): JwtAssertion -> GitHub App installation token -> GitHub REST API.
// The credential is the generic JwtAssertion type in BearerExchange mode: CredProx mints
// an RS256 app JWT (iss = app id, aud = api.github.com, fresh jti), presents it as
// Authorization: Bearer to the installation-access-tokens endpoint, caches the returned
// installation token until its expires_at, and attaches it to every forwarded request.
// All of GitHub's flow is plain config in appsettings.json: RS256, aud, the 9-minute
// lifetime, BearerExchange, the token/expires_at response shape and the signing-key
// secret reference — plus the App's own id and installation endpoint.
builder.Services.AddCredProxTokenCache();
builder.Services.AddCredProxConfigurationSecrets(builder.Configuration);
builder.Services.AddCredProxBuiltInCredentials();
builder.Services.AddCredProxCredentials(builder.Configuration);
builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx(builder.Configuration);

// --smoke runs against in-process stubs instead of GitHub, so the example is verifiable
// offline (CI): a generated RSA key stands in for the App's private key and both GitHub
// endpoints are mapped below. The key outlives the setup block because the token-endpoint
// stub verifies the app JWT with it while the smoke request is in flight.
const string StubInstallationToken = "ghs_stub_installation";
var smoke = args.Contains("--smoke");
RSA? stubKey = null;
if (smoke)
{
    stubKey = RSA.Create(2048);
    builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
    {
        ["CredProx:Secrets:github-app-signing-key"] = stubKey.ExportPkcs8PrivateKeyPem(),
        ["CredProx:Destinations:github:Template"] = "http://localhost:5081",
        ["CredProx:Credentials:github-app:TokenEndpoint"] = "http://localhost:5081/app/installations/789012/access_tokens",
        ["ReverseProxy:Clusters:github:Destinations:github:Address"] = "http://localhost:5081/",
    });
}

builder.WebHost.UseUrls("http://localhost:5081");

var app = builder.Build();

if (smoke)
{
    // GitHub's installation-access-tokens endpoint stand-in. It verifies the app JWT
    // with an independent implementation — signature against the generated public key
    // plus the claim essentials — the way GitHub's verifier does.
    app.MapPost("/app/installations/{installationId}/access_tokens", async (HttpContext context) =>
    {
        var header = context.Request.Headers.Authorization.ToString();
        var jwt = header.StartsWith("Bearer ", StringComparison.Ordinal) ? header["Bearer ".Length..] : "";
        var parts = jwt.Split('.');

        if (jwt.Length == 0 || parts.Length != 3 || !VerifyJwt(stubKey!, parts))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsync("""{"message":"JWT verification failed"}""");
            return;
        }

        context.Response.StatusCode = StatusCodes.Status201Created;
        await context.Response.WriteAsync(
            $$"""{"token":"{{StubInstallationToken}}","expires_at":"{{DateTime.UtcNow.AddHours(1):yyyy-MM-ddTHH:mm:ssZ}}"}""");
    });

    // A GitHub REST endpoint stand-in: reports the Authorization it received.
    app.Map("/repos/{owner}/{repo}", (HttpContext context) =>
        context.Response.WriteAsync(
            JsonSerializer.Serialize(new { authorization = context.Request.Headers.Authorization.ToString() })));
}

app.MapReverseProxy();

if (smoke)
{
    app.Start();
    using var client = new HttpClient();
    var response = await client.GetAsync("http://localhost:5081/github/repos/octocat/hello-world");
    var body = await response.Content.ReadAsStringAsync();
    stubKey!.Dispose();
    var ok = response.IsSuccessStatusCode
        && body.Contains($"Bearer {StubInstallationToken}", StringComparison.Ordinal);
    Console.WriteLine(ok
        ? "SMOKE OK: the stub verified the app JWT and GitHub saw the cached installation token."
        : $"SMOKE FAILED ({(int)response.StatusCode}): {body}");
    return ok ? 0 : 1;
}

app.Run();
return 0;

static bool VerifyJwt(RSA publicKey, string[] parts)
{
    try
    {
        var signingInput = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
        var signature = Convert.FromBase64String(
            parts[2].Replace('-', '+').Replace('_', '/') + new string('=', (4 - parts[2].Length % 4) % 4));
        if (!publicKey.VerifyData(signingInput, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
        {
            return false;
        }

        var payloadJson = Encoding.UTF8.GetString(Convert.FromBase64String(
            parts[1].Replace('-', '+').Replace('_', '/') + new string('=', (4 - parts[1].Length % 4) % 4)));
        using var payload = JsonDocument.Parse(payloadJson);
        var root = payload.RootElement;
        return root.GetProperty("iss").GetString() == "123456"
            && root.GetProperty("aud").GetString() == "https://api.github.com"
            && root.GetProperty("exp").GetInt64() > DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            && !string.IsNullOrEmpty(root.GetProperty("jti").GetString());
    }
    catch (Exception ex) when (ex is CryptographicException or FormatException or JsonException or InvalidOperationException)
    {
        return false;
    }
}
