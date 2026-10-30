using System.Security.Cryptography;
using System.Text;
using CredProx;

var builder = WebApplication.CreateBuilder(args);

// E9 (plan §6): the Hmac credential against a local signature-verifying stub. The
// canonical-string recipe lives entirely in appsettings.json — method, path, timestamp
// and body hash joined by newlines, HMAC-SHA256, lowercase hex, written to X-Signature
// with the timestamp in X-Timestamp. Buffering is opt-in per credential with a size cap;
// the /small route shows the cap answering 413 credprox.body_too_large_to_sign.
builder.Services.AddCredProxTokenCache();
builder.Services.AddCredProxConfigurationSecrets(builder.Configuration);
builder.Services.AddCredProxBuiltInCredentials();
builder.Services.AddCredProxCredentials(builder.Configuration);
builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx(builder.Configuration);

builder.WebHost.UseUrls("http://localhost:5080");

var app = builder.Build();

const string SharedKey = "demo-shared-key";

// The stub vendor: an INDEPENDENT verifier of the same documented layout
// (METHOD \n PATH \n UNIX-SECONDS \n sha256-hex(body), HMAC-SHA256 lowercase hex).
// It shares no code with CredProx — exactly how a real vendor's verifier works.
app.Map("/verify", async (HttpContext context) =>
{
    using var reader = new StreamReader(context.Request.Body, Encoding.UTF8);
    var body = await reader.ReadToEndAsync();

    var signature = context.Request.Headers["X-Signature"].ToString();
    var timestamp = context.Request.Headers["X-Timestamp"].ToString();
    var canonical = string.Join('\n',
        context.Request.Method,
        context.Request.Path,
        timestamp,
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(body))).ToLowerInvariant());
    var expected = Convert.ToHexString(HMACSHA256.HashData(
        Encoding.UTF8.GetBytes(SharedKey), Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();

    context.Response.StatusCode = signature == expected ? StatusCodes.Status200OK : StatusCodes.Status401Unauthorized;
    await context.Response.WriteAsync(signature == expected ? "signature valid" : "signature invalid");
});

app.MapReverseProxy();

if (args.Contains("--smoke"))
{
    app.Start();
    using var client = new HttpClient();

    // 1. A signed POST flows and the vendor's independent verifier accepts it.
    var post = await client.PostAsync("http://localhost:5080/api/verify",
        new StringContent("{\"order\":42}"));
    var postBody = await post.Content.ReadAsStringAsync();
    var signedOk = post.IsSuccessStatusCode && postBody.Contains("signature valid", StringComparison.Ordinal);

    // 2. The buffering cap answers 413 with the documented code before forwarding.
    var overCap = await client.PostAsync("http://localhost:5080/small/verify",
        new StringContent(new string('x', 100)));
    var overCapBody = await overCap.Content.ReadAsStringAsync();
    var capOk = (int)overCap.StatusCode == 413
        && overCapBody.Contains("credprox.body_too_large_to_sign", StringComparison.Ordinal);

    var ok = signedOk && capOk;
    Console.WriteLine(ok
        ? "SMOKE OK: the vendor verified the HMAC signature, and the size cap answered 413."
        : $"SMOKE FAILED: signed={(int)post.StatusCode} {postBody}; cap={(int)overCap.StatusCode} {overCapBody}");
    return ok ? 0 : 1;
}

app.Run();
return 0;
