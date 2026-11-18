using System.Security.Cryptography;
using System.Text;
using CredProx;

var builder = WebApplication.CreateBuilder(args);

// The Hmac credential against a local signature-verifying stub. The canonical-string
// recipe lives entirely in appsettings.json — method, path, timestamp and body hash,
// HMAC-SHA256, written to X-Signature/X-Timestamp. Buffering is opt-in with a size cap.

// AddCredProx registers the core defaults; the Hmac credential type joins them as an
// add-on.
builder.Services.AddCredProx(builder.Configuration);
builder.Services.AddCredProxHmac();

builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx(builder.Configuration);

var app = builder.Build();

const string SharedKey = "demo-shared-key";

// The stub vendor: an INDEPENDENT verifier of the same documented layout
// (METHOD \n PATH \n UNIX-SECONDS \n sha256-hex(body), HMAC-SHA256 lowercase hex).
// It shares no code with CredProx — exactly how a real vendor's verifier works. It is
// the offline stand-in for the vendor, kept deliberately in this project so the example
// is verifiable with no Docker and no vendor account; the cells drive it over the socket.
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
app.Run();
