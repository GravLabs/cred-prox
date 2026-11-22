using CredProx;

var builder = WebApplication.CreateBuilder(args);

// Callers authenticate to the proxy with an API key, validated against a secret-backed
// store (SHA-256 hashes, constant-time compare) and stripped before forwarding. Missing
// and wrong keys get the same refusal, so valid keys cannot be enumerated.

// AddCredProx registers the core defaults; a caller key hash under CredProx:Callers arms
// the caller-key scheme with no extra call.
builder.Services.AddCredProx(builder.Configuration);

builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx();

var app = builder.Build();

app.MapReverseProxy();
app.Run();
