using CredProx;

// The operational story on one host: throttling (rate/concurrency limits with a bounded
// queue), a circuit breaker with retry policy, and background credential-health probes.
// All three are appsettings.json plus one registration line each; WireMock is the vendor.
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCredProx(builder.Configuration);

// Per-cluster outbound rate/concurrency limits with a bounded queue (full or expired
// queue -> 429 + Retry-After) and a vendor-429 pause of the whole cluster.
builder.Services.AddCredProxThrottling(builder.Configuration);

// Retry (idempotent only), attempt timeout, and a per-cluster circuit breaker
// (open circuit -> 503 without reaching the upstream, half-open after the break).
builder.Services.AddCredProxResilience(builder.Configuration);

builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx(builder.Configuration);

// Background credential-health probes (token obtainable, certificate expiry) feeding the
// "credprox" ASP.NET Core health check. Registered last: the probes read the credential
// and destination registries.
builder.Services.AddCredProxHealthProbes(builder.Configuration);

var app = builder.Build();
app.MapHealthChecks("/health");
app.MapReverseProxy();
app.Run();
