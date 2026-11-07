using CredProx;

// E11 (plan §6): the operational story — throttling under load with a vendor stub that
// returns 429 + Retry-After, a circuit breaker, and credential health checks. All three
// are config + one registration line each; the behavior lives in the core (plan §8.4).
// WireMock plays the vendor: wiremock/mappings holds the three vendor personalities.
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCredProxTokenCache();
builder.Services.AddCredProxConfigurationSecrets(builder.Configuration);
builder.Services.AddCredProxBuiltInCredentials();
builder.Services.AddCredProxCredentials(builder.Configuration);

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

builder.WebHost.UseUrls("http://localhost:5091");

var app = builder.Build();
app.MapHealthChecks("/health");
app.MapReverseProxy();
app.Run();
return 0;
