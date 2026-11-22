using CredProx;

// The operational story on one host: throttling (rate/concurrency limits with a bounded
// queue), a circuit breaker with retry policy, and background credential-health probes.
// All three are appsettings.json plus one chained call; WireMock is the vendor.
var builder = WebApplication.CreateBuilder(args);

// The chained AddOperations() arms each leg that has its own section: per-cluster
// outbound rate/concurrency limits with a bounded queue (full or expired queue ->
// 429 + Retry-After) and a vendor-429 pause of the whole cluster (CredProx:Throttling);
// retry (idempotent only), attempt timeout, and a per-cluster circuit breaker (open
// circuit -> 503 without reaching the upstream, half-open after the break)
// (CredProx:Resilience); and background credential-health probes (token obtainable,
// certificate expiry) feeding the "credprox" ASP.NET Core health check
// (CredProx:Health). No section, no leg.
builder.Services.AddCredProx(builder.Configuration)
    .AddOperations();

builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx();

var app = builder.Build();
app.MapHealthChecks("/health");
app.MapReverseProxy();
app.Run();
