using CredProx;
using OpenTelemetry;
using OpenTelemetry.Exporter;
using OpenTelemetry.Metrics;

// The AI provider gateway: caller keys in, provider key out, per-caller allow-lists,
// budgets, cluster throttle and audit — all config. StubApi/ is the provider stand-in
// the offline cells drive; a real provider is just a different address and key.
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCredProx(builder.Configuration)
    .AddOperations();

// Metering export (M50): CredProx's Operations metering emits on the "CredProx" meter —
// per-caller request and byte counts, plus token counts on routes that opted in with
// the CredProx.Metering.Usage metadata naming a usage format. OTLP is the default
// exporter; Metrics:Console switches to the console exporter so a local run sees the
// counters without a collector.
builder.Services.AddOpenTelemetry().WithMetrics(metrics =>
{
    metrics.AddMeter("CredProx");
    if (builder.Configuration.GetSection("Metrics").GetValue("Console", false))
    {
        metrics.AddConsoleExporter();
    }
    else
    {
        metrics.AddOtlpExporter();
    }
});

builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx();

var app = builder.Build();
app.MapReverseProxy();
app.Run();
return 0;
