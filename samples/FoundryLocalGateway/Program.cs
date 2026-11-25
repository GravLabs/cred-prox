using CredProx;
using OpenTelemetry;
using OpenTelemetry.Exporter;
using OpenTelemetry.Metrics;

// The local AI gateway: a Foundry Local server on this machine's loopback speaks the
// OpenAI wire format and authenticates nothing — CredProx in front of it is the only
// gate. Callers authenticate with their own X-CredProx-Key, each caller's Operations
// list is its allow-list, and the OpenAI usage block is metered per caller through the
// route's usage format. StubApi/ is the offline stand-in the smoke cells drive; a real
// Foundry Local is just the loopback address in appsettings.json.
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCredProx(builder.Configuration)
    .AddOperations();

// Metering export: the Operations metering leg emits on the "CredProx" meter —
// per-caller request and byte counts, plus token counts read from the response usage
// block because the route opts in with CredProx.Metering.Usage. OTLP is the default
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
