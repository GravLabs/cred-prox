using OpenTelemetry;
using OpenTelemetry.Exporter;
using OpenTelemetry.Metrics;

var builder = WebApplication.CreateBuilder(args);

// The deployable host: AddCredProx registers the core defaults, the chained AddIdentity()
// arms the caller-token leg that validates agent OIDC tokens against the Authority in
// appsettings.json, the chained AddOperations() arms the per-caller operation allow-list
// and usage metering, and YARP serves the proxy from config. Who gets admitted to what is
// explained in the README.
builder.Services.AddCredProx(builder.Configuration)
    .AddIdentity()
    .AddOperations();

// Metering export (M50): CredProx's Operations metering emits on the "CredProx" meter —
// per-caller request and byte counts, plus token counts on routes that opted in with
// the CredProx.Metering.Usage metadata with a format name (the model route names
// anthropic, so a live run attributes the agent's Anthropic tokens to the agent's
// caller). Metrics:Console switches to the
// console exporter so a local run sees the counters without a collector.
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
