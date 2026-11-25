using CredProx;
using OpenTelemetry;
using OpenTelemetry.Exporter;
using OpenTelemetry.Metrics;
// One CredProx front, two model routes: a Foundry Local server on this machine's
// loopback (OpenAI format, no credential anywhere on that path) and a cloud
// Anthropic route behind a StaticKey the apps never hold. Which route a request
// takes is the URL plus the caller's allow-list — pure config. There is no
// failover and no fallback: if the local model is down the local call fails, and
// nothing reroutes it to the cloud. StubApi/ is the offline stand-in for both
// upstreams that the smoke cells drive.
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCredProx(builder.Configuration)
    .AddOperations();
// Metering export: the Operations metering leg emits on the "CredProx" meter —
// per-caller request and byte counts, plus token counts read from the response
// usage block because each route opts in with CredProx.Metering.Usage (openai on
// the local route, anthropic on the cloud route). OTLP is the default exporter;
// Metrics:Console switches to the console exporter so a local run sees the
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
