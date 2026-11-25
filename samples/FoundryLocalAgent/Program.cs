using CredProx;
using OpenTelemetry;
using OpenTelemetry.Exporter;
using OpenTelemetry.Metrics;
// The local-model agent's gate: a Foundry Local server on this machine's loopback
// speaks the OpenAI chat format and authenticates nothing, and the tool API behind
// /tools/** is a plain HTTP service. The agent is the only caller; it carries its own
// Entra bearer (AddIdentity arms the caller-token leg that validates it against the
// Authority and maps its client id to the caller), and the caller's NAMED operations
// are the tool boundary — a token's roles admit exactly those, so a tool the model
// tries that no named rule admits is refused 403 at the gate and never reaches the
// tool server, and a token from an unlisted client id is refused 401 before routing.
// Agent/ is the agent itself; StubApi/ is the offline stand-in the smoke cells drive
// for both upstreams AND for the token issuer.
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCredProx(builder.Configuration)
    .AddIdentity()
    .AddOperations();
// Metering export: the Operations metering leg emits on the "CredProx" meter —
// per-caller request and byte counts, plus token counts read from the model response's
// usage block because the model route opts in with CredProx.Metering.Usage.
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
