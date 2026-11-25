using Azure.Identity;
using CredProx;
using OpenTelemetry;
using OpenTelemetry.Exporter;
using OpenTelemetry.Metrics;

// The Azure OpenAI gateway: caller key in, short-lived Entra token out. Callers authenticate to
// CredProx with their own X-CredProx-Key; CredProx authenticates to Azure OpenAI with a Microsoft
// Entra token (scope https://cognitiveservices.azure.com/.default) acquired from the deployment's
// managed identity, or from your az sign-in when running locally — DefaultAzureCredential picks
// whichever it finds first. There is no API key anywhere in this sample. Each caller's Operations
// list is its deployment allow-list. StubApi/ is the Entra-only Azure OpenAI stand-in the offline
// cells drive; a real resource is the same config with your resource's host.
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCredProx(builder.Configuration)
    .AddOperations()
    .AddAzure(new DefaultAzureCredential());

// Metering export (M50): the route opts into the "openai" usage format, which reads the Azure
// OpenAI response's usage object (prompt_tokens / completion_tokens / total_tokens — the same
// shape Azure documents; see docs/azureopenai-notes.md). OTLP is the default exporter;
// Metrics:Console switches to the console exporter so a local run sees the counters.
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
