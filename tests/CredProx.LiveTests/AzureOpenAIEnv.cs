namespace CredProx.LiveTests;

// The azureopenai vendor's machine-local contract (M52 part B): the five NAMES a run
// creates its own resource from - location, model, model version, account SKU and
// deployment SKU - in the central ~/.config/credprox-live/live.env at mode exactly 600. Nothing is
// remembered by the scripts: the run creates the resource group, account and
// deployment those names describe and destroys them again (the creation is the
// billable action, armed only by CREDPROX_M52_BILLABLE=1, which scripts/live-run.sh
// exports to its own azureopenai leg only). The endpoint and deployment the live
// cell dials are RUNNER-EXPORTED from the run's own names handoff, never read from
// this file: names steer creation here, but the dial never depends on the file.
// Names are not secrets, but they steer real resource creation, so they live only
// there: never committed, never pasted.
public static class AzureOpenAIEnv
{
    public const string Vendor = "azureopenai";

    public static readonly IReadOnlyList<string> RequiredKeys =
    [
        "AZURE_OPENAI_LOCATION",
        "AZURE_OPENAI_MODEL",
        "AZURE_OPENAI_MODEL_VERSION",
        "AZURE_OPENAI_SKU",
        "AZURE_OPENAI_DEPLOYMENT_SKU",
    ];

    public static LiveEnvResult Probe() => LiveEnv.Probe(Vendor, RequiredKeys);

    // The host dials the resource's base url: https, and an Azure OpenAI or Cognitive
    // Services suffix. The live cell keeps this gate for the value the runner exports
    // after create - a wrong-shape dial still cannot leave the harness.
    public static bool IsPlausibleEndpoint(string? value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
        uri.Scheme == Uri.UriSchemeHttps &&
        (uri.Host.EndsWith(".openai.azure.com", StringComparison.OrdinalIgnoreCase) ||
         uri.Host.EndsWith(".cognitiveservices.azure.com", StringComparison.OrdinalIgnoreCase));
}
