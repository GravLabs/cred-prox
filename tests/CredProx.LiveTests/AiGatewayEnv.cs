namespace CredProx.LiveTests;

// The AiGateway vendor's machine-local contract (plan M46 unit 2): one variable,
// ANTHROPIC_API_KEY, in the central ~/.config/credprox-live/live.env at mode
// exactly 600.
// The value is a provider API key used verbatim as the x-api-key header value — no
// base64, no wrapping. Shape problems name the variable and the expectation only,
// never the value; a file that passes the file gate but carries a wrong-shape value
// FAILs in the cell, like every other vendor.
public static class AiGatewayEnv
{
    public const string Vendor = "aigateway";

    public static readonly IReadOnlyList<string> RequiredKeys = ["ANTHROPIC_API_KEY"];

    public static LiveEnvResult Probe() => LiveEnv.Probe(Vendor, RequiredKeys);

    // Shape problems only — names and reasons, never values. An Anthropic API key
    // starts with sk-ant- and carries at least 20 further key characters.
    public static IReadOnlyList<string> ValueProblems(IReadOnlyDictionary<string, string> values)
    {
        var problems = new List<string>();
        if (values.TryGetValue("ANTHROPIC_API_KEY", out var value))
        {
            if (value.Length < "sk-ant-".Length + 20 || !value.StartsWith("sk-ant-", StringComparison.Ordinal))
            {
                problems.Add(
                    "ANTHROPIC_API_KEY must be an Anthropic API key: starts with sk-ant- and carries " +
                    "at least 20 further characters");
            }
        }

        return problems;
    }
}
