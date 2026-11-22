namespace CredProx.LiveTests;

// The ACA vendor's machine-local contract (plan M46 unit 3): one variable,
// TENANT_ID, in the central ~/.config/credprox-live/live.env at mode exactly 600
// (the value is shared with graph and agenttokens). The whole
// Azure resource set is NOT in this file — scripts/live-m46-aca.sh applies it,
// and destroy deletes it all again (resource group included). Shape problems
// name the variable and the expectation only, never the value.
public static class AcaEnv
{
    public const string Vendor = "aca";

    public static readonly IReadOnlyList<string> RequiredKeys = ["TENANT_ID"];

    public static LiveEnvResult Probe() => LiveEnv.Probe(Vendor, RequiredKeys);

    // A tenant id is a GUID. Anything else is a wrong-shape value: FAIL in the
    // cell, naming the variable, never the value.
    public static IReadOnlyList<string> ValueProblems(IReadOnlyDictionary<string, string> values)
    {
        var problems = new List<string>();
        if (values.TryGetValue("TENANT_ID", out var value) && !Guid.TryParse(value, out _))
        {
            problems.Add("TENANT_ID must be the Entra tenant id (a GUID)");
        }

        return problems;
    }
}
