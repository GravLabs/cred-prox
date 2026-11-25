namespace CredProx.LiveTests;

// The foundrylocal vendor's machine-local contract: one variable, TENANT_ID, in
// the central ~/.config/credprox-live/live.env at mode exactly 600 (the value is
// shared with graph, agenttokens and aca). The run's three app registrations and
// their secrets are NOT in this file — the runner leg creates them with
// scripts/live-agenttokens-app.sh (the same lifecycle script agenttokens uses)
// and deletes them again at the end. Shape problems name the variable and the
// expectation only, never the value.
public static class FoundryLocalEnv
{
    public const string Vendor = "foundrylocal";

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

    // The model this vendor answers is a loopback Foundry Local server: not part
    // of the harness, authenticates nothing, costs nothing per call, and holds
    // no secret — so its base URL is a plain machine-local override, never a
    // live.env variable. The runner's model gate dials the same default before
    // it creates anything.
    public static string ModelBaseUrl =>
        Environment.GetEnvironmentVariable("CREDPROX_FOUNDRYLOCAL_URL") is { Length: > 0 } s
            ? s.TrimEnd('/')
            : "http://127.0.0.1:5273";
}
