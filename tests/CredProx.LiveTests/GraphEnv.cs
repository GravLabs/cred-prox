namespace CredProx.LiveTests;

// The MicrosoftGraph vendor's machine-local contract (plan M46 unit 3): one
// variable, TENANT_ID, in the central ~/.config/credprox-live/live.env at mode
// exactly 600 (the value is shared with agenttokens and aca).
// A tenant id is not a secret, but it stays out of committed text and PASS lines
// the same way. The run's own client id and secret are NOT in this file — the run
// creates the app registration and its secret, pipes them to a scratch dir, and
// deletes them again at the end. Shape problems name the variable and the
// expectation only, never the value.
public static class GraphEnv
{
    public const string Vendor = "graph";

    public static readonly IReadOnlyList<string> RequiredKeys = ["TENANT_ID"];

    public static LiveEnvResult Probe() => LiveEnv.Probe(Vendor, RequiredKeys);

    // A tenant id is a GUID. Anything else (a domain name, a quoted value) is a
    // wrong-shape value: FAIL in the cell, naming the variable, never the value.
    public static IReadOnlyList<string> ValueProblems(IReadOnlyDictionary<string, string> values)
    {
        var problems = new List<string>();
        if (values.TryGetValue("TENANT_ID", out var value) && !Guid.TryParse(value, out _))
        {
            problems.Add("TENANT_ID must be the Entra tenant id (a GUID)");
        }

        return problems;
    }

    // The Graph live cell reads the vendor error code through the three-segment
    // path extensions.vendor_detail.error.code. Parsing through here gives the
    // cell curated failures instead of exception dumps and keeps the path in the
    // one place the offline cells can pin (GraphProblemParseTests). The body is
    // never echoed: it can carry tenant-derived material.
    public static (string ExtensionsCode, string? VendorErrorCode) ParseGraphProblem(
        string body, int status, string where)
    {
        System.Text.Json.JsonDocument doc;
        try
        {
            doc = System.Text.Json.JsonDocument.Parse(body);
        }
        catch (System.Text.Json.JsonException)
        {
            // the exception message itself quotes the offending bytes, so it is
            // deliberately not reused - the whole point is the body is not echoed:
            throw new Xunit.Sdk.XunitException(
                $"the {where} got an unparseable body (HTTP {status}) - " +
                "expected the problem document with extensions.code and extensions.vendor_detail.error.code (body not echoed)");
        }

        using (doc)
        {
            if (!doc.RootElement.TryGetProperty("extensions", out var extensions)
                || !extensions.TryGetProperty("code", out var code))
            {
                throw new Xunit.Sdk.XunitException(
                    $"the {where} (HTTP {status}) carried no extensions.code - expected the credprox.vendor_error " +
                    "problem document with extensions.vendor_detail.error.code (body not echoed)");
            }

            string? vendor = null;
            if (extensions.TryGetProperty("vendor_detail", out var detail)
                && detail.TryGetProperty("error", out var error)
                && error.TryGetProperty("code", out var errorCode))
            {
                vendor = errorCode.GetString();
            }

            return (code.GetString() ?? string.Empty, vendor);
        }
    }
}
