using Xunit;

namespace CredProx.LiveTests;

// The azureopenai vendor's one billable leg: a tiny chat through the deployment
// THIS run creates (the creation is the billable action, and the lead's run destroys
// it again). Three gates, each skipping loudly, in the order that refuses cheapest
// first: the machine-local env file (same discipline as the other vendors' attributes
// — the four NAMES the resource is created from), then the shared runner gate — the
// process must carry scripts/live-run.sh's marker naming the azureopenai leg
// (marker-only: the run's endpoint and deployment arrive as runner-exported env,
// not as a scratch file this attribute reads) — and last the explicit
// CREDPROX_M52_BILLABLE=1 go-ahead. A bare or filtered dotnet test never carries the
// marker even when the other two are present, so no test run can ever create, dial
// or spend without the owner's flag and the runner driving the process.
public sealed class AzureOpenAILiveFactAttribute : FactAttribute, ILiveFactAttribute
{
    public AzureOpenAILiveFactAttribute()
    {
        var probe = AzureOpenAIEnv.Probe();
        if (!probe.Available)
        {
            Skip = probe.SkipReason;
            return;
        }

        var problems = LiveRunnerGate.Problems(
            AzureOpenAIEnv.Vendor,
            Environment.GetEnvironmentVariable(LiveRunnerGate.RunnerVendorVariable));
        if (problems.Count > 0)
        {
            Skip = LiveRunnerGate.SkipReason(problems);
            return;
        }

        if (Environment.GetEnvironmentVariable("CREDPROX_M52_BILLABLE") != "1")
        {
            Skip = "billable by design: set CREDPROX_M52_BILLABLE=1 to create one Azure OpenAI resource, spend one tiny chat through it, and destroy it again (owner-approved for M52, the lead runs it)";
        }
    }
}
