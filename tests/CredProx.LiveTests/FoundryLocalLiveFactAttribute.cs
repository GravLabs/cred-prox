using Xunit;

namespace CredProx.LiveTests;

// A cell that reaches real Entra AND the local Foundry Local model. Three gates,
// each skipping loudly: the machine-local env file (same discipline as
// AgentTokensLiveFactAttribute), then the shared runner gate — the run-created
// app handoff must exist AND the process must carry scripts/live-run.sh's marker
// naming the foundrylocal leg. Neither env nor scratch alone is proof a runner
// drives this process: live.env is shared across vendors and resident by design,
// the local model answers whatever dials it, and the scratch handoff is shared by
// every Entra vendor that uses the same lifecycle script. The runner itself
// additionally gates on the az sign-in, curl and the model's /v1/models answer
// before it ever creates an app.
public sealed class FoundryLocalLiveFactAttribute : FactAttribute, ILiveFactAttribute
{
    public FoundryLocalLiveFactAttribute()
    {
        var probe = FoundryLocalEnv.Probe();
        if (!probe.Available)
        {
            Skip = probe.SkipReason;
            return;
        }

        var problems = LiveRunnerGate.Problems(
            FoundryLocalEnv.Vendor,
            Environment.GetEnvironmentVariable(LiveRunnerGate.RunnerVendorVariable),
            FoundryLocalLiveFixture.ScratchDir);
        if (problems.Count > 0)
        {
            Skip = LiveRunnerGate.SkipReason(problems);
        }
    }
}
