using Xunit;

namespace CredProx.LiveTests;

// A cell that reaches real Entra, gated the same way as the other vendor live
// cells: first the machine-local env file (without it the cell skips loudly and
// the fixture is never constructed, so no host starts and no request can leave
// the machine), then the shared runner gate — the run-created app handoff must
// exist AND the process must carry scripts/live-run.sh's marker naming the
// agenttokens leg. The scratch alone is not proof: it is shared with the other
// Entra vendors' lifecycle, and live.env is resident on a machine where live legs
// run at all, so only the runner's own marker distinguishes a runner-driven run
// from a bare test process that happens to find leftovers. The runner
// additionally skips on a missing az sign-in before it ever runs the lifecycle
// script.
public sealed class AgentTokensLiveFactAttribute : FactAttribute, ILiveFactAttribute
{
    public AgentTokensLiveFactAttribute()
    {
        var probe = AgentTokensEnv.Probe();
        if (!probe.Available)
        {
            Skip = probe.SkipReason;
            return;
        }

        var problems = LiveRunnerGate.Problems(
            AgentTokensEnv.Vendor,
            Environment.GetEnvironmentVariable(LiveRunnerGate.RunnerVendorVariable),
            AgentTokensFixture.ScratchDir);
        if (problems.Count > 0)
        {
            Skip = LiveRunnerGate.SkipReason(problems);
        }
    }
}
