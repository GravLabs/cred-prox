using Xunit;

namespace CredProx.LiveTests;

// The M53 opt-in gate for cells that make BILLABLE Anthropic calls on the owner's API
// credits. Conditions, all named without values: the Entra leg (AgentTokensEnv); the
// shared runner gate (the run-created app handoff this cell reads, plus scripts/
// live-run.sh's marker naming the agenttokens leg — leftover scratch from any
// interrupted run must never arm a billable cell inside an offline test run); and the
// explicit go-ahead CREDPROX_M53_BILLABLE=1 plus an ANTHROPIC_API_KEY in the live env.
// Without them the cell skips loudly, the fixture is never constructed, and no request
// leaves the machine — the plan's rule: the lead runs this leg only after the owner's
// separate go-ahead for billable agent calls.
public sealed class AgentTokensBillableLiveFactAttribute : FactAttribute, ILiveFactAttribute
{
    public AgentTokensBillableLiveFactAttribute()
    {
        var probe = AgentTokensEnv.Probe();
        if (!probe.Available)
        {
            Skip = probe.SkipReason;
            return;
        }

        var gateProblems = LiveRunnerGate.Problems(
            AgentTokensEnv.Vendor,
            Environment.GetEnvironmentVariable(LiveRunnerGate.RunnerVendorVariable),
            AgentTokensFixture.ScratchDir);
        if (gateProblems.Count > 0)
        {
            Skip = LiveRunnerGate.SkipReason(gateProblems);
            return;
        }

        if (Environment.GetEnvironmentVariable("CREDPROX_M53_BILLABLE") != "1")
        {
            Skip = "skipped: billable agent calls need CREDPROX_M53_BILLABLE=1 in the live env " +
                   "(the owner's separate go-ahead); this cell makes a few cents of real Anthropic calls";
        }
        else if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("ANTHROPIC_API_KEY")))
        {
            Skip = "skipped: CREDPROX_M53_BILLABLE=1 is set but ANTHROPIC_API_KEY is missing from the live env";
        }
    }
}
