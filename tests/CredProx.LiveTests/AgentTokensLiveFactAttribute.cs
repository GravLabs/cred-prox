using Xunit;

namespace CredProx.LiveTests;

// A cell that reaches real Entra, gated on the machine-local env file (same
// discipline as GraphLiveFactAttribute). Without a usable env file the cell
// skips loudly and the fixture is never constructed, so no host starts and no
// request can leave the machine. The runner additionally skips on a missing az
// sign-in before it ever runs the lifecycle script.
public sealed class AgentTokensLiveFactAttribute : FactAttribute
{
    public AgentTokensLiveFactAttribute()
    {
        var probe = AgentTokensEnv.Probe();
        if (!probe.Available)
        {
            Skip = probe.SkipReason;
        }
    }
}
