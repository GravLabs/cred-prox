using Xunit;

namespace CredProx.LiveTests;

// A cell that reaches real Entra and Microsoft Graph, gated on the machine-local
// env file (same discipline as GitHubAppLiveFactAttribute). Without a usable env
// file the cell skips loudly — the skip reason names the missing variable or
// mode problem, never a value — and the fixture is never constructed, so no host
// starts and no request can leave the machine. The runner additionally skips on a
// missing az sign-in before it ever runs the lifecycle script.
public sealed class GraphLiveFactAttribute : FactAttribute
{
    public GraphLiveFactAttribute()
    {
        var probe = GraphEnv.Probe();
        if (!probe.Available)
        {
            Skip = probe.SkipReason;
        }
    }
}
