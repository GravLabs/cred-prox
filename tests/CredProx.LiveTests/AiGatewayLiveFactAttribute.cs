using Xunit;

namespace CredProx.LiveTests;

// A cell that reaches the real Anthropic API, gated on the machine-local env file
// (same discipline as GitHubAppLiveFactAttribute). Without a usable env file the
// cell skips loudly — the skip reason names the missing variable or mode problem,
// never a value — and the fixture is never constructed, so no host starts and no
// request can leave the machine. A usable env file is NOT proof a runner drives
// this process: it is resident by design on a host where live legs run at all, so
// the cell also requires the shared runner gate — the marker naming the aigateway
// leg. The one-command runner turns an unavailable state into a SKIP exit; a
// direct dotnet test run shows the same name on the skip line.
public sealed class AiGatewayLiveFactAttribute : FactAttribute, ILiveFactAttribute
{
    public AiGatewayLiveFactAttribute()
    {
        var probe = AiGatewayEnv.Probe();
        if (!probe.Available)
        {
            Skip = probe.SkipReason;
            return;
        }

        var problems = LiveRunnerGate.Problems(
            AiGatewayEnv.Vendor,
            Environment.GetEnvironmentVariable(LiveRunnerGate.RunnerVendorVariable));
        if (problems.Count > 0)
        {
            Skip = LiveRunnerGate.SkipReason(problems);
        }
    }
}
