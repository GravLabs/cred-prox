using Xunit;

namespace CredProx.LiveTests;

// A cell that reaches real GitHub, gated on the machine-local env file (precedent:
// the DockerFact capability probe in tests/CredProx.E2ETests). Without a usable
// env file the cell skips loudly — the skip reason names every missing variable and
// any mode problem, never a value — and the fixture is never constructed, so no host
// starts. A usable env file is NOT proof a runner drives this process — it is
// resident by design on a host where live legs run at all — so the cell also
// requires the shared runner gate: the marker naming the githubapp leg. The
// one-command runner turns such an unavailable state into a SKIP exit; a direct
// dotnet test run shows the same names on the skip line.
public sealed class GitHubAppLiveFactAttribute : FactAttribute, ILiveFactAttribute
{
    public GitHubAppLiveFactAttribute()
    {
        var probe = GitHubAppEnv.Probe();
        if (!probe.Available)
        {
            Skip = probe.SkipReason;
            return;
        }

        var problems = LiveRunnerGate.Problems(
            GitHubAppEnv.Vendor,
            Environment.GetEnvironmentVariable(LiveRunnerGate.RunnerVendorVariable));
        if (problems.Count > 0)
        {
            Skip = LiveRunnerGate.SkipReason(problems);
        }
    }
}
