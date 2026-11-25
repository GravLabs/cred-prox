namespace CredProx.LiveTests;

// The shared runner-only arm for EVERY live cell. The marker condition must hold
// inside the cell's own process, named without values: the process carries
// scripts/live-run.sh's marker naming THIS vendor's leg. The env file alone is
// not proof — it is resident and usable on a machine where live legs run at all,
// so any bare or filtered dotnet test on that host would otherwise arm live
// cells: real vendor calls, port binds, a dialled local model that answers
// instead of refusing. Scratch-gated vendors add the second condition: the
// run-created app handoff exists under their scratch directory — the handoff is
// shared on purpose (one lifecycle script mints the same three apps for every
// Entra vendor that uses it), so leftover scratch from any interrupted run could
// otherwise arm a cell too. The marker variable is exported by the runner for
// its own leg only and is never read from the central env file, so a bare
// dotnet test never has it.
public static class LiveRunnerGate
{
    public const string RunnerVendorVariable = "CREDPROX_LIVE_VENDOR";

    /// <summary>
    /// The marker-only arm, for vendors whose live cells read no run-created
    /// scratch. Empty means armed. Every problem names files, variables and
    /// expectations only — never a value, id or path.
    /// </summary>
    public static IReadOnlyList<string> Problems(string vendor, string? runnerVendor)
    {
        var problems = new List<string>();
        if (runnerVendor != vendor)
        {
            problems.Add(MarkerProblem(vendor, runnerVendor));
        }

        return problems;
    }

    /// <summary>
    /// Empty means armed. Every problem names files, variables and expectations
    /// only — never a value, id or path from outside the scratch contract.
    /// </summary>
    public static IReadOnlyList<string> Problems(string vendor, string? runnerVendor, string scratchDir)
    {
        var problems = new List<string>();
        if (runnerVendor != vendor)
        {
            problems.Add(MarkerProblem(vendor, runnerVendor));
        }

        if (!File.Exists(Path.Combine(scratchDir, "resource-audience.txt")))
        {
            problems.Add(
                $"the run-created app handoff is missing under {scratchDir} - run scripts/live-run.sh {vendor}, which creates the three apps first");
        }

        return problems;
    }

    private static string MarkerProblem(string vendor, string? runnerVendor) =>
        $"{RunnerVendorVariable} is " +
        (string.IsNullOrEmpty(runnerVendor) ? "not set" : $"\"{runnerVendor}\"") +
        $" - it is exported ONLY by scripts/live-run.sh for its own {vendor} leg, so a bare test run never arms this cell";

    // The runner's tail greps exactly this prefix out of the test log.
    public static string SkipReason(IReadOnlyList<string> problems) =>
        "SKIP (live): " + string.Join("; ", problems);
}
