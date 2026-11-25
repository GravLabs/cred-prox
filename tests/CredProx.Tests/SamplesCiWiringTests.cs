using System.Text.RegularExpressions;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// Every sample ships a smoke script; the CI examples job must actually run each
/// one. This binds the three lists that can silently drift apart — the sample
/// directories, the build loop inside "Build all examples", and the smoke steps —
/// so adding a sample without wiring it into CI fails the battery instead of
/// leaving the sample untested. It also pins that the ACA harness's offline proxy
/// smoke (`--mode proxy --smoke`) has a CI step: it is the only cheap in-process
/// witness of the harness that proves the Key Vault path. Every CI pin reads content
/// lines only — a step or loop recited in a comment does not satisfy them — and each binds the
/// step's real shape: the smoke-project step must run exactly once, and the harness
/// step must be a content line that STARTS with 'docker run' and carries the flag —
/// a step name or an echo that recites the command is not the step.
/// </summary>
public sealed class SamplesCiWiringTests
{
    private static readonly Regex BuildLoopPattern = new(
        @"for p in (?<names>[^;]+); do", RegexOptions.Compiled);

    private static readonly Regex SmokeStepPattern = new(
        @"run: samples/(?<name>[A-Za-z0-9_]+)/smoke\.sh", RegexOptions.Compiled);

    private static readonly Regex WholeSmokeStepPattern = new(
        @"^\s*run:\s*dotnet test tests/CredProx\.SampleSmokes\s*$",
        RegexOptions.Compiled | RegexOptions.Multiline);

    [Fact]
    public void EverySample_IsBuiltByTheExamplesLoop()
    {
        var ci = CiContent();
        var loop = BuildLoopPattern.Match(ci);
        Assert.True(loop.Success, "ci.yml has no 'for p in ...; do' build loop to bind");
        var built = loop.Groups["names"].Value
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var missing = SampleNames().Except(built, StringComparer.Ordinal).OrderBy(n => n, StringComparer.Ordinal);
        var stale = built.Except(SampleNames(), StringComparer.Ordinal).OrderBy(n => n, StringComparer.Ordinal);
        Assert.True(!missing.Any() && !stale.Any(),
            $"the examples build loop and samples/ disagree; not built: [{string.Join(", ", missing)}]; " +
            $"stale loop entries with no sample directory: [{string.Join(", ", stale)}]");
    }

    [Fact]
    public void EverySample_HasACIsmokeStep()
    {
        var ci = CiContent();
        var smokes = SmokeStepPattern.Matches(ci).Select(m => m.Groups["name"].Value).ToArray();
        var missing = SampleNames().Except(smokes, StringComparer.Ordinal).OrderBy(n => n, StringComparer.Ordinal);
        var stale = smokes.Except(SampleNames(), StringComparer.Ordinal).OrderBy(n => n, StringComparer.Ordinal);
        Assert.True(!missing.Any() && !stale.Any(),
            $"every sample needs exactly one 'run: samples/<name>/smoke.sh' step; without a step: " +
            $"[{string.Join(", ", missing)}]; steps pointing at no sample: [{string.Join(", ", stale)}]");
    }

    [Fact]
    public void AcaHarnessOfflineSmoke_RunsInCI()
    {
        var ciPath = Path.Combine(RepoRoot(), ".github", "workflows", "ci.yml");
        var harnessLine = File.ReadAllLines(ciPath)
            .FirstOrDefault(l => !l.TrimStart().StartsWith("#", StringComparison.Ordinal)
                && l.TrimStart().StartsWith("docker run", StringComparison.Ordinal)
                && l.Contains("--mode proxy --smoke", StringComparison.Ordinal));
        Assert.True(harnessLine is not null,
            "no content line IS the harness command: a line starting with 'docker run' that also " +
            "asks for the offline proxy smoke ('--mode proxy --smoke'); reciting both phrases on any " +
            "other line (a step name, an echo) is not the step");
    }

    [Fact]
    public void WholeSmokeProjectStep_RunsUnfilteredInCI()
    {
        var count = WholeSmokeStepPattern.Matches(CiContent()).Count;
        Assert.True(count == 1,
            "the examples job needs exactly one 'run: dotnet test tests/CredProx.SampleSmokes' " +
            $"content step — it is the only place the unfiltered order-dependence pass runs; found {count}");
    }

    // A commented-out step can never run: every regex pin here reads content lines only,
    // the same filter the harness cell applies line by line.
    private static string CiContent() =>
        string.Join("\n", File.ReadAllLines(Path.Combine(RepoRoot(), ".github", "workflows", "ci.yml"))
            .Where(l => !l.TrimStart().StartsWith("#", StringComparison.Ordinal)));

    private static string[] SampleNames() =>
        Directory.EnumerateDirectories(Path.Combine(RepoRoot(), "samples"))
            .Where(d => Directory.GetFiles(d, "*.csproj").Length > 0)
            .Select(d => Path.GetFileName(d)!)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "docs", "credprox-plan.md")))
        {
            dir = dir.Parent;
        }

        Assert.NotNull(dir);
        return dir!.FullName;
    }
}
