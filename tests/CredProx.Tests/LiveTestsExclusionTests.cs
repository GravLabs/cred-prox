using Xunit;

namespace CredProx.Tests;

// The live-test project (tests/CredProx.LiveTests) must stay invisible to CI and to
// a plain solution-wide test run: it is deliberately absent from CredProx.slnx (the
// same exclusion shape StubApi uses), and no workflow may reference it or its
// on-demand runner. These cells run inside the CI suite, so any future change that
// wires live tests into CI fails here, loudly, before it can reach a real vendor.
public sealed class LiveTestsExclusionTests
{
    [Fact]
    public void Solution_DoesNotMentionTheLiveTestsProject()
    {
        var slnx = File.ReadAllText(Path.Combine(FindRepoRoot(), "CredProx.slnx"));
        Assert.DoesNotContain("LiveTests", slnx, StringComparison.Ordinal);
    }

    [Fact]
    public void Workflows_NeverReferenceLiveTestsOrTheLiveRunner()
    {
        var workflows = Path.Combine(FindRepoRoot(), ".github", "workflows");
        Assert.True(Directory.Exists(workflows), "CI workflows moved; update this guard");
        var files = Directory.GetFiles(workflows, "*.yml")
            .Concat(Directory.GetFiles(workflows, "*.yaml"))
            .ToList();
        Assert.NotEmpty(files);
        foreach (var file in files)
        {
            var text = File.ReadAllText(file);
            var name = Path.GetFileName(file);
            Assert.DoesNotContain("LiveTests", text, StringComparison.Ordinal);
            Assert.DoesNotContain("live-run.sh", text, StringComparison.Ordinal);
        }
    }

    // same walk-up-to-.git idiom as the hygiene cells (a .git file in linked worktrees)
    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null &&
               !Directory.Exists(Path.Combine(dir.FullName, ".git")) &&
               !File.Exists(Path.Combine(dir.FullName, ".git")))
        {
            dir = dir.Parent;
        }

        Assert.NotNull(dir);
        return dir.FullName;
    }
}
