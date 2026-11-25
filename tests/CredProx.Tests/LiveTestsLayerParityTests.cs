using System.Diagnostics;
using System.Text;
using Xunit;

namespace CredProx.Tests;

// The standing parity leg for the live-test project's Layer partition: every
// test the runner can DISCOVER must sit in exactly one Layer filter, because the
// two Layer filters are the only sanctioned ways to run that project — a test
// the filters miss is dead bytes no leg ever executes. The partition cell inside
// the live project proves the trait labels from the assembly; this cell closes
// the other half from the discovery surface the filters actually act on: three
// `dotnet test --list-tests` runs (all, Layer=Offline, Layer=Live) whose counts
// must add up, read from the output every run — never a hard-coded total, so a
// newly added cell cannot dodge the partition by updating a constant. Listing
// is not running: discovery starts no fixture, no host and no vendor call, and
// no workflow references the live project (the LiveTestsExclusionTests guard
// above still holds); this cell lives in the ordinary CI suite, which is what
// makes it a standing leg.
public sealed class LiveTestsLayerParityTests
{
    [Fact]
    public async Task ListTests_AllEqualsOfflinePlusLive_CountsFromOutputNotConstants()
    {
        var all = await ListCountAsync(null);
        var offline = await ListCountAsync("Layer=Offline");
        var live = await ListCountAsync("Layer=Live");
        Assert.True(all > 100, $"discovery listed only {all} tests - the live project's shape changed under this guard");
        Assert.True(offline > 0, "the Layer=Offline filter listed nothing");
        Assert.True(live > 0, "the Layer=Live filter listed nothing");
        Assert.True(
            all == offline + live,
            $"the Layer filters do not partition discovery: all={all} offline={offline} live={live} - a test carries no Layer trait or more than one, and unfiltered runs are forbidden, so such a test never executes");
    }

    private static async Task<int> ListCountAsync(string? filter)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            WorkingDirectory = FindRepoRoot(),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var arg in new[] { "test", "tests/CredProx.LiveTests", "-c", "Release", "--list-tests", "--nologo" })
        {
            psi.ArgumentList.Add(arg);
        }
        if (filter is not null)
        {
            psi.ArgumentList.Add("--filter");
            psi.ArgumentList.Add(filter);
        }
        using var proc = Process.Start(psi) ?? throw new InvalidOperationException("could not start dotnet");
        var stdoutTask = proc.StandardOutput.ReadToEndAsync();
        var stderrTask = proc.StandardError.ReadToEndAsync();
        await proc.WaitForExitAsync();
        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        var tail = (stdout + stderr).ReplaceLineEndings("\n").Split('\n').TakeLast(15);
        Assert.True(
            proc.ExitCode == 0,
            $"dotnet test --list-tests {(filter is null ? "(unfiltered)" : filter)} exited {proc.ExitCode}; tail:\n{string.Join("\n", tail)}");
        var count = stdout.Split('\n').Count(line => line.StartsWith("    CredProx.LiveTests.", StringComparison.Ordinal));
        Assert.True(
            count > 0,
            $"--list-tests {(filter is null ? "(unfiltered)" : filter)} matched no test lines - the output format changed and this parser must be updated deliberately, never silently vacuous; tail:\n{string.Join("\n", tail)}");
        return count;
    }

    // same walk-up-to-.git idiom as the exclusion and hygiene cells (a .git
    // file in linked worktrees)
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
