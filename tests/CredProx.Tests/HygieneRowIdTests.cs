using System.Diagnostics;
using System.Text.RegularExpressions;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// Internal queue row ids — the "qitem-" prefix followed by any lowercase
/// letter or digit — are provenance for the private work queue; they must
/// never ride along in source-bearing or public repo text. Three shapes are
/// minted: full ids (digit-initial), recovery rows (the word "recovery"
/// followed by hex) and compaction-restore rows (the word "compaction"
/// followed by a uuid). The one-character class is right because the first
/// character after the prefix is always a lowercase letter or a digit; the
/// planted check proves the pattern on every planted shape. The hygiene
/// work of 2026-11-21 removed 23 such mentions across 15 files; these two
/// checks are the pin that keeps them out. The scan covers exactly the text
/// files git reports for the checkout — tracked plus untracked, with
/// gitignore, .git/info/exclude and the global excludes honored — so a
/// seat's scratch under an ignored path cannot redden another checkout's
/// suite, while an id in any file the repo would carry still fails it.
/// Paths git lists that are absent from disk — removed without staging,
/// a sparse checkout, a submodule slot — carry no text here and are
/// skipped. If git cannot run, the check fails loudly instead of passing
/// quietly.
/// </summary>
public class HygieneRowIdTests
{
    private static readonly Regex Pattern = new(@"qitem-[0-9a-z]", RegexOptions.Compiled);
    private static readonly string[] ScannedExtensions =
        [".cs", ".sh", ".md", ".yml", ".yaml", ".json", ".props", ".csproj", ".slnx",
         ".txt", ".xml", ".conf", ".config", ".py", ".js", ".tmpl"];
    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null &&
               !Directory.Exists(Path.Combine(dir.FullName, ".git")) &&
               !File.Exists(Path.Combine(dir.FullName, ".git")))
        {
            dir = dir.Parent;
        }
        return dir?.FullName ?? throw new InvalidOperationException("no repo root found above the test assembly");
    }

    [Fact]
    public void RepoTreeTextCarriesNoInternalRowIds()
    {
        var root = FindRepoRoot();
        var hits = new List<string>();
        foreach (var rel in GitReportedRepoFiles(root))
        {
            if (!ScannedExtensions.Contains(Path.GetExtension(rel)))
            {
                continue;
            }
            var file = Path.Combine(root, rel);
            if (!File.Exists(file))
            {
                // ls-files --cached lists index entries whatever the worktree
                // holds: a tracked file removed without staging, a sparse
                // checkout or a submodule slot carries no text to scan here.
                continue;
            }
            foreach (var (line, text) in File.ReadLines(file).Select((text, i) => (i + 1, text)))
            {
                if (Pattern.IsMatch(text))
                {
                    hits.Add($"{rel}:{line}");
                    if (hits.Count >= 5)
                    {
                        break;
                    }
                }
            }
            if (hits.Count >= 5)
            {
                break;
            }
        }
        Assert.True(hits.Count == 0, "internal queue row ids found in repo text (tracked or untracked, git-ignored excluded, paths missing from disk skipped): " + string.Join(", ", hits));
    }

    /// <summary>
    /// Asks git which files belong to the checkout: tracked plus untracked,
    /// with gitignore, .git/info/exclude and the global excludes honored.
    /// Git owns the scope decision so the test never re-implements it.
    /// </summary>
    private static List<string> GitReportedRepoFiles(string root)
    {
        var psi = new ProcessStartInfo("git", "ls-files -z --cached --others --exclude-standard")
        {
            WorkingDirectory = root,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        Process? process;
        try
        {
            process = Process.Start(psi);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                "git could not be started from the test; the repo-text scan refuses to guess its scope: " + ex.Message);
        }
        using (process ?? throw new InvalidOperationException("git ls-files did not start"))
        {
            var raw = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException(
                    "git ls-files failed (exit " + process.ExitCode + "): " + process.StandardError.ReadToEnd().Trim());
            }
            return raw.Split('\0', StringSplitOptions.RemoveEmptyEntries).ToList();
        }
    }

    [Fact]
    public void PatternFiresOnAPlantedRowId()
    {
        // Three plants, each built by concatenation so this file cannot match
        // its own scan: a digit-initial full id, a bare letter-initial hex id
        // (the shape of the mention once present in tracked text), and a
        // recovery-shaped id (synthetic hex, same shape as minted).
        var digitInitial = "decision recorded 14:21Z on row qitem-" + "20261121000000-0123456789abcdef: every shipped";
        var letterInitial = "the measurement (qitem-" + "bf1a82fd of the newline bypass) stands";
        var recoveryShaped = "witness gathered from qitem-" + "recovery-0123456789abcdef reproduced";
        Assert.Matches(Pattern, digitInitial);
        Assert.Matches(Pattern, letterInitial);
        Assert.Matches(Pattern, recoveryShaped);
    }
}
