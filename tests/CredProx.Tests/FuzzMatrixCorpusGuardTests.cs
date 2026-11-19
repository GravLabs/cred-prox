using System.Text.RegularExpressions;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The fuzz-run matrix hand-lists its targets and nothing else reads that list:
/// a corpus directory with no matrix entry fuzzes nothing, silently, and a
/// matrix target with no corpus directory fails the nightly for the wrong
/// reason. This is the drift class SamplesCiWiringTests exists to kill for
/// samples. The guard binds the fuzz-run matrix list in nightly.yml and
/// tests/CredProx.Fuzz/corpus/ both ways.
/// </summary>
public sealed class FuzzMatrixCorpusGuardTests
{
    private static readonly Regex MatrixPattern = new(
        @"^\s*target:\s*\[(?<targets>[^\]]*)\]\s*$",
        RegexOptions.Compiled | RegexOptions.Multiline);

    [Fact]
    public void FuzzMatrixTargets_AndCorpusDirectories_Agree()
    {
        var nightly = File.ReadAllText(Path.Combine(RepoRoot(), ".github", "workflows", "nightly.yml"));
        var matrix = MatrixPattern.Match(nightly);
        Assert.True(matrix.Success,
            "nightly.yml has no 'target: [ … ]' matrix list to bind the corpus to");
        var targets = matrix.Groups["targets"].Value
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var corpora = Directory.EnumerateDirectories(Path.Combine(RepoRoot(), "tests", "CredProx.Fuzz", "corpus"))
            .Select(d => Path.GetFileName(d)!)
            .ToArray();
        Assert.True(corpora.Length > 0, "tests/CredProx.Fuzz/corpus has no target directories at all");
        var missing = corpora.Except(targets, StringComparer.Ordinal).OrderBy(n => n, StringComparer.Ordinal);
        var stale = targets.Except(corpora, StringComparer.Ordinal).OrderBy(n => n, StringComparer.Ordinal);
        Assert.True(!missing.Any() && !stale.Any(),
            $"the fuzz matrix and the corpus directories disagree; corpora with no matrix target " +
            $"(fuzzed by nobody): [{string.Join(", ", missing)}]; matrix targets with no corpus " +
            $"(job fails for the wrong reason): [{string.Join(", ", stale)}]");
    }

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
