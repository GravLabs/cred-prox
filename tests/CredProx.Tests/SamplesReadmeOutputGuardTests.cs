using System.Text.RegularExpressions;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// Sample READMEs show what a run prints: untagged fenced blocks are recorded output,
/// and recorded output goes stale silently when the code or the smoke cells move under
/// it. This guard binds every such block to the repository's own sources: at least one
/// claim token of the block (a printed-prefix, a quoted segment, a long identifier or a
/// delimiter-separated segment) must appear verbatim in that sample's files, its smoke
/// fixture/cells, or the library sources. When the emitted text changes, its token
/// disappears from the corpus and the block goes RED here instead of drifting. Blocks
/// that illustrate a wire shape rather than a run's output carry an explicit language
/// tag (```http, ```json, …) — a tag is the author's statement that the block is not a
/// transcript; only untagged blocks are smoke-bound. A pure status-code block ("401")
/// is exempt: nothing of it survives into any source to bind to.
/// </summary>
public sealed class SamplesReadmeOutputGuardTests
{
    private static readonly Regex QuotedToken = new(@"""([^""]{12,})""", RegexOptions.Compiled);
    private static readonly Regex IdentifierRun = new(@"[A-Za-z0-9_.\-]{16,}", RegexOptions.Compiled);
    private static readonly Regex BracketMarker = new(@"\[[A-Za-z]+\]", RegexOptions.Compiled);
    private static readonly Regex StatusLine = new(@"^\s*\d{3}\s*$", RegexOptions.Compiled);

    [Fact]
    public void EverySampleReadmeOutputBlock_IsSubstantiatedInSource()
    {
        var root = RepoRoot();
        var srcBlob = string.Concat(Directory.EnumerateFiles(Path.Combine(root, "src"), "*.cs", SearchOption.AllDirectories)
            .Select(File.ReadAllText));

        var readmePaths = Directory.EnumerateDirectories(Path.Combine(root, "samples"))
            .Select(d => Path.Combine(d, "README.md"))
            .Where(File.Exists)
            .Concat([Path.Combine(root, "samples", "README.md")])
            .OrderBy(p => p, StringComparer.Ordinal)
            .ToList();
        Assert.NotEmpty(readmePaths);

        foreach (var readme in readmePaths)
        {
            var sampleDir = Path.GetDirectoryName(readme)!;
            var sampleName = Path.GetFileName(sampleDir);
            var corpus = BuildCorpus(root, sampleDir, sampleName, srcBlob);

            foreach (var (start, lines) in UntaggedBlocks(File.ReadAllLines(readme)))
            {
                if (lines.All(l => string.IsNullOrWhiteSpace(l) || StatusLine.IsMatch(l)))
                {
                    continue; // a bare status-code echo has no bindable literal
                }

                var bound = lines.Any(line => TokenCandidates(line).Any(corpus.Contains));
                Assert.True(bound,
                    $"{Path.GetRelativePath(root, readme)}:{start} — recorded-output block has no literal that " +
                    $"exists in the sample's files, its smoke cells/fixtures, or src. Either the output drifted " +
                    $"from the block, or the block shows a hand-written shape: if it is not a transcript of a " +
                    $"real run, give it an explicit language tag.");
            }
        }
    }

    private static string BuildCorpus(string root, string sampleDir, string sampleName, string srcBlob)
    {
        var parts = new List<string> { srcBlob };
        parts.AddRange(Directory
            .EnumerateFiles(sampleDir, "*", SearchOption.AllDirectories)
            .Where(p => !Path.GetFileName(p).Equals("README.md", StringComparison.OrdinalIgnoreCase)
                        && !p.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                        && !p.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                        && (p.EndsWith(".cs", StringComparison.Ordinal)
                            || p.EndsWith(".csproj", StringComparison.Ordinal)
                            || p.EndsWith(".sh", StringComparison.Ordinal)
                            || p.EndsWith(".json", StringComparison.Ordinal)
                            || p.EndsWith(".yml", StringComparison.Ordinal)
                            || p.EndsWith(".py", StringComparison.Ordinal)))
            .Select(File.ReadAllText));

        var smokeDir = Path.Combine(root, "tests", "CredProx.SampleSmokes");
        foreach (var file in Directory.EnumerateFiles(smokeDir, $"{sampleName}*.cs"))
        {
            parts.Add(File.ReadAllText(file));
        }

        return string.Concat(parts);
    }

    private static IEnumerable<(int Start, List<string> Lines)> UntaggedBlocks(string[] lines)
    {
        var open = -1;
        var tagged = false;
        for (var i = 0; i < lines.Length; i++)
        {
            if (!lines[i].StartsWith("```", StringComparison.Ordinal))
            {
                continue;
            }

            if (open < 0)
            {
                open = i + 1;
                tagged = lines[i].Length > 3;
            }
            else
            {
                if (!tagged)
                {
                    yield return (open, lines[(open)..i].ToList());
                }

                open = -1;
            }
        }

        Assert.True(open < 0, "unbalanced fence in a sample README");
    }

    private static IEnumerable<string> TokenCandidates(string line)
    {
        var trimmed = line.Trim();
        if (trimmed.Length >= 16)
        {
            yield return trimmed[..16];
        }

        foreach (Match m in QuotedToken.Matches(trimmed))
        {
            yield return m.Groups[1].Value;
        }

        foreach (Match m in IdentifierRun.Matches(trimmed))
        {
            yield return m.Value.Trim('.', '-', '_');
        }

        foreach (Match m in BracketMarker.Matches(trimmed))
        {
            if (m.Value.Length >= 10)
            {
                yield return m.Value;
            }
        }

        foreach (var segment in trimmed.Split(['|', '=', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (segment.Length >= 12)
            {
                yield return segment.Trim('"');
            }
        }
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
