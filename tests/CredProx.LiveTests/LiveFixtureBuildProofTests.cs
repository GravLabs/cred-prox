using System.Text;
using System.Text.RegularExpressions;
using Xunit;

namespace CredProx.LiveTests;

// Every executable a live fixture execs as its own process must be produced by a
// project this test project build-builds (ProjectReference with
// ReferenceOutputAssembly=false): the fixtures exec the dlls from their bin dirs
// and no assembly is referenced here, so a missing reference means a worktree
// that builds only tests/CredProx.LiveTests has no dll and the live leg dies in
// the fixture ctor. Foundry Local live run 1 at 7ae9bf8 showed the real failure
// shape — and the full-solution build in the battery was masking it, so the
// proof must live INSIDE the test project: this cell names each launched
// executable, demands the producing ProjectReference in this csproj, and demands
// the built dll on disk next to where it runs. Adding a fixture that launches
// another executable means adding its pair here (the two checks together are
// the gate: reference without build output, or output that no reference
// produces, both fail). The hand-kept roster itself went stale exactly that way
// when a live cell started dialing a sample with no row, so completeness arms
// derive the launched set from this project's sources and demand a roster row
// per hit — a launcher can no longer outrun the roster. The locator call shape
// is one derived arm; a few fixtures build their bin paths with Path.Combine
// directly, so a second arm pairs file-wide (a source file naming a bin
// directory under samples/ or tools/ and any dll declares launches) and asserts
// SET-VALUED: every derived directory and every derived dll name must each
// appear in some roster row, checked on its own. It cannot assert pairs because
// the file-wide reading does not know which directory runs which dll, and a
// pairwise assert would invent combinations no launch uses (the ACA file names
// three directories and three dlls; only three of the nine pairs exist). The
// roster is then required to run no further than the scans: every row must be
// explained by a derived directory (or the one named witness exception), so the
// hand-kept list cannot silently grow stale again in either direction.
[Trait("Layer", "Offline")]
public sealed class LiveFixtureBuildProofTests
{
    // (project-relative dir, launched dll) — one row per executable a live
    // fixture starts; the source line naming each launcher is in the comment.
    private static readonly (string ProjectDir, string Dll, string Launcher)[] LaunchedExecutables =
    [
        ("samples/GitHubApp", "GitHubApp.dll", "GitHubAppFixture.cs"),
        (@"samples/GitHubApp/StubApi", "StubApi.dll", "GitHubAppFixture.cs"),
        ("samples/AiGateway", "AiGateway.dll", "AiGatewayFixture.cs"),
        (@"samples/AiGateway/StubApi", "StubApi.dll", "AiGatewayFixture.cs"),
        ("samples/MicrosoftGraph", "MicrosoftGraph.dll", "MicrosoftGraphFixture.cs"),
        ("samples/AgentTokens", "AgentTokens.dll", "AgentTokensFixture.cs"),
        ("samples/AgentTokens/Agent", "Agent.dll", "AgentTokensFixture.cs"),
        ("samples/AzureContainerApps", "AzureContainerApps.dll", "AcaCheckLoopbackTests.cs"),
        (@"samples/AzureContainerApps/StubApi", "StubApi.dll", "AcaCheckLoopbackTests.cs"),
        ("tools/aca-live-harness", "AcaLiveHarness.dll", "AcaCheckLoopbackTests.cs"),
        ("samples/FoundryLocalAgent", "FoundryLocalAgent.dll", "FoundryLocalLiveFixture.cs"),
        ("samples/FoundryLocalGateway", "FoundryLocalGateway.dll", "FoundryLocalGatewayLiveTests.cs"),
        ("samples/FoundryLocalCloud", "FoundryLocalCloud.dll", "FoundryLocalCloudLiveTests.cs"),
        ("samples/AzureOpenAI", "AzureOpenAI.dll", "AzureOpenAILiveTests.cs"),
        (@"tests/CredProx.LiveTests/Witness", "CredProx.LiveWitness.dll", "LiveHosts.cs"),
    ];

    [Fact]
    public void EveryExecLaunchedByALiveFixture_IsProducedByABuildReference_AndPresentOnDisk()
    {
        var repoRoot = RepoRoot();
        var csproj = File.ReadAllText(Path.Combine(repoRoot, "tests", "CredProx.LiveTests", "CredProx.LiveTests.csproj"))
            .Replace('\\', '/');
        var configuration = Configuration();
        var offenders = new List<string>();

        foreach (var (projectDir, dll, launcher) in LaunchedExecutables)
        {
            // The reference is written relative to THIS csproj: projects under
            // this directory carry a plain relative path, the rest a ../../ path.
            var csprojRelative = projectDir.StartsWith("tests/CredProx.LiveTests/", StringComparison.Ordinal)
                ? projectDir["tests/CredProx.LiveTests/".Length..]
                : $"../../{projectDir}";
            var expectedReference = $"Include=\"{csprojRelative}/{Path.GetFileNameWithoutExtension(dll)}.csproj\"";
            if (!csproj.Contains(expectedReference, StringComparison.Ordinal))
            {
                offenders.Add($"{launcher} launches {projectDir}/{dll} but CredProx.LiveTests.csproj has no ProjectReference to {projectDir}");
            }

            var bin = Path.Combine(repoRoot, projectDir, "bin", configuration, "net10.0", dll);
            if (!File.Exists(bin))
            {
                offenders.Add($"{launcher} launches {dll} but no built copy exists at {bin}");
            }
        }

        Assert.True(LaunchedExecutables.Length >= 15, "the launched-executable list shrank below the fixtures on disk");

        // Derived arm one, the locator call shape: every locator call in this
        // project's COMPILED sources (the csproj **/*.cs glob minus bin and
        // obj) must carry a roster row, which in turn demands the build
        // reference and the built dll — so a launcher added without a row
        // (the exact drift that cost live run 5) turns this cell RED by
        // itself. The call genuinely pairs a directory with a dll, so this
        // arm checks the pair. Both arms match on comment-stripped code, so
        // commented-out call shapes cannot move the cell in either direction.
        var located = new List<(string ProjectDir, string Dll, string Source)>();
        foreach (var sourceFile in CompiledTestSources(
                     Path.Combine(repoRoot, "tests", "CredProx.LiveTests")))
        {
            foreach (Match call in Regex.Matches(
                ScannableCode(File.ReadAllText(sourceFile)),
                @"LiveHosts\.LocateBin\(\s*Path\.Combine\(\s*(?<dir>(?:""[^""]*""\s*,\s*)*""[^""]*"")\s*\)\s*,\s*""(?<dll>[^""]+)""",
                RegexOptions.Singleline))
            {
                var segments = Regex.Matches(call.Groups["dir"].Value, @"""([^""]+)""");
                located.Add((
                    string.Join("/", segments.Select(m => m.Groups[1].Value)),
                    call.Groups["dll"].Value,
                    Path.GetFileName(sourceFile)));
            }
        }
        Assert.True(located.Count >= 11,
            $"the locator scan found only {located.Count} call sites — the scan is vacuous or the sources moved; reconcile deliberately");
        foreach (var (projectDir, dll, sourceFile) in located)
        {
            if (!LaunchedExecutables.Any(row => row.ProjectDir == projectDir && row.Dll == dll))
            {
                offenders.Add($"{sourceFile} locates {projectDir}/{dll} but the launched-executable roster has no row for it");
            }
        }

        // Derived arm two, direct Path.Combine bin dirs (the aca loopback cells
        // build theirs here instead of calling the locator). File-scoped loose
        // pairing, this guard file excluded: its roster strings would echo back
        // as derived launches. A file declaring launches contributes its bin
        // directories and every dll name it contains; both sets are asserted
        // set-valued, each element against any roster row, because the file-
        // wide reading cannot know which directory runs which dll.
        // KNOWN BLIND SPOT: re-pairing a directory with a dll name that both
        // already carry roster rows passes this arm — only the reference and
        // on-disk halves above can see that pairing, and only when a live leg
        // actually execs it. The call is read by its QUOTED arguments only: a
        // samples/ or tools/ literal before a bin literal inside one flat
        // Path.Combine call. The receiver spelling is therefore irrelevant —
        // a repoRoot-rooted and an AppContext.BaseDirectory ..-traversed bin
        // path are the same launch to this arm; the .. hops drop when the
        // directory is joined repo-relative. MEASURED LIMIT, recorded not
        // chased: a bin path whose root is produced by a NESTED call is
        // invisible to this arm — an argument list containing parentheses
        // never matches, so the directory and its bin segment never appear
        // in one reading, and the inner call alone carries no bin literal.
        var declaredDirs = new SortedSet<string>(StringComparer.Ordinal);
        var declaredDlls = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var sourceFile in CompiledTestSources(
                     Path.Combine(repoRoot, "tests", "CredProx.LiveTests")))
        {
            if (Path.GetFileName(sourceFile) == nameof(LiveFixtureBuildProofTests) + ".cs")
            {
                continue;
            }
            var text = ScannableCode(File.ReadAllText(sourceFile));
            var declares = false;
            foreach (Match call in Regex.Matches(text, @"Path\.Combine\((?<args>[^()]*)\)"))
            {
                var quoted = Regex.Matches(call.Groups["args"].Value, @"""([^""]+)""");
                var seenRoot = false;
                var seenBin = false;
                foreach (Match seg in quoted)
                {
                    var literal = seg.Groups[1].Value;
                    if (literal == "samples" || literal == "tools")
                    {
                        seenRoot = true;
                    }
                    else if (literal == "bin")
                    {
                        seenBin = true;
                        break;
                    }
                }
                if (!seenRoot || !seenBin)
                {
                    continue;
                }
                declares = true;
                declaredDirs.Add(string.Join("/", quoted
                    .Where(m => m.Groups[1].Value != "..")
                    .TakeWhile(m => m.Groups[1].Value != "bin")
                    .Select(m => m.Groups[1].Value)));
            }
            if (!declares)
            {
                continue;
            }
            foreach (Match dll in Regex.Matches(text, @"""(?<dll>[^""]+\.dll)"""))
            {
                declaredDlls.Add(dll.Groups["dll"].Value);
            }
        }
        Assert.True(declaredDirs.Count >= 3,
            $"the direct-launch scan found only {declaredDirs.Count} bin directories — the scan is vacuous or the sources moved; reconcile deliberately");
        foreach (var dir in declaredDirs)
        {
            if (!LaunchedExecutables.Any(row => row.ProjectDir == dir))
            {
                offenders.Add($"{dir} is built as a launch directory by a direct Path.Combine but the launched-executable roster has no row for it");
            }
        }
        foreach (var dll in declaredDlls)
        {
            if (!LaunchedExecutables.Any(row => row.Dll == dll))
            {
                offenders.Add($"{dll} is named next to a direct launch directory but the launched-executable roster has no row for it");
            }
        }

        // Reverse direction: every roster directory must be explained by one of
        // the two derived scans or by the one launch no scan can see — the
        // witness, resolved by an unqualified call inside LiveHosts itself.
        // A row kept for a launcher that no longer exists is the same hand-kept
        // drift in the other direction.
        var knownDirs = new HashSet<string>(StringComparer.Ordinal);
        foreach (var hit in located)
        {
            knownDirs.Add(hit.ProjectDir);
        }
        knownDirs.UnionWith(declaredDirs);
        knownDirs.Add(@"tests/CredProx.LiveTests/Witness");
        foreach (var (projectDir, dll, launcher) in LaunchedExecutables)
        {
            if (!knownDirs.Contains(projectDir))
            {
                offenders.Add($"the roster row {projectDir}/{dll} ({launcher}) is not produced by the locator scan, the direct-launch scan, or the named witness exception — drop it only together with the launcher");
            }
        }

        Assert.True(offenders.Count == 0, string.Join("; ", offenders));
    }

    // Every .cs under the project directory, minus build intermediates - a
    // superset of the compiler's set on purpose: the csproj drops Witness/**
    // from compilation, but this scan keeps it, because the witness binary is
    // launched by this project and a roster row earned only there still needs
    // its build reference to exist.
    private static IEnumerable<string> CompiledTestSources(string projectDir)
    {
        var sep = Path.DirectorySeparatorChar;
        var binSep = string.Concat(sep, "bin", sep);
        var objSep = string.Concat(sep, "obj", sep);
        return Directory.EnumerateFiles(projectDir, "*.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains(binSep, StringComparison.Ordinal)
                     && !f.Contains(objSep, StringComparison.Ordinal))
            .OrderBy(f => f, StringComparer.Ordinal);
    }

    [Fact]
    public void ScannableCode_DropsBlockBodiesAcrossLines_KeepsRawBodiesVerbatim()
    {
        // The ghost shape: an unstarred call line inside a multi-line block -
        // the old line-local cut kept it and the arms saw a phantom launch:
        var ghosted = string.Join("\n",
            "var before = Path.Combine(\"samples\", \"KeepBefore\", \"bin\");",
            "/* witness block opens here:",
            "var ghost = Path.Combine(\"samples\", \"B1Ghost\", \"bin\", \"b1ghost.dll\");",
            "*/",
            "var after = Path.Combine(\"samples\", \"KeepAfter\", \"bin\");");
        var stripped = ScannableCode(ghosted);
        Assert.DoesNotContain("B1Ghost", stripped, StringComparison.Ordinal);
        Assert.Contains("KeepBefore", stripped, StringComparison.Ordinal);
        Assert.Contains("KeepAfter", stripped, StringComparison.Ordinal);

        // raw-literal bodies are DATA another scan reads: kept verbatim, comment
        // markers inside them are content, not state:
        var raw = string.Join("\n",
            "var src = \"\"\"",
            "// LiveHosts.LocateBin(Path.Combine(\"samples\", \"StubSample\", \"bin\"), \"stub.dll\")",
            "\"\"\";");
        Assert.Contains("LocateBin(Path.Combine", ScannableCode(raw), StringComparison.Ordinal);

        // a single-line raw literal closes on its own line - the state must not
        // leak past it and start swallowing real code:
        var closed = "var body = \"\"\"{\"u\":\"https://credprox.dev/x\",\"s\":403}\"\"\";"
            + "\nvar real = Path.Combine(\"samples\", \"KeepClosed\", \"bin\");";
        var strippedClosed = ScannableCode(closed);
        Assert.Contains("https://credprox.dev/x", strippedClosed, StringComparison.Ordinal);
        Assert.Contains("KeepClosed", strippedClosed, StringComparison.Ordinal);
    }

    // internal: the OBSERVED pin in RunnerRunCreatedScanTests shares this exact
    // strip (post-release item 6) - both guards must read the same code, so the
    // scanner lives once.
    // Both arms read CODE, never raw text. Comment and string state CROSS LINES
    // (post-release item 5, 2026-11-25): the old line-local cut kept every body
    // line of a multi-line /* */ block that did not start with *, so a call
    // named inside such a block became a phantom declaration. Now: a /* puts the
    // scanner in comment mode that holds until */ (comment bytes are dropped and
    // never toggle string state); a """ raw literal keeps its content VERBATIM
    // — that content is data another scan reads — and neither quotes nor comment
    // markers inside it can open or close a comment. A // outside a string still
    // ends the line's code; a // inside a quoted literal (any https URL) never
    // does, and inside a quoted literal a backslash escapes the char it
    // precedes, so \" never closes the string. Lines whose remaining code
    // starts with * stay dropped (doc-block and */ lines).
    internal static string ScannableCode(string text)
    {
        var kept = new List<string>();
        var inBlock = false;
        var inRaw = false;
        foreach (var line in text.Split('\n'))
        {
            var inString = false;
            var code = new StringBuilder(line.Length);
            for (var i = 0; i < line.Length; i++)
            {
                var c = line[i];
                if (inBlock)
                {
                    // comment bytes are never code and never toggle string state:
                    if (c == '*' && i + 1 < line.Length && line[i + 1] == '/')
                    {
                        inBlock = false;
                        i++;
                    }

                    continue;
                }

                // every EXACT three-quote run is a delimiter - opening or closing
                // (the sources carry no """" run; a longer one is a known, loud
                // miscount if anyone ever writes one):
                if (!inString && c == '"' && i + 2 < line.Length
                    && line[i + 1] == '"' && line[i + 2] == '"'
                    && !(i + 3 < line.Length && line[i + 3] == '"'))
                {
                    inRaw = !inRaw;
                    code.Append("\"\"\"");
                    i += 2;
                    continue;
                }

                if (inRaw)
                {
                    // raw-literal body is DATA another scan reads: kept verbatim,
                    // and no quote or comment marker inside it acts here:
                    code.Append(c);
                    continue;
                }

                if (c == '"')
                {
                    inString = !inString;
                    code.Append(c);
                    continue;
                }

                if (inString && c == '\\')
                {
                    // an escape is data: a backslash never lets the char it
                    // escapes close the string (measured 2026-11-25: a "  \"...
                    // /**...\""  config assertion closed its string early and
                    // the /** inside the URL pattern opened a comment that
                    // ate the rest of the file for every consumer of this
                    // strip):
                    code.Append(c);
                    if (i + 1 < line.Length)
                    {
                        code.Append(line[i + 1]);
                        i++;
                    }

                    i++;
                    continue;
                }

                if (inString)
                {
                    code.Append(c);
                    continue;
                }

                if (c == '/' && i + 1 < line.Length)
                {
                    if (line[i + 1] == '/')
                    {
                        break;
                    }

                    if (line[i + 1] == '*')
                    {
                        inBlock = true;
                        i++;
                        continue;
                    }
                }

                code.Append(c);
            }

            var keptLine = code.ToString();
            if (keptLine.TrimStart().StartsWith("*", StringComparison.Ordinal))
            {
                continue;
            }

            kept.Add(keptLine);
        }

        return string.Join("\n", kept);
    }

    private static string Configuration()
    {
        var parts = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar).Split(Path.DirectorySeparatorChar);
        return parts[Array.IndexOf(parts, "bin") + 1];
    }

    private static string RepoRoot()
    {
        var parts = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar).Split(Path.DirectorySeparatorChar);
        var binIndex = Array.IndexOf(parts, "bin");
        Assert.True(binIndex >= 3, $"unexpected test assembly location '{AppContext.BaseDirectory}'");
        return string.Join(Path.DirectorySeparatorChar, parts[..(binIndex - 2)]);
    }
}
