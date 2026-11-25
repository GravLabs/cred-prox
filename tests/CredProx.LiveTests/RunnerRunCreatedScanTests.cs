using System.Diagnostics;
using System.Reflection;
using System.Text.RegularExpressions;
using Xunit;

namespace CredProx.LiveTests;

// Marker: this class EXECs the real scripts/live-run.sh (it resolves the runner
// through LocateRunner() and starts it). RunnerRunCreatedScanTests' guard cell
// walks every derived class: no name on such a class - the class itself, its
// methods, its nested types - may carry one of live-run.sh's --filter tokens in
// any case, or a live leg would select that cell and exec a nested runner. The
// marker plus the guard cell's textual arms against LocateRunner() are the
// definition: reflection cannot see method calls, so a hand-kept list drifts.
// An ABSTRACT BASE, not an interface (m46u finding 1): every class has exactly one
// base slot, so the per-declaration textual arm reads a marker unambiguously,
// and that arm - not the old per-file one - closes the measured residual where
// a multi-marked file dropping one marker read even against its siblings.
public abstract class ExecutesLiveRunner
{
}

// LOW-1 from the 2026-11-22 secret-wait check: no committed cell named any of the
// runner's five RUN-CREATED leak-scan arms - deleting an arm body left the
// committed set green. Four cells here now name all five arms positively - the
// 2026-11-22 re-check added the unmapped witness, so neutering any arm body makes
// this class the only RED in the whole suite. Each cell here execs the
// REAL live-run.sh under a sandbox HOME against the canned az (+ canned docker
// for aca) from the scaffold classes,
// the fake curl and dotnet from SecretPropagationStubs, and plants the run-created
// secret values into the run's log through the one stderr door each vendor leaves
// unsuppressed after the values exist. Each cell asserts the runner names that
// arm's kind, fails the run, and never echoes the value from its own leak lines.
// No az, no network; the real ~/.config/credprox-live is never created or read.
// Recursion safety is a NAMING property that needs upkeep: the runner's
// --filter FullyQualifiedName~ substring-matches the FULLY QUALIFIED test name
// CASE-INSENSITIVELY (measured 2026-11-22: a lower-case ~githubapp selects a
// GithubApp-shaped cell), and a class name counts as much as a method name. So
// no name on ANY class that execs the real live-run.sh - the class itself, its
// methods, its nested types - may contain one of live-run.sh's filter tokens in
// ANY case; a name carrying one IS selected by that vendor's live leg and would
// exec a nested live-run.sh from inside the run. Every runner-execing class
// derives the ExecutesLiveRunner base, and the NamesCarryNoRunnerFilterToken
// cell below enforces the invariant against live-run.sh itself over every
// marked class: a rename into a token in any case, a new leg filter token
// naming a marked class, or a runner-execing file without a marked class
// turns it RED.
//
// The doors (all test-side; no shipped script carries a plant knob):
// - graph: the canned stub's STUB_SECRET makes the run-created client secret a
//   fixed canary, and STUB_DESTROY_PLANT echoes it on the destroy-phase pre-delete
//   "ad app list" stderr, which live-graph-app.sh does not command-substitute.
// - agenttokens: the canned stub already mints fixed canaries for both client
//   secrets (AgentTokensScaffoldTests.cs:501/:502); STUB_DESTROY_PLANT echoes one
//   planted canary on the destroy list arm (the script captures only that call's
//   stdout, so stderr passes through) - the mapped and unmapped cells each plant
//   one value and assert the OTHER arm stays silent.
// - aca: the keys are openssl-minted under the sandbox PATH, so the plant reads
//   THIS run's scratch handoff: the canned stub's "keyvault secret list" arm - the
//   one post-material az call whose stderr is NOT suppressed (live-m46-aca.sh runs
//   it inside the material echo; every destroy read-back runs with 2>/dev/null) -
//   cats $CREDPROX_M46_ACA_SCRATCH/aca-secrets.env to stderr, which reaches the
//   log through the apply tee.
[Trait("Layer", "Offline")]
public sealed class RunnerRunCreatedScanTests : ExecutesLiveRunner, IDisposable
{
    // matches none of the runner's shape arms (no gh_*/sk-ant-/eyJ shapes); for the
    // graph cell this is both the minted secret (STUB_SECRET) and the plant, so
    // only the arm that holds the run-created value can fire:
    private const string GraphCanary = "canary-run-created-secret-0123456789";

    // the agenttokens canned stub mints this exact value for the MAPPED client
    // (AgentTokensScaffoldTests credential-reset arm): planting it must name the
    // mapped arm and NOT the unmapped one, whose canary is nowhere in the log:
    private const string MappedCanary = "canary-secret-mapped-do-not-echo";

    // the same stub's UNMAPPED client secret: planting it must name the unmapped
    // arm and NOT the mapped one - the mirror image of the cell above:
    private const string UnmappedCanary = "canary-secret-unmapped-do-not-echo";

    private readonly string _stubBin;
    private readonly string _home;
    private readonly string _scratch;
    private readonly string _countFile;
    private readonly string _runner;
    private string? _runnerLog;

    public RunnerRunCreatedScanTests()
    {
        _stubBin = Path.Combine(Path.GetTempPath(), $"credprox-m46-runcanstub-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_stubBin);
        SecretPropagationStubs.WriteExec(_stubBin, "dotnet", SecretPropagationStubs.StubDotnet);
        SecretPropagationStubs.WriteExec(_stubBin, "curl", SecretPropagationStubs.StubCurl);
        // inert for the Entra cells; the aca push step needs a docker on PATH:
        SecretPropagationStubs.WriteExec(_stubBin, "docker", AcaScriptTests.StubDocker);
        _home = SecretPropagationStubs.MakeSandboxHome();
        _scratch = Path.Combine(Path.GetTempPath(), $"credprox-m46-runcan-scratch-{Guid.NewGuid():N}");
        _countFile = Path.Combine(_stubBin, "curl-count");
        _runner = SecretPropagationStubs.LocateRunner();
    }

    [Fact]
    public void GraphRunCreatedSecret_PlantedInDestroyReadback_Named_AndFails()
    {
        SecretPropagationStubs.WriteExec(_stubBin, "az", GraphAppScriptTests.StubAz);
        var run = Run("graph", new()
        {
            ["STUB_AZ_SIGNED_IN"] = "1",
            ["STUB_CRED"] = "1",
            ["STUB_APP_LEFT"] = "0",
            ["STUB_SP_LEFT"] = "0",
            ["STUB_CREATE_FAIL"] = "0",
            ["STUB_SECRET"] = GraphCanary,
            ["STUB_DESTROY_PLANT"] = GraphCanary,
            ["STUB_CURL_CODES"] = "200",
        });
        Assert.Equal(1, run.Exit);
        // the leg itself passed and its destroy ran clean - the plant lands in the
        // log only through the destroy read-back, so the FAIL must come AFTER the
        // destroy's clean line (the pre-destroy legs carry no such string):
        Assert.Contains("graph destroy: read-back clean", run.Out, StringComparison.Ordinal);
        AssertLeakNamed(run.Out, "run-created-client-secret", GraphCanary);
        Assert.True(
            run.Out.IndexOf("graph destroy: read-back clean", StringComparison.Ordinal)
                < run.Out.IndexOf("secret material appears", StringComparison.Ordinal),
            "the scan that names the arm must run after the destroy that plants it");
        Assert.Contains(GraphCanary, RunnerLog(run.Out), StringComparison.Ordinal);
        Assert.DoesNotContain(GraphCanary, run.Err, StringComparison.Ordinal);
    }

    [Fact]
    public void MappedTokenSecret_PlantedInDestroyReadback_NamesMappedArmOnly_AndFails()
    {
        SecretPropagationStubs.WriteExec(_stubBin, "az", AgentTokensScriptTests.StubAz);
        var run = Run("agenttokens", new()
        {
            ["STUB_AZ_SIGNED_IN"] = "1",
            ["STUB_AUD"] = "api://aaaaaaaa-0000-0000-0000-000000000001",
            ["STUB_URI"] = "1",
            ["STUB_ROLE"] = "2",
            ["STUB_APP_LEFT"] = "0",
            ["STUB_SP_LEFT"] = "0",
            ["STUB_CURL_CODES"] = "200",
            ["STUB_DESTROY_PLANT"] = MappedCanary,
        });
        Assert.Equal(1, run.Exit);
        Assert.Contains("agenttokens destroy: read-back clean", run.Out, StringComparison.Ordinal);
        AssertLeakNamed(run.Out, "run-created-client-secret-mapped", MappedCanary);
        // the unmapped arm's own canary is nowhere in the log - its arm must stay
        // silent while the mapped one fires:
        Assert.DoesNotContain("run-created-client-secret-unmapped", run.Out, StringComparison.Ordinal);
        Assert.DoesNotContain("canary-secret-unmapped-do-not-echo", run.Out, StringComparison.Ordinal);
        Assert.True(
            run.Out.IndexOf("agenttokens destroy: read-back clean", StringComparison.Ordinal)
                < run.Out.IndexOf("secret material appears", StringComparison.Ordinal),
            "the scan that names the arm must run after the destroy that plants it");
        Assert.Contains(MappedCanary, RunnerLog(run.Out), StringComparison.Ordinal);
        Assert.DoesNotContain(MappedCanary, run.Err, StringComparison.Ordinal);
    }

    [Fact]
    public void UnmappedArmSecret_PlantedInDestroyReadback_NamesUnmappedArmOnly_AndFails()
    {
        SecretPropagationStubs.WriteExec(_stubBin, "az", AgentTokensScriptTests.StubAz);
        var run = Run("agenttokens", new()
        {
            ["STUB_AZ_SIGNED_IN"] = "1",
            ["STUB_AUD"] = "api://aaaaaaaa-0000-0000-0000-000000000001",
            ["STUB_URI"] = "1",
            ["STUB_ROLE"] = "2",
            ["STUB_APP_LEFT"] = "0",
            ["STUB_SP_LEFT"] = "0",
            ["STUB_CURL_CODES"] = "200",
            ["STUB_DESTROY_PLANT"] = UnmappedCanary,
        });
        Assert.Equal(1, run.Exit);
        Assert.Contains("agenttokens destroy: read-back clean", run.Out, StringComparison.Ordinal);
        AssertLeakNamed(run.Out, "run-created-client-secret-unmapped", UnmappedCanary);
        // the mapped arm's own canary is nowhere in the log - its arm must stay
        // silent while the unmapped one fires (this cell is the positive witness
        // that made the mapped-only pair complete all five arms):
        Assert.DoesNotContain("run-created-client-secret-mapped", run.Out, StringComparison.Ordinal);
        Assert.DoesNotContain(MappedCanary, run.Out, StringComparison.Ordinal);
        Assert.True(
            run.Out.IndexOf("agenttokens destroy: read-back clean", StringComparison.Ordinal)
                < run.Out.IndexOf("secret material appears", StringComparison.Ordinal),
            "the scan that names the arm must run after the destroy that plants it");
        Assert.Contains(UnmappedCanary, RunnerLog(run.Out), StringComparison.Ordinal);
        Assert.DoesNotContain(UnmappedCanary, run.Err, StringComparison.Ordinal);
    }

    [Fact]
    public void ContainerRunMaterialKeys_PlantedFromScratchHandoff_NameBothMaterialArms_AndFails()
    {
        SecretPropagationStubs.WriteExec(_stubBin, "az", AcaScriptTests.StubAz);
        var run = Run("aca", new()
        {
            // every canned arm pinned to its happy default, as the script-leg cells
            // do - an arm the runner fails to invoke shows as the stub's loud error:
            ["STUB_AZ_SIGNED_IN"] = "1",
            ["STUB_EXT"] = "1",
            ["STUB_ROLE_OK"] = "1",
            ["STUB_VAULT"] = "1",
            ["STUB_ACR"] = "1",
            ["STUB_DIGEST"] = "1",
            ["STUB_APP_EXISTS"] = "0",
            ["STUB_JOB_EXISTS"] = "0",
            ["STUB_KUBELET"] = "true",
            ["STUB_ID_COUNT"] = "2",
            ["STUB_STAMP"] = AcaScriptTests.AcaDigestHead,
            ["STUB_STATUS"] = "Succeeded",
            ["STUB_LOGS"] = "ok",
            ["STUB_START"] = "ok",
            ["STUB_LISTDELETED"] = "0",
            ["STUB_ID_LEFT"] = "0",
            ["STUB_ROLE_LEFT"] = "0",
            ["STUB_PRIN"] = "1",
            ["STUB_RG_EXISTS"] = "false",
            ["STUB_ACR_LEFT"] = "0",
            // the offline poll knobs: shapes identical, seconds instead of minutes:
            ["CREDPROX_M46_ACA_POLL_S"] = "1",
            ["CREDPROX_M46_ACA_POLL_N"] = "2",
            ["CREDPROX_M46_ACA_POLL_RG_N"] = "2",
            ["CREDPROX_M46_ACA_VERIFY_POLL_S"] = "0",
            ["CREDPROX_M46_ACA_VERIFY_N"] = "2",
            // the plant: hand off the minted values on the unsuppressed
            // material-phase stderr door:
            ["STUB_PLANT_HANDOFF"] = "1",
        });
        Assert.Equal(1, run.Exit);
        Assert.Contains("live-m46-aca.sh destroy (read-backs decide, RG included)", run.Out, StringComparison.Ordinal);
        AssertLeakNamed(run.Out, "run-material-caller-key", PlantValue(run.Out, "ACA_CALLER_KEY"));
        AssertLeakNamed(run.Out, "run-material-vendor-key", PlantValue(run.Out, "ACA_VENDOR_KEY"));
        // both arms named on the SAME single leak line (one scan, both matches):
        var failLine = run.Out.Split('\n').Single(l => l.Contains("secret material appears", StringComparison.Ordinal));
        Assert.Contains("run-material-caller-key run-material-vendor-key", failLine, StringComparison.Ordinal);
        Assert.True(
            run.Out.IndexOf("live-m46-aca.sh destroy (read-backs decide", StringComparison.Ordinal)
                < run.Out.IndexOf("secret material appears", StringComparison.Ordinal),
            "the scan that names the arms must run after the destroys");
        Assert.DoesNotContain(PlantValue(run.Out, "ACA_CALLER_KEY"), run.Err, StringComparison.Ordinal);
        Assert.DoesNotContain(PlantValue(run.Out, "ACA_VENDOR_KEY"), run.Err, StringComparison.Ordinal);
    }

    // the runner's own log file (named by its early "log: " line), read back:
    private string RunnerLog(string stdout)
    {
        _runnerLog = RunnerLoadedSecretScanTests.ExtractRunnerLogPath(stdout);
        return File.ReadAllText(_runnerLog);
    }

    // the minted handoff value for a key, read back from the runner log the plant
    // wrote (openssl-minted, so the cell cannot know it up front):
    private string PlantValue(string stdout, string key)
    {
        foreach (var line in RunnerLog(stdout).Split('\n'))
        {
            if (line.StartsWith(key + "=", StringComparison.Ordinal))
            {
                return line[(key.Length + 1)..].Trim();
            }
        }

        throw new InvalidOperationException($"the planted handoff line {key}=... is not in the runner log");
    }

    // exactly one leak line names the expected kind, and neither it nor the value
    // pointer below it echoes the planted value:
    private static void AssertLeakNamed(string stdout, string kind, string plantedValue)
    {
        var lines = stdout.Split('\n');
        var leakLine = Assert.Single(lines, l => l.Contains("secret material appears", StringComparison.Ordinal));
        var at = Array.IndexOf(lines, leakLine);
        Assert.Contains(kind, lines[at], StringComparison.Ordinal);
        Assert.DoesNotContain(plantedValue, lines[at], StringComparison.Ordinal);
        Assert.DoesNotContain(plantedValue, lines[at + 1], StringComparison.Ordinal);
    }

    // INFO-1 from the m46m check: the naming invariant above was prose-only, so
    // nothing failed if it broke. This cell derives the leg-filter tokens from
    // live-run.sh itself (no hand-copied list) and asserts none of them occurs
    // in a name --filter FullyQualifiedName~ could select from this class: the
    // class name, every method it declares, every nested type name. It turns
    // RED every way the invariant can rot: a rename of any marked class's name
    // into a token in any case, a new leg filter token naming a marked class, a
    // runner-execing file without a marked class, a marked class without the call.
    [Fact]
    public void NamesCarryNoRunnerFilterToken()
    {
        var runnerPath = SecretPropagationStubs.LocateRunner();
        var runner = File.ReadAllText(runnerPath);
        var tokens = new SortedSet<string>(StringComparer.Ordinal);
        foreach (Match match in Regex.Matches(runner, @"FullyQualifiedName~([A-Za-z0-9_.]+)"))
        {
            tokens.Add(match.Groups[1].Value);
        }

        // five legs expose eleven distinct tokens (measured 2026-11-25); pinned
        // to equality (m46u finding 3), so a stripped-out filter or a new leg token
        // lands here instead of leaving this cell vacuously green:
        Assert.True(tokens.Count == 11, $"live-run.sh exposes {tokens.Count} filter tokens, expected 11: {string.Join(",", tokens)}");

        // VSTest's ~ match is case-INsensitive, so the comparison must be too:
        // an exact-case comparison let a case-variant rename slip through this
        // guard while the real leg filter DID select the cell (measured 2026-11-22).
        const BindingFlags DeclaredMembers = BindingFlags.DeclaredOnly | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static;
        var marked = typeof(RunnerRunCreatedScanTests).Assembly.GetTypes()
            .Where(t => t.IsClass && !t.IsAbstract && typeof(ExecutesLiveRunner).IsAssignableFrom(t))
            .ToList();
        // equality, not a floor (m46u finding 3): eight measured 2026-11-22, twelve
        // measured 2026-11-25 - a dropped marker must not stay GREEN as merely
        // the ninth of "at least eight":
        Assert.True(marked.Count == 12, $"expected 12 classes deriving ExecutesLiveRunner, found {marked.Count} (twelve measured 2026-11-25)");

        foreach (var type in marked)
        {
            var names = new List<string> { type.FullName ?? type.Name };
            foreach (var method in type.GetMethods(DeclaredMembers))
            {
                names.Add(method.Name);
            }

            foreach (var nested in type.GetNestedTypes(DeclaredMembers))
            {
                names.Add(nested.FullName ?? nested.Name);
            }

            foreach (var token in tokens)
            {
                foreach (var name in names)
                {
                    Assert.DoesNotContain(token, name, StringComparison.OrdinalIgnoreCase);
                }
            }
        }

        // Textual arms, both directions - reflection cannot see method calls, so
        // the marker set is pinned against the code it stands for. The arms read
        // the same comment-stripped code the OBSERVED pin uses: on raw text a
        // brace-less declaration's base-list group reached past its own line and
        // a comment naming the marker counted (m46u finding 4). PER DECLARATION
        // (m46u finding 1): every class whose own body calls LocateRunner() derives
        // the marker - a multi-marked file dropping one marker now REDs instead
        // of reading even against its siblings. The stale direction stays
        // per-file. Generated obj/ and bin/ output is not source (m46u finding 2).
        var testDir = Path.Combine(Directory.GetParent(runnerPath)!.Parent!.FullName, "tests", "CredProx.LiveTests");
        var declarations = new Regex(@"^\s*(?:public|internal|sealed|static|\s)*(?:class|record)\s+([A-Za-z_]\w*)([^{\n]*)", RegexOptions.Multiline);
        var declaredMarkedCount = 0;
        var unmarkedExecers = new List<string>();
        foreach (var file in SourceFiles(testDir))
        {
            var code = LiveFixtureBuildProofTests.ScannableCode(File.ReadAllText(file));
            var fileMarked = 0;
            foreach (Match decl in declarations.Matches(code))
            {
                if (decl.Groups[2].Value.Contains("ExecutesLiveRunner", StringComparison.Ordinal))
                {
                    fileMarked++;
                    continue;
                }

                // an unmarked declaration's own body: its opening brace must come
                // next (a positional record ends in ';' instead), and its call
                // mentions must not outnumber its definitions:
                var at = decl.Index + decl.Length;
                while (at < code.Length && char.IsWhiteSpace(code[at]))
                {
                    at++;
                }

                if (at < code.Length && code[at] == '{' && CallsRunner(code[at..MethodBodyEnd(code, at)]))
                {
                    unmarkedExecers.Add($"{Path.GetFileName(file)}::{decl.Groups[1].Value}");
                }
            }

            declaredMarkedCount += fileMarked;
            Assert.True(fileMarked == 0 || code.Contains("LocateRunner()", StringComparison.Ordinal),
                $"{Path.GetFileName(file)} declares an ExecutesLiveRunner class but never calls LocateRunner() - the marker is stale");
        }

        Assert.True(unmarkedExecers.Count == 0,
            $"classes exec live-run.sh without deriving the marker - the guard above cannot see their names: {string.Join(", ", unmarkedExecers)}");

        // The stale arm cannot see one of several marked classes in the SAME
        // file dropping its marker, so the sets are counted against each other:
        // reflection and text must see the same number of marked classes.
        Assert.True(marked.Count == declaredMarkedCount,
            $"reflected {marked.Count} ExecutesLiveRunner classes but text declared {declaredMarkedCount} - the marker set drifted");
    }

    // m46m finding 1: the naming cell above discovers its classes by reflection;
    // this arm re-checks the same invariant on SOURCE text, so one blind
    // discovery mechanism can no longer darken the naming guard unnoticed -
    // this very branch watched one discovery mechanism go blind (U-B7: live
    // attributes discovered by name suffix). Same strip, same file set, same
    // tokens; the declared class NAME is what a leg selects with
    // FullyQualifiedName~ (the fully qualified name, case-insensitively, per
    // the header). MEASURED LIMIT, recorded not chased: a declaration-shaped
    // line inside a raw body reads as a declaration here too - the strip keeps
    // raw bodies verbatim on purpose, and no source carries one today (the
    // same limit the OBSERVED pin records).
    [Fact]
    public void MarkedClassNamesInSourceTextCarryNoFilterToken()
    {
        var runnerPath = SecretPropagationStubs.LocateRunner();
        var tokens = new SortedSet<string>(StringComparer.Ordinal);
        foreach (Match match in Regex.Matches(File.ReadAllText(runnerPath), @"FullyQualifiedName~([A-Za-z0-9_.]+)"))
        {
            tokens.Add(match.Groups[1].Value);
        }

        Assert.True(tokens.Count == 11, $"live-run.sh exposes {tokens.Count} filter tokens, expected 11: {string.Join(",", tokens)}");

        var testDir = Path.Combine(Directory.GetParent(runnerPath)!.Parent!.FullName, "tests", "CredProx.LiveTests");
        var declarations = new Regex(@"^\s*(?:public|internal|sealed|static|\s)*(?:class|record)\s+([A-Za-z_]\w*)([^{\n]*)", RegexOptions.Multiline);
        var offenders = new List<string>();
        var seen = 0;
        foreach (var file in SourceFiles(testDir))
        {
            var code = LiveFixtureBuildProofTests.ScannableCode(File.ReadAllText(file));
            foreach (Match decl in declarations.Matches(code))
            {
                if (!decl.Groups[2].Value.Contains("ExecutesLiveRunner", StringComparison.Ordinal))
                {
                    continue;
                }

                seen++;
                foreach (var token in tokens)
                {
                    if (decl.Groups[1].Value.Contains(token, StringComparison.OrdinalIgnoreCase))
                    {
                        offenders.Add($"{Path.GetFileName(file)}::{decl.Groups[1].Value} carries {token}");
                    }
                }
            }
        }

        Assert.True(seen == 12, $"source text declares {seen} marked classes, expected 12 (measured 2026-11-25)");
        Assert.True(offenders.Count == 0,
            $"marked class names carrying a runner filter token would be selected by that leg: {string.Join(", ", offenders)}");
    }

    [Fact]
    public void LiveAttributedCells_EachCarriesItsOwnObservedLiteral()
    {
        // The runner builds each vendor's PASS line from the leg log's OBSERVED
        // lines — every one of them, aggregated since post-release item 3 — and
        // records FAIL when the log holds neither an OBSERVED line nor a skip,
        // so a live cell that writes no OBSERVED line records an already-spent
        // run as FAIL. The pin is PER METHOD (post-release item 6): the old
        // per-file reading let one cell's OBSERVED line stand in for every
        // other live cell in the same file, which is exactly the drift the
        // per-method writes exist to prevent. Comments cannot mask or fake a
        // WriteLine: the scan reads the same comment- and string-aware strip
        // the build-proof guard uses (a first draft of this cell read raw text,
        // a comment naming the token passed it, and the witness caught it).
        // MEASURED LIMIT, recorded not chased: an attribute-looking line inside
        // a quoted or raw body would read as an attributed method — no source
        // carries one today, and the strip keeps raw bodies verbatim on purpose.
        var testDir = Path.Combine(
            Directory.GetParent(SecretPropagationStubs.LocateRunner())!.Parent!.FullName,
            "tests", "CredProx.LiveTests");
        var liveFactUsage = new Regex(@"^\s*\[[\w.]*LiveFact\b", RegexOptions.Multiline);
        var offenders = new List<string>();
        foreach (var file in SourceFiles(testDir))
        {
            var code = LiveFixtureBuildProofTests.ScannableCode(File.ReadAllText(file));
            foreach (Match attributed in liveFactUsage.Matches(code))
            {
                // The method is the declaration the attribute sits on; its body
                // is the brace-matched block that follows. The name is read back
                // from the last argument list before the body opens.
                var head = code[attributed.Index..];
                var bodyStart = code.IndexOf('{', attributed.Index);
                if (bodyStart < 0)
                {
                    offenders.Add($"{Path.GetFileName(file)} (live attribute with no following body)");
                    continue;
                }

                var sigAt = head[..(bodyStart - attributed.Index)].LastIndexOf('(');
                var declared = sigAt > 0
                    ? Regex.Match(head[..sigAt], @"([A-Za-z_]\w*)\s*$").Groups[1].Value
                    : "?";
                var body = code[bodyStart..MethodBodyEnd(code, bodyStart)];
                if (!body.Contains("OBSERVED ", StringComparison.Ordinal))
                {
                    offenders.Add($"{Path.GetFileName(file)}::{declared}");
                }
            }
        }

        Assert.True(offenders.Count == 0,
            $"live-attributed methods with no OBSERVED literal in their own body - their legs could not record a PASS: {string.Join(", ", offenders)}");
    }

    // Brace-matches a body in stripped code: the strip has already dropped
    // comments, so the only non-structure braces left sit inside quoted and
    // raw literals. An exact-three-quote run toggles the same raw state the
    // strip uses (opener AND closer); inside a raw body or a quoted literal no
    // brace counts, and a backslash never lets an escaped quote close a string.
    // An unbalanced tail returns the end of the text.
    private static int MethodBodyEnd(string code, int openBrace)
    {
        var depth = 0;
        var inString = false;
        var inRaw = false;
        for (var i = openBrace; i < code.Length; i++)
        {
            var c = code[i];
            if (c == '"' && i + 2 < code.Length && code[i + 1] == '"' && code[i + 2] == '"'
                && !(i + 3 < code.Length && code[i + 3] == '"'))
            {
                inRaw = !inRaw;
                i += 2;
            }
            else if (inRaw)
            {
                // raw body: data another scan reads; its braces are content
            }
            else if (c == '"')
            {
                inString = !inString;
            }
            else if (inString)
            {
                if (c == '\\')
                {
                    i++;
                }
            }
            else if (c == '{')
            {
                depth++;
            }
            else if (c == '}' && --depth == 0)
            {
                return i + 1;
            }
        }

        return code.Length;
    }

    // The test-dir walk minus generated output: the compiler's obj/ and bin/
    // intermediates are not source, and their generated attributes drift with
    // the toolchain (m46u finding 2: six of the files the old walk scanned were
    // generated).
    private static IEnumerable<string> SourceFiles(string testDir) =>
        Directory.EnumerateFiles(testDir, "*.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                     && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal));

    // A class EXECs the runner when its code (outside string content) mentions
    // LocateRunner() more often than it defines it: the locator's own stub
    // class (SecretPropagationStubs) defines the method inside an unmarked
    // class, and a definition alone must not read as an exec. The strip keeps
    // string content as data on purpose, and three unmarked classes name the
    // call inside their assertion strings (measured 2026-11-25), so the counts
    // blank literal content first.
    private static bool CallsRunner(string body)
    {
        var code = BlankLiterals(body);
        return Regex.Matches(code, @"\bLocateRunner\(\)").Count
             > Regex.Matches(code, @"\bstring\s+LocateRunner\(\)").Count;
    }

    // Blanks quoted and raw content so a mention inside a literal is data, not
    // an exec: an exact-three-quote run toggles raw state (like the strip), a
    // backslash escapes the char it precedes inside a string or char literal,
    // and everything inside a literal becomes spaces. The strip's known limits
    // carry over (verbatim "" runs count as a close plus an open).
    private static string BlankLiterals(string body)
    {
        var chars = body.ToCharArray();
        var inString = false;
        var inChar = false;
        var inRaw = false;
        for (var i = 0; i < chars.Length; i++)
        {
            if ((inString || inChar) && chars[i] == '\\')
            {
                chars[i] = ' ';
                if (i + 1 < chars.Length)
                {
                    chars[i + 1] = ' ';
                    i++;
                }

                continue;
            }

            var isTriple = chars[i] == '"' && i + 2 < chars.Length
                && chars[i + 1] == '"' && chars[i + 2] == '"'
                && !(i + 3 < chars.Length && chars[i + 3] == '"');
            if (isTriple && !inString && !inChar)
            {
                inRaw = !inRaw;
                chars[i] = chars[i + 1] = chars[i + 2] = ' ';
                i += 2;
                continue;
            }

            if (inRaw)
            {
                chars[i] = ' ';
                continue;
            }

            if (chars[i] == '"' && !inChar)
            {
                inString = !inString;
                continue;
            }

            if (chars[i] == '\'' && !inString)
            {
                inChar = !inChar;
                continue;
            }

            if (inString || inChar)
            {
                chars[i] = ' ';
            }
        }

        return new string(chars);
    }

    private sealed record RunnerRun(int Exit, string Out, string Err);

    private RunnerRun Run(string vendor, Dictionary<string, string> stubEnv)
    {
        _runnerLog = null;
        var azLogPath = Path.Combine(Path.GetTempPath(), $"credprox-m46-azlog-{Guid.NewGuid():N}.log");
        var psi = new ProcessStartInfo
        {
            FileName = "/bin/bash",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add(_runner);
        psi.ArgumentList.Add(vendor);
        psi.Environment["PATH"] = _stubBin + ":/usr/bin:/bin";
        psi.Environment["HOME"] = _home;
        psi.Environment["CREDPROX_M46_SCRATCH"] = _scratch;
        psi.Environment["CREDPROX_M46_ACA_SCRATCH"] = _scratch;
        psi.Environment["STUB_AZ_LOG"] = azLogPath;
        psi.Environment["STUB_CURL_COUNT"] = _countFile;
        foreach (var (key, value) in stubEnv)
        {
            psi.Environment[key] = value;
        }

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("live-run.sh did not start");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        Assert.True(process.WaitForExit(120_000), "live-run.sh did not exit within 120 s");
        if (File.Exists(azLogPath))
        {
            File.Delete(azLogPath);
        }

        return new RunnerRun(process.ExitCode, stdout.Result, stderr.Result);
    }

    public void Dispose()
    {
        foreach (var dir in new[] { _stubBin, _home, _scratch })
        {
            SecretPropagationStubs.TryDelete(dir);
        }

        try
        {
            if (_runnerLog is not null && File.Exists(_runnerLog))
            {
                File.Delete(_runnerLog);
            }
        }
        catch (IOException)
        {
            // scratch tree
        }
    }
}
