using System.Diagnostics;
using System.Reflection;
using System.Text.RegularExpressions;
using Xunit;

namespace CredProx.LiveTests;

// Marker: this class EXECs the real scripts/live-run.sh (it resolves the runner
// through LocateRunner() and starts it). RunnerRunCreatedScanTests' guard cell
// walks every implementer: no name on such a class - the class itself, its
// methods, its nested types - may carry one of live-run.sh's --filter tokens in
// any case, or a live leg would select that cell and exec a nested runner. The
// marker plus the guard cell's textual arms against LocateRunner() are the
// definition: reflection cannot see method calls, so a hand-kept list drifts.
internal interface IExecutesLiveRunner
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
// carries the IExecutesLiveRunner marker, and the NamesCarryNoRunnerFilterToken
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
public sealed class RunnerRunCreatedScanTests : IDisposable, IExecutesLiveRunner
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
            ["STUB_ROLE"] = "1",
            ["STUB_ASSIGN"] = "1",
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
            ["STUB_ROLE"] = "1",
            ["STUB_ASSIGN"] = "1",
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

        // five legs each carry at least one token; a stripped-out filter would
        // otherwise make this cell vacuously green:
        Assert.True(tokens.Count >= 5, $"live-run.sh exposes only {tokens.Count} filter tokens: {string.Join(",", tokens)}");

        // VSTest's ~ match is case-INsensitive, so the comparison must be too:
        // an exact-case comparison let a case-variant rename slip through this
        // guard while the real leg filter DID select the cell (measured 2026-11-22).
        const BindingFlags DeclaredMembers = BindingFlags.DeclaredOnly | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static;
        var marked = typeof(RunnerRunCreatedScanTests).Assembly.GetTypes()
            .Where(t => t.IsClass && typeof(IExecutesLiveRunner).IsAssignableFrom(t))
            .ToList();
        Assert.True(marked.Count >= 8, $"only {marked.Count} classes carry IExecutesLiveRunner (eight measured 2026-11-22)");

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
        // the marker set is pinned against the code it stands for: every file
        // calling LocateRunner() declares at least one marked class, and every
        // file declaring one calls LocateRunner(). A runner-execing class added
        // without the marker REDs; a dropped marker whose call stays REDs too.
        var testDir = Path.Combine(Directory.GetParent(runnerPath)!.Parent!.FullName, "tests", "CredProx.LiveTests");
        var declarations = new Regex(@"^\s*(?:public|internal|sealed|static|\s)*(?:class|record)\s+[A-Za-z_]\w*([^{}]*)", RegexOptions.Multiline);
        var declaredMarkedCount = 0;
        foreach (var file in Directory.GetFiles(testDir, "*.cs", SearchOption.AllDirectories))
        {
            var text = File.ReadAllText(file);
            var callsRunner = text.Contains("LocateRunner()", StringComparison.Ordinal);
            var fileMarked = declarations.Matches(text).Cast<Match>()
                .Count(m => m.Groups[1].Value.Contains("IExecutesLiveRunner", StringComparison.Ordinal));
            declaredMarkedCount += fileMarked;
            Assert.True(!callsRunner || fileMarked > 0,
                $"{Path.GetFileName(file)} calls LocateRunner() but declares no IExecutesLiveRunner class - the guard above could not see it");
            Assert.True(fileMarked == 0 || callsRunner,
                $"{Path.GetFileName(file)} declares an IExecutesLiveRunner class but never calls LocateRunner() - the marker is stale");
        }

        // The per-file arms cannot see one of several marked classes in the SAME
        // file dropping its marker, so the sets are counted against each other:
        // reflection and text must see the same number of marked classes.
        Assert.True(marked.Count == declaredMarkedCount,
            $"reflected {marked.Count} IExecutesLiveRunner classes but text declared {declaredMarkedCount} - the marker set drifted");
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
