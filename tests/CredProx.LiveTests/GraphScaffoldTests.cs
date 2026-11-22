using System.Diagnostics;
using Xunit;

namespace CredProx.LiveTests;

// The MicrosoftGraph vendor's machine-local contract, proven offline against
// planted files in the temp directory (same shape as the AiGateway contract
// cells): a missing file names TENANT_ID, a loose mode names the actual octal, a
// well-formed 600 file round-trips, and a wrong-shape tenant id is a problem that
// names the variable and the expectation but never the value. These cells use the
// path override and never touch the real ~/.config/credprox-live.
[Trait("Layer", "Offline")]
public sealed class GraphEnvContractTests : IDisposable
{
    private readonly string _tempPath = Path.Combine(
        Path.GetTempPath(),
        $"credprox-live-graph-{Guid.NewGuid():N}.env");

    public void Dispose()
    {
        try
        {
            File.Delete(_tempPath);
        }
        catch (IOException)
        {
            // scratch file; the temp dir clears it
        }
    }

    [Fact]
    public void FileGate_NamesTheVariable_ModeAndRoundTrip()
    {
        var absent = LiveEnv.Probe(GraphEnv.Vendor, GraphEnv.RequiredKeys, _tempPath + ".absent");
        Assert.False(absent.Available);
        Assert.Contains("does not exist", absent.SkipReason, StringComparison.Ordinal);
        Assert.Contains("~/.config/credprox-live/live.env", absent.SkipReason, StringComparison.Ordinal);
        Assert.Contains("TENANT_ID", absent.SkipReason, StringComparison.Ordinal);

        File.WriteAllLines(_tempPath, new[] { "TENANT_ID=00000000-0000-0000-0000-000000000000" });
        File.SetUnixFileMode(
            _tempPath,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead); // 644
        var loose = LiveEnv.Probe(GraphEnv.Vendor, GraphEnv.RequiredKeys, _tempPath);
        Assert.False(loose.Available);
        Assert.Contains("mode 644, must be exactly 600", string.Join("; ", loose.Problems), StringComparison.Ordinal);

        var missing = Path.Combine(Path.GetTempPath(), $"credprox-live-graph-missing-{Guid.NewGuid():N}.env");
        File.WriteAllLines(missing, new[] { "# no keys here" });
        File.SetUnixFileMode(missing, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        var noKey = LiveEnv.Probe(GraphEnv.Vendor, GraphEnv.RequiredKeys, missing);
        Assert.False(noKey.Available);
        Assert.Contains("missing variables: TENANT_ID", string.Join("; ", noKey.Problems), StringComparison.Ordinal);
        File.Delete(missing);

        File.SetUnixFileMode(_tempPath, UnixFileMode.UserRead | UnixFileMode.UserWrite); // 600
        var probe = LiveEnv.Probe(GraphEnv.Vendor, GraphEnv.RequiredKeys, _tempPath);
        Assert.True(probe.Available, string.Join("; ", probe.Problems));
        Assert.Equal("00000000-0000-0000-0000-000000000000", probe.Values["TENANT_ID"]);
    }

    [Fact]
    public void ValueProblems_NameBadShapesWithoutEchoingValues()
    {
        var domain = GraphEnv.ValueProblems(new Dictionary<string, string>
        {
            ["TENANT_ID"] = "contoso.onmicrosoft.com",
        });
        Assert.Single(domain);
        Assert.Contains("TENANT_ID", domain[0], StringComparison.Ordinal);
        Assert.DoesNotContain("contoso", domain[0], StringComparison.Ordinal);

        var quoted = GraphEnv.ValueProblems(new Dictionary<string, string>
        {
            ["TENANT_ID"] = "\"00000000-0000-0000-0000-000000000000\"",
        });
        Assert.Single(quoted);
        Assert.DoesNotContain("00000000", quoted[0], StringComparison.Ordinal);

        var good = GraphEnv.ValueProblems(new Dictionary<string, string>
        {
            ["TENANT_ID"] = "00000000-0000-0000-0000-000000000000",
        });
        Assert.Empty(good);
    }
}

// The offline contract for scripts/live-graph-app.sh, run against a stub az
// shadowed at the front of PATH. Nothing here can touch a tenant: every az
// answer is canned, and each call is logged so a cell can also assert what did
// NOT happen (a dry-run must never call create; the signed-in gate must die
// before any write verb; the stub REFUSES the grant-era calls — az rest and
// ad app permission admin-consent — so any regression toward granting dies
// offline). The claims proven: destroy's exit code reflects its own read-back
// (apps left, or service principals left, flips it to 1 with the failure marker
// on stderr), create pipes the run-created secret to the scratch handoff
// without ever echoing it, and the create-side read-back fails loudly when the
// credential the script asked for is not there.
[Trait("Layer", "Offline")]
public sealed class GraphAppScriptTests : IDisposable
{
    private const string StubSecret = "canary-secret-do-not-echo";
    private const string StubAppId = "aaaaaaaa-0000-0000-0000-000000000001";

    private static readonly string ScriptPath = LocateScript();
    private readonly string _stubBin;
    private readonly string _scratch;

    public GraphAppScriptTests()
    {
        _stubBin = Path.Combine(Path.GetTempPath(), $"credprox-m46-stubbin-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_stubBin);
        var azStub = Path.Combine(_stubBin, "az");
        File.WriteAllText(azStub, StubAz);
        File.SetUnixFileMode(
            azStub,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
            | UnixFileMode.GroupRead | UnixFileMode.GroupExecute
            | UnixFileMode.OtherRead | UnixFileMode.OtherExecute); // 755
        _scratch = Path.Combine(Path.GetTempPath(), $"credprox-m46-scratch-{Guid.NewGuid():N}");
    }

    public void Dispose()
    {
        foreach (var dir in new[] { _stubBin, _scratch })
        {
            try
            {
                if (Directory.Exists(dir))
                {
                    Directory.Delete(dir, recursive: true);
                }
            }
            catch (IOException)
            {
                // scratch dirs; /tmp clears them
            }
        }
    }

    [Fact]
    public void Destroy_ZeroReadBack_ExitsZero()
    {
        var run = Run("destroy");
        Assert.True(run.Exit == 0, $"destroy with zero leftovers must exit 0: exit={run.Exit} err={run.Err}");
        Assert.Contains("OK live-graph-app destroy", run.Out, StringComparison.Ordinal);
    }

    [Fact]
    public void Destroy_AppStillListed_ExitsOneAndNamesTheReadback()
    {
        var run = Run("destroy", new() { ["STUB_APP_LEFT"] = "1" });
        Assert.Equal(1, run.Exit);
        Assert.Contains("DESTROY-READBACK FAILED", run.Err, StringComparison.Ordinal);
        Assert.DoesNotContain("OK live-graph-app destroy", run.Out, StringComparison.Ordinal);
    }

    [Fact]
    public void Destroy_ServicePrincipalLeft_ExitsOne()
    {
        // the app list is empty (the delete "succeeded") but the SP list still
        // shows one — the read-back must catch that alone:
        var run = Run("destroy", new() { ["STUB_SP_LEFT"] = "1" });
        Assert.Equal(1, run.Exit);
        Assert.Contains("service-principals left=1", run.Err, StringComparison.Ordinal);
    }

    [Fact]
    public void Create_HappyPath_PipesSecretToScratchAndNeverEchoesIt()
    {
        var run = Run("create");
        Assert.True(run.Exit == 0, $"create must exit 0: exit={run.Exit} err={run.Err}");
        Assert.Contains("OK live-graph-app create", run.Out, StringComparison.Ordinal);
        Assert.DoesNotContain(StubSecret, run.Out + run.Err, StringComparison.Ordinal);
        Assert.DoesNotContain(StubSecret, run.Log, StringComparison.Ordinal);

        var idPath = Path.Combine(_scratch, "client-id.txt");
        var secretPath = Path.Combine(_scratch, "client-secret.txt");
        Assert.Equal(StubAppId, File.ReadAllText(idPath).Trim());
        Assert.Equal(StubSecret, File.ReadAllText(secretPath).Trim());
        // exact 600 on the handoff files, exact 700 on the scratch dir:
        Assert.Equal(Convert.ToInt32("600", 8), (int)File.GetUnixFileMode(secretPath));
        Assert.Equal(Convert.ToInt32("600", 8), (int)File.GetUnixFileMode(idPath));
        Assert.Equal(Convert.ToInt32("700", 8), (int)File.GetUnixFileMode(_scratch));
    }

    [Fact]
    public void Create_NeverRequestsGrantsOrConsent()
    {
        // The no-consent contract (owner decision 2026-11-22): the script must
        // never PATCH requiredResourceAccess and never call admin-consent. The
        // stub refuses both loudly (exit 9), so a regressed script cannot even
        // reach its read-backs; the log assertions pin the claim in the other
        // direction too — a refused call still leaves its shape in the log:
        var run = Run("create");
        Assert.True(run.Exit == 0, $"create must exit 0: exit={run.Exit} err={run.Err}");
        Assert.DoesNotContain("admin-consent", run.Log, StringComparison.Ordinal);
        Assert.DoesNotContain("requiredResourceAccess", run.Log, StringComparison.Ordinal);
        Assert.DoesNotContain("rest --method", run.Log, StringComparison.Ordinal);
    }

    [Fact]
    public void Create_NoAzOnPath_DiesBeforeAnyWrite()
    {
        var run = Run("create", new(), withAz: false);
        Assert.Equal(1, run.Exit);
        Assert.Contains("az CLI not on PATH", run.Err, StringComparison.Ordinal);
        Assert.False(Directory.Exists(_scratch), "the scratch dir must not be created before the gates pass");
    }

    [Fact]
    public void Create_NoSignedIn_DiesBeforeAnyWrite()
    {
        var run = Run("create", new() { ["STUB_AZ_SIGNED_IN"] = "0" });
        Assert.Equal(1, run.Exit);
        Assert.Contains("no active az login", run.Err, StringComparison.Ordinal);
        Assert.DoesNotContain("ad app create", run.Log, StringComparison.Ordinal);
    }

    [Fact]
    public void DryRun_PrintsThePlanButTouchesNothing()
    {
        var run = Run("--dry-run");
        Assert.True(run.Exit == 0, $"--dry-run must exit 0: exit={run.Exit} err={run.Err}");
        Assert.Contains("DRY-RUN", run.Out, StringComparison.Ordinal);
        Assert.DoesNotContain("ad app create", run.Log, StringComparison.Ordinal);
        Assert.DoesNotContain("ad app delete", run.Log, StringComparison.Ordinal);
        Assert.DoesNotContain("credential reset", run.Log, StringComparison.Ordinal);
        // no tenant fact is resolved any more — the run grants nothing, so the
        // Graph service-principal and app-role lookups are gone from the script:
        Assert.DoesNotContain("ad sp list", run.Log, StringComparison.Ordinal);
        Assert.DoesNotContain("az rest", run.Log, StringComparison.Ordinal);
        Assert.DoesNotContain("admin-consent", run.Log, StringComparison.Ordinal);
        Assert.False(Directory.Exists(_scratch), "--dry-run must not create the scratch dir");
    }

    [Fact]
    public void UnknownVerb_PrintsUsageAndExitsTwo()
    {
        var run = Run("obliterate");
        Assert.Equal(2, run.Exit);
        Assert.Contains("usage: live-graph-app.sh create|destroy|--dry-run", run.Err, StringComparison.Ordinal);
    }

    private sealed record ScriptRun(int Exit, string Out, string Err, string Log);

    private ScriptRun Run(string verb, Dictionary<string, string>? stubEnv = null, bool withAz = true)
    {
        var logPath = Path.Combine(Path.GetTempPath(), $"credprox-m46-azlog-{Guid.NewGuid():N}.log");
        var psi = new ProcessStartInfo
        {
            FileName = "/bin/bash",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add(ScriptPath);
        psi.ArgumentList.Add(verb);
        // withAz: the stub dir leads, so it shadows the machine's real az; the
        // system dirs stay behind it for the script's ordinary tools (date) and
        // for the stub's own env-bash shebang. Without it the PATH holds nothing,
        // which is exactly the no-az arm.
        psi.Environment["PATH"] = withAz ? _stubBin + ":/usr/bin:/bin" : "/credprox-m46-no-az-here";
        psi.Environment["CREDPROX_M46_SCRATCH"] = _scratch;
        psi.Environment["STUB_AZ_LOG"] = logPath;
        psi.Environment["STUB_SECRET"] = StubSecret;
        psi.Environment["STUB_APP_ID"] = StubAppId;
        // hermetic: pin every canned arm to its happy default so an ambient
        // STUB_* from some outer harness (live-run.sh sets these for its own
        // legs) cannot change this cell's canned answers
        psi.Environment["STUB_AZ_SIGNED_IN"] = "1";
        psi.Environment["STUB_CRED"] = "1";
        psi.Environment["STUB_APP_LEFT"] = "0";
        psi.Environment["STUB_SP_LEFT"] = "0";
        if (stubEnv is not null)
        {
            foreach (var (key, value) in stubEnv)
            {
                psi.Environment[key] = value;
            }
        }

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("the script did not start");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        Assert.True(process.WaitForExit(60_000), "the script did not exit within 60 s");
        var log = File.Exists(logPath) ? File.ReadAllText(logPath) : string.Empty;
        File.Delete(logPath);
        return new ScriptRun(process.ExitCode, stdout.Result, stderr.Result, log);
    }

    // Walk up from this assembly's bin folder to the repository root, then into
    // scripts/ (same locating discipline as LiveHosts.LocateBin).
    private static string LocateScript()
    {
        var own = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
        var parts = own.Split(Path.DirectorySeparatorChar);
        var binIndex = Array.IndexOf(parts, "bin");
        if (binIndex < 3)
        {
            throw new InvalidOperationException($"unexpected test assembly location '{own}'");
        }

        // Path.Combine would drop the empty first segment of an absolute path:
        var repoRoot = string.Join(Path.DirectorySeparatorChar, parts[..(binIndex - 2)]);
        var script = Path.Combine(repoRoot, "scripts", "live-graph-app.sh");
        if (!File.Exists(script))
        {
            throw new InvalidOperationException($"the lifecycle script is not where the test expects it: {script}");
        }

        return script;
    }

    // Canned az answers keyed off the verb line; env switches drive the failure
    // arms (STUB_AZ_SIGNED_IN, STUB_APP_LEFT, STUB_SP_LEFT; the
    // STUB_CREATE_FAIL/STUB_PLANT/STUB_DESTROY_PLANT trio serves the runner
    // leak-scan cells below, which exec live-run.sh against this same stub).
    // The grant-era verbs (az rest, permission admin-consent) are REFUSED with
    // exit 9, not canned: a regression toward granting fails offline.
    // Every invocation is logged so cells can assert absence of write verbs too.
    // INTERNAL (not private): RunnerLeakScanTests reuses this exact stub rather
    // than carrying a second copy that could drift from the verbs' shapes.
    internal const string StubAz = """
        #!/usr/bin/env bash
        if [ -n "${STUB_AZ_LOG:-}" ]; then printf '%s\n' "$*" >> "$STUB_AZ_LOG"; fi
        all="$*"
        case "$all" in
            "account get-access-token"*)
                if [ "${STUB_AZ_SIGNED_IN:-1}" = "0" ]; then echo "Please run 'az login'" >&2; exit 1; fi
                echo '{"accessToken":"stub-token"}'; exit 0;;
            "ad sp list"*"--display-name"*)
                printf '%s\n' "${STUB_SP_LEFT:-0}"; exit 0;;
            "ad app create"*)
                # STUB_CREATE_FAIL plants a line on stderr and refuses; stderr is
                # NOT command-substituted by live-graph-app.sh, so it passes
                # through into the leg's tee'd output and lands in the runner log:
                if [ "${STUB_CREATE_FAIL:-0}" = "1" ]; then echo "${STUB_PLANT:-stub az: create refused}" >&2; exit 1; fi
                printf '%s\n' "${STUB_APP_ID:-stub-app-id}"; exit 0;;
            "ad sp create"*) echo '{}'; exit 0;;
            "rest"*) echo "stub az: REFUSED grant-era call (az rest): $all" >&2; exit 9;;
            "ad app permission admin-consent"*) echo "stub az: REFUSED grant-era call (admin-consent): $all" >&2; exit 9;;
            "ad app credential reset"*) printf '%s\n' "${STUB_SECRET:-stub-secret-value}"; exit 0;;
            "ad app show"*"passwordCredentials"*) printf '%s\n' "${STUB_CRED:-1}"; exit 0;;
            "ad app list"*)
                case "$all" in
                    *length*) printf '%s\n' "${STUB_APP_LEFT:-0}"; exit 0;;
                    *)
                        # the destroy phase's pre-delete list: a plant on stderr
                        # here appears in the log AFTER the failing leg already
                        # exited - only a scan that runs after the destroys sees it:
                        if [ -n "${STUB_DESTROY_PLANT:-}" ]; then echo "$STUB_DESTROY_PLANT" >&2; fi
                        printf '%s\n' "${STUB_EXISTING_IDS:-}"; exit 0;;
                esac;;
            "ad app delete"*) echo '{}'; exit 0;;
            *) echo "stub az: unmatched invocation: $all" >&2; exit 3;;
        esac
        """;
}

// MEDIUM-1 from the 268d470 check: the runner's leak scan lived inline after the
// legs, so a failing leg (create/apply/push/deploy/verify exit 1) skipped it -
// the verify diagnostics left through an unscanned door. This class execs the
// real live-run.sh (vendor=graph: the cheapest az vendor) against the canned az
// above plus a fake dotnet, under a SANDBOX HOME - the machine's real
// ~/.config/credprox-live is never created or read; only this temp tree is.
// Two secret shapes are planted at two different times: a JWT into the failing
// create's stderr passthrough, and a ghp_ token into the destroy the EXIT trap
// runs after that failure. The leak line must name BOTH kinds: jwt-shape proves
// the scan runs on a failing path at all; github-token-shape can only come from
// the post-failure destroy output, so it alone proves the trap scans AFTER the
// destroys. The runner's own leak lines must never echo either value. The class
// name matches none of live-run.sh's filters, so a runner leg can never exec
// this cell and recurse into itself.
[Trait("Layer", "Offline")]
public sealed class RunnerLeakScanTests : IDisposable, IExecutesLiveRunner
{
    private const string PlantedJwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJjYW5hcnktbWVtYmVyIn0.p0kfc3Ffak3sig2natureX9_p0kfc3Ffak3sig2";
    private const string PlantedGhp = "ghp_LeakScanCanaryValue0123456789abcdef";

    private readonly string _stubBin;
    private readonly string _home;
    private readonly string _scratch;
    private readonly string _runner;
    private string? _runnerLog;

    public RunnerLeakScanTests()
    {
        _stubBin = Path.Combine(Path.GetTempPath(), $"credprox-m46-runnerstub-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_stubBin);
        WriteExec("az", GraphAppScriptTests.StubAz);
        WriteExec("dotnet", """
            #!/usr/bin/env bash
            if [ -n "${STUB_AZ_LOG:-}" ]; then printf 'dotnet %s\n' "$*" >> "$STUB_AZ_LOG"; fi
            echo "OBSERVED runner-leak-scan-stub"
            exit 0
            """);
        // sandbox HOME: the runner's env-file gate reads $HOME/.config/credprox-live;
        // it is pointed at THIS tree only, and the central live.env gets the exact
        // 600 it demands (the graph vendor needs only TENANT_ID from it):
        _home = Path.Combine(Path.GetTempPath(), $"credprox-m46-home-{Guid.NewGuid():N}");
        var confDir = Path.Combine(_home, ".config", "credprox-live");
        Directory.CreateDirectory(confDir);
        var envFile = Path.Combine(confDir, "live.env");
        File.WriteAllText(envFile, "TENANT_ID=00000000-0000-0000-0000-000000000000\n");
        File.SetUnixFileMode(envFile, UnixFileMode.UserRead | UnixFileMode.UserWrite); // exactly 600
        _scratch = Path.Combine(Path.GetTempPath(), $"credprox-m46-scratch-{Guid.NewGuid():N}");
        _runner = LocateRunner();
    }

    [Fact]
    public void FailingLeg_PlantedShapes_ScannedFromTheTrapAfterTheDestroys()
    {
        var run = Run(new()
        {
            ["STUB_CREATE_FAIL"] = "1",
            ["STUB_PLANT"] = PlantedJwt,
            ["STUB_DESTROY_PLANT"] = PlantedGhp,
        });
        Assert.Equal(1, run.Exit);
        Assert.Contains("FAIL: live-graph-app.sh create failed", run.Out, StringComparison.Ordinal);
        // the destroy was armed before create and the trap still ran it, clean:
        Assert.Contains("graph destroy: read-back clean", run.Out, StringComparison.Ordinal);
        // then the trap's scan caught BOTH shapes and turned the outcome into FAIL:
        Assert.Contains("secret material appears in the run log", run.Out, StringComparison.Ordinal);
        Assert.Contains("jwt-shape", run.Out, StringComparison.Ordinal);
        Assert.Contains("github-token-shape", run.Out, StringComparison.Ordinal);
        // destroy BEFORE scan - the trap's order is half the point of the fix:
        Assert.True(
            run.Out.IndexOf("graph destroy: read-back clean", StringComparison.Ordinal)
            < run.Out.IndexOf("secret material appears", StringComparison.Ordinal),
            "the trap must scan after the destroys so their output is covered too");
        // the runner's own leak lines never echo the values (the shapes reach the
        // terminal only as the legs' own passthrough - catching that passthrough
        // is what the scan exists for):
        var lines = run.Out.Split('\n');
        var checkedLeakLines = 0;
        for (var i = 0; i + 1 < lines.Length; i++)
        {
            if (!lines[i].Contains("secret material appears", StringComparison.Ordinal))
            {
                continue;
            }

            checkedLeakLines++;
            Assert.DoesNotContain(PlantedJwt, lines[i], StringComparison.Ordinal);
            Assert.DoesNotContain(PlantedGhp, lines[i], StringComparison.Ordinal);
            Assert.DoesNotContain(PlantedJwt, lines[i + 1], StringComparison.Ordinal);
            Assert.DoesNotContain(PlantedGhp, lines[i + 1], StringComparison.Ordinal);
        }

        Assert.Equal(1, checkedLeakLines);
        Assert.DoesNotContain(PlantedJwt, run.Err, StringComparison.Ordinal);
        Assert.DoesNotContain(PlantedGhp, run.Err, StringComparison.Ordinal);
        // both shapes really were in the log the scan read - the FAIL came from
        // finding them, not from the create-fail text itself:
        _runnerLog = ExtractRunnerLogPath(run.Out);
        var runnerLog = File.ReadAllText(_runnerLog);
        Assert.Contains(PlantedJwt, runnerLog, StringComparison.Ordinal);
        Assert.Contains(PlantedGhp, runnerLog, StringComparison.Ordinal);
    }

    private sealed record RunnerRun(int Exit, string Out, string Err, string AzLog);

    private RunnerRun Run(Dictionary<string, string> stubEnv)
    {
        var azLogPath = Path.Combine(Path.GetTempPath(), $"credprox-m46-azlog-{Guid.NewGuid():N}.log");
        var psi = new ProcessStartInfo
        {
            FileName = "/bin/bash",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add(_runner);
        psi.ArgumentList.Add("graph");
        // the stub dir LEADS the PATH: it shadows the machine's az AND any real
        // dotnet (a real `dotnet test` here would recurse the whole battery);
        // system dirs stay behind it for the scripts' ordinary tools:
        psi.Environment["PATH"] = _stubBin + ":/usr/bin:/bin";
        psi.Environment["HOME"] = _home;
        psi.Environment["CREDPROX_M46_SCRATCH"] = _scratch;
        psi.Environment["STUB_AZ_LOG"] = azLogPath;
        // hermetic pins, same discipline as GraphAppScriptTests.Run: every canned
        // arm pinned to its default so no ambient STUB_* can steer this cell:
        psi.Environment["STUB_AZ_SIGNED_IN"] = "1";
        psi.Environment["STUB_CRED"] = "1";
        psi.Environment["STUB_APP_LEFT"] = "0";
        psi.Environment["STUB_SP_LEFT"] = "0";
        psi.Environment["STUB_CREATE_FAIL"] = "0";
        psi.Environment["STUB_PLANT"] = string.Empty;
        psi.Environment["STUB_DESTROY_PLANT"] = string.Empty;
        foreach (var (key, value) in stubEnv)
        {
            psi.Environment[key] = value;
        }

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("live-run.sh did not start");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        Assert.True(process.WaitForExit(120_000), "live-run.sh did not exit within 120 s");
        var azLog = File.Exists(azLogPath) ? File.ReadAllText(azLogPath) : string.Empty;
        File.Delete(azLogPath);
        return new RunnerRun(process.ExitCode, stdout.Result, stderr.Result, azLog);
    }

    private void WriteExec(string name, string body)
    {
        var path = Path.Combine(_stubBin, name);
        File.WriteAllText(path, body);
        File.SetUnixFileMode(
            path,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
            | UnixFileMode.GroupRead | UnixFileMode.GroupExecute
            | UnixFileMode.OtherRead | UnixFileMode.OtherExecute); // 755
    }

    private static string ExtractRunnerLogPath(string stdout)
    {
        foreach (var line in stdout.Split('\n'))
        {
            if (line.StartsWith("log: ", StringComparison.Ordinal))
            {
                return line[5..].Trim();
            }
        }

        throw new InvalidOperationException($"the runner printed no log path; stdout was:\n{stdout}");
    }

    // same walk-up discipline as GraphAppScriptTests.LocateScript, for live-run.sh:
    private static string LocateRunner()
    {
        var own = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
        var parts = own.Split(Path.DirectorySeparatorChar);
        var binIndex = Array.IndexOf(parts, "bin");
        if (binIndex < 3)
        {
            throw new InvalidOperationException($"unexpected test assembly location '{own}'");
        }

        var repoRoot = string.Join(Path.DirectorySeparatorChar, parts[..(binIndex - 2)]);
        var script = Path.Combine(repoRoot, "scripts", "live-run.sh");
        if (!File.Exists(script))
        {
            throw new InvalidOperationException($"the runner is not where the test expects it: {script}");
        }

        return script;
    }

    public void Dispose()
    {
        foreach (var dir in new[] { _stubBin, _home, _scratch })
        {
            try
            {
                if (Directory.Exists(dir))
                {
                    Directory.Delete(dir, recursive: true);
                }
            }
            catch (IOException)
            {
                // scratch trees; /tmp clears them
            }
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
