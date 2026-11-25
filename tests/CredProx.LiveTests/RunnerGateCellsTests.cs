using System.Diagnostics;
using Xunit;

namespace CredProx.LiveTests;

// Cells for the runner gates the 2026-11-22 check asked to pin (the check findings
// are the row's; these cells are the proofs). All exec the REAL live-run.sh under
// a sandbox HOME against the canned az + fake curl + fake dotnet — no az, no
// network, the real ~/.config/credprox-live is never created or read. Class names
// AND method names match NONE of live-run.sh's test filters, in any case (the
// runner's ~ match is case-insensitive), so a runner leg can never exec these cells
// and recurse; RunnerRunCreatedScanTests.NamesCarryNoRunnerFilterToken enforces
// this over every ExecutesLiveRunner-derived class against live-run.sh itself.

// The loaded-value arms (private key, api key) had no cell naming them, and the
// run-created arms matched through a printf|grep pipe that the comment already
// called wrong: under pipefail the grep that exits at its first match leaves the
// printf dying on SIGPIPE (rc 141), the pipeline fails as if nothing matched, and
// a real leak reads as clean. All value matching is now the builtin case match.
// This class plants the two loaded values through the SAME two doors the shape
// cells use — the failing create's stderr passthrough and the post-failure
// destroy — with the private key WRAPPED across lines, so only the folded match
// can catch it (the newline-free invariant is half of why case matching is sound).
[Trait("Layer", "Offline")]
public sealed class RunnerLoadedSecretScanTests : ExecutesLiveRunner, IDisposable
{
    // single line in the central file, exactly as the line-by-line loader stores it:
    private const string LoadedPrivateKey = "RkFLRVBBVkVBTE5PQVJFQUxLRVk=";

    // the same bytes as they reach the log through the console's line wrap:
    private const string WrappedPrivateKey = "RkFLRVBBVkVBTE5PQVJFQUxL\nRVk=";

    // deliberately NOT an sk-ant shape: the FAIL must come from the loaded-arm,
    // never from the shape arm, for this cell to name the arm:
    private const string LoadedApiKey = "loaded-canary-key-0123456789abcdefg";

    private readonly string _stubBin;
    private readonly string _home;
    private readonly string _scratch;
    private readonly string _runner;
    private string? _runnerLog;

    public RunnerLoadedSecretScanTests()
    {
        _stubBin = Path.Combine(Path.GetTempPath(), $"credprox-m46-gatestub-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_stubBin);
        SecretPropagationStubs.WriteExec(_stubBin, "az", GraphAppScriptTests.StubAz);
        SecretPropagationStubs.WriteExec(_stubBin, "dotnet", SecretPropagationStubs.StubDotnet);
        SecretPropagationStubs.WriteExec(_stubBin, "curl", SecretPropagationStubs.StubCurl);
        _home = MakeUnionHome("00000000-0000-0000-0000-000000000000");
        _scratch = Path.Combine(Path.GetTempPath(), $"credprox-m46-gate-scratch-{Guid.NewGuid():N}");
        _runner = SecretPropagationStubs.LocateRunner();
    }

    [Fact]
    public void LoadedArms_NameBothKinds_Fail_AndNeverEchoValues()
    {
        var run = Run(new()
        {
            ["STUB_CREATE_FAIL"] = "1",
            ["STUB_PLANT"] = WrappedPrivateKey,
            ["STUB_DESTROY_PLANT"] = LoadedApiKey,
        });
        Assert.Equal(1, run.Exit);
        Assert.Contains("FAIL: live-graph-app.sh create failed", run.Out, StringComparison.Ordinal);
        Assert.Contains("FAIL: secret material appears in the run log:", run.Out, StringComparison.Ordinal);
        Assert.Contains("loaded-private-key(base64)", run.Out, StringComparison.Ordinal);
        Assert.Contains("loaded-api-key", run.Out, StringComparison.Ordinal);
        // the pem arm must NOT fire: the decoded value is nowhere in the log, so a
        // base64-only leak is named as base64, not as pem:
        Assert.DoesNotContain("loaded-private-key(pem)", run.Out, StringComparison.Ordinal);
        // the tenant arm is no longer a FAIL kind at all:
        Assert.DoesNotContain("loaded-tenant-id", run.Out, StringComparison.Ordinal);
        // the runner's own leak lines never echo the planted values:
        var lines = run.Out.Split('\n');
        var checkedLeakLines = 0;
        for (var i = 0; i + 1 < lines.Length; i++)
        {
            if (!lines[i].Contains("secret material appears", StringComparison.Ordinal))
            {
                continue;
            }

            checkedLeakLines++;
            Assert.DoesNotContain(LoadedPrivateKey, lines[i], StringComparison.Ordinal);
            Assert.DoesNotContain(LoadedApiKey, lines[i], StringComparison.Ordinal);
            Assert.DoesNotContain(LoadedPrivateKey, lines[i + 1], StringComparison.Ordinal);
            Assert.DoesNotContain(LoadedApiKey, lines[i + 1], StringComparison.Ordinal);
        }

        Assert.Equal(1, checkedLeakLines);
        Assert.DoesNotContain(LoadedApiKey, run.Err, StringComparison.Ordinal);
        // both values really were in the log the scan read — the FAIL came from
        // finding them (the private key only after folding), not from stub text:
        _runnerLog = ExtractRunnerLogPath(run.Out);
        var flatLog = File.ReadAllText(_runnerLog).Replace("\n", string.Empty, StringComparison.Ordinal);
        Assert.Contains(LoadedPrivateKey, flatLog, StringComparison.Ordinal);
        Assert.Contains(LoadedApiKey, flatLog, StringComparison.Ordinal);
        // the wrapped form alone was in the log (folding, not luck, made it match):
        Assert.Contains(WrappedPrivateKey, File.ReadAllText(_runnerLog), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("")]
    [InlineData("10s")]
    [InlineData("abc")]
    [InlineData("0")]
    [InlineData("007")]
    [InlineData("99999999999999999999")]
    public void SecretWaitBudget_NotAPositiveWholeNumber_RefusedBeforeAnythingIsCreated(string budget)
    {
        // review LOW-2 (2026-11-22): "10s" made the wait's numeric test error out
        // and the loop never end while a run-created app registration was held
        var run = Run(new() { ["CREDPROX_M46_SECRET_WAIT_SECONDS"] = budget });
        Assert.Equal(2, run.Exit);
        Assert.Contains("REFUSED: CREDPROX_M46_SECRET_WAIT_SECONDS must be a positive whole number of seconds, at most 6 digits",
            run.Out, StringComparison.Ordinal);
        Assert.DoesNotContain("live-graph-app.sh create", run.Out, StringComparison.Ordinal);
    }

    [Fact]
    public void RoleWaitBudget_ExportedEmpty_RefusedBeforeAnythingIsCreated()
    {
        // Every verb parses BOTH wait budgets before any vendor dispatches, so
        // the graph runner reaches the role-budget guard without an
        // azureopenai run. An operator who exported the name with an EMPTY
        // value used to silently get the 300s default; exported-empty is the
        // refused shape now, unset still defaults.
        var run = Run(new() { ["CREDPROX_M52_AOAI_ROLE_WAIT_SECONDS"] = string.Empty });
        Assert.Equal(2, run.Exit);
        Assert.Contains("REFUSED: CREDPROX_M52_AOAI_ROLE_WAIT_SECONDS must be a positive whole number of seconds, at most 6 digits",
            run.Out, StringComparison.Ordinal);
        Assert.DoesNotContain("live-graph-app.sh create", run.Out, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("")]
    [InlineData("10s")]
    [InlineData("abc")]
    [InlineData("0")]
    [InlineData("007")]
    [InlineData("99999999999999999999")]
    public void M46RoleWaitBudget_NotAPositiveWholeNumber_RefusedBeforeAnythingIsCreated(string budget)
    {
        // The third wait budget, guarded last: wait_roles_in_token used the `:-`
        // expansion with NO shape guard anywhere, so an exported-empty value
        // silently took the 300 default and a non-numeric one reached the
        // numeric wait comparison. The top guard and the `-` expansion at the
        // wait land together: refused by name before any dispatch, unset still
        // defaults (same LOW-2 hang shape as the sibling budgets).
        var run = Run(new() { ["CREDPROX_M46_ROLE_WAIT_SECONDS"] = budget });
        Assert.Equal(2, run.Exit);
        Assert.Contains("REFUSED: CREDPROX_M46_ROLE_WAIT_SECONDS must be a positive whole number of seconds, at most 6 digits",
            run.Out, StringComparison.Ordinal);
        Assert.DoesNotContain("live-graph-app.sh create", run.Out, StringComparison.Ordinal);
    }

    private sealed record RunnerRun(int Exit, string Out, string Err);

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
        psi.Environment["PATH"] = _stubBin + ":/usr/bin:/bin";
        psi.Environment["HOME"] = _home;
        psi.Environment["CREDPROX_M46_SCRATCH"] = _scratch;
        psi.Environment["STUB_AZ_LOG"] = azLogPath;
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
        if (File.Exists(azLogPath))
        {
            File.Delete(azLogPath);
        }

        return new RunnerRun(process.ExitCode, stdout.Result, stderr.Result);
    }

    internal static string MakeUnionHome(string tenantId)
    {
        var home = Path.Combine(Path.GetTempPath(), $"credprox-m46-gate-home-{Guid.NewGuid():N}");
        var confDir = Path.Combine(home, ".config", "credprox-live");
        Directory.CreateDirectory(confDir);
        var envFile = Path.Combine(confDir, "live.env");
        File.WriteAllText(
            envFile,
            $"TENANT_ID={tenantId}\n"
            + "APP_ID=11111111-0000-0000-0000-000000000001\n"
            + "INSTALLATION_ID=999001\n"
            + "PRIVATE_KEY_BASE64=RkFLRVBBVkVBTE5PQVJFQUxLRVk=\n"
            + "ANTHROPIC_API_KEY=loaded-canary-key-0123456789abcdefg\n");
        File.SetUnixFileMode(envFile, UnixFileMode.UserRead | UnixFileMode.UserWrite); // exactly 600
        return home;
    }

    internal static string ExtractRunnerLogPath(string stdout)
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

// The owner decided (2026-11-22): a TENANT_ID in the run log is NOT secret material
// — it names a tenant, not a credential. The scan must WARN by kind, never print
// the value, and the run must still PASS. This cell plants the tenant id through
// the destroy door on an otherwise happy run: WARN present, PASS intact.
[Trait("Layer", "Offline")]
public sealed class RunnerTenantWarnTests : ExecutesLiveRunner, IDisposable
{
    // distinct so the WARN provably came from the plant, not from canned stub noise:
    private const string TenantId = "5f1e2d3c-4b5a-4678-9a0b-cdef01234567";

    private readonly string _stubBin;
    private readonly string _home;
    private readonly string _scratch;
    private readonly string _countFile;
    private readonly string _runner;
    private string? _runnerLog;

    public RunnerTenantWarnTests()
    {
        _stubBin = Path.Combine(Path.GetTempPath(), $"credprox-m46-gatestub-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_stubBin);
        SecretPropagationStubs.WriteExec(_stubBin, "az", GraphAppScriptTests.StubAz);
        SecretPropagationStubs.WriteExec(_stubBin, "dotnet", SecretPropagationStubs.StubDotnet);
        SecretPropagationStubs.WriteExec(_stubBin, "curl", SecretPropagationStubs.StubCurl);
        _home = RunnerLoadedSecretScanTests.MakeUnionHome(TenantId);
        _scratch = Path.Combine(Path.GetTempPath(), $"credprox-m46-gate-scratch-{Guid.NewGuid():N}");
        _countFile = Path.Combine(_stubBin, "curl-count");
        _runner = SecretPropagationStubs.LocateRunner();
    }

    [Fact]
    public void TenantIdInLog_WarnsByKind_StillPasses()
    {
        var run = Run();
        Assert.True(run.Exit == 0, $"a tenant id must not fail the run: exit={run.Exit} out={run.Out} err={run.Err}");
        Assert.Contains("PASS graph", run.Out, StringComparison.Ordinal);
        var warnLine = run.Out.Split('\n').Where(l => l.Contains("tenant-id-in-log", StringComparison.Ordinal)).ToList();
        Assert.Single(warnLine);
        Assert.StartsWith("WARN:", warnLine[0], StringComparison.Ordinal);
        // the WARN names the kind, never the value:
        Assert.DoesNotContain(TenantId, warnLine[0], StringComparison.Ordinal);
        // and no FAIL of any kind rode along:
        Assert.DoesNotContain("FAIL: secret material", run.Out, StringComparison.Ordinal);
        Assert.DoesNotContain("loaded-tenant-id", run.Out, StringComparison.Ordinal);
        // WARN lands before the PASS tail: the scan runs, warns, and lets the run pass:
        Assert.True(
            run.Out.IndexOf("tenant-id-in-log", StringComparison.Ordinal)
            < run.Out.IndexOf("PASS graph", StringComparison.Ordinal),
            "the WARN must precede the PASS line");
        // the plant really reached the scanned log:
        _runnerLog = RunnerLoadedSecretScanTests.ExtractRunnerLogPath(run.Out);
        Assert.Contains(TenantId, File.ReadAllText(_runnerLog), StringComparison.Ordinal);
    }

    private sealed record RunnerRun(int Exit, string Out, string Err);

    private RunnerRun Run()
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
        psi.Environment["PATH"] = _stubBin + ":/usr/bin:/bin";
        psi.Environment["HOME"] = _home;
        psi.Environment["CREDPROX_M46_SCRATCH"] = _scratch;
        psi.Environment["STUB_AZ_LOG"] = azLogPath;
        psi.Environment["STUB_SECRET"] = "canary-gate-secret-0123456789";
        psi.Environment["STUB_APP_ID"] = "stub-app-id";
        psi.Environment["STUB_AZ_SIGNED_IN"] = "1";
        psi.Environment["STUB_CRED"] = "1";
        psi.Environment["STUB_APP_LEFT"] = "0";
        psi.Environment["STUB_SP_LEFT"] = "0";
        psi.Environment["STUB_CREATE_FAIL"] = "0";
        psi.Environment["STUB_PLANT"] = string.Empty;
        // the destroy door plants the tenant id into the post-test destroy output:
        psi.Environment["STUB_DESTROY_PLANT"] = TenantId;
        psi.Environment["STUB_EXISTING_IDS"] = "stub-app-id";
        psi.Environment["STUB_CURL_CODES"] = "200";
        psi.Environment["STUB_CURL_COUNT"] = _countFile;

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

// Vendor isolation, pinned at the child that does the real work: the fake dotnet
// dumps only the NAMES of the variables it was given (never values — a value dump
// here would itself be the leak class this suite exists to stop). The central file
// holds five vendors' variables; each vendor's child must see exactly its own.
[Trait("Layer", "Offline")]
public sealed class RunnerExportIsolationTests : ExecutesLiveRunner, IDisposable
{
    private static readonly string[] AllNames =
    [
        "TENANT_ID", "APP_ID", "INSTALLATION_ID", "PRIVATE_KEY_BASE64", "ANTHROPIC_API_KEY",
    ];

    // the fake dotnet: names only, then the OBSERVED line so the run still passes:
    private const string StubDotnetNames = """
        #!/usr/bin/env bash
        if [ -n "${STUB_ENV_DUMP:-}" ]; then env | cut -d= -f1 > "$STUB_ENV_DUMP"; fi
        if [ -n "${STUB_AZ_LOG:-}" ]; then printf 'dotnet %s\n' "$*" >> "$STUB_AZ_LOG"; fi
        echo "OBSERVED export-isolation-stub"
        exit 0
        """;

    private readonly string _stubBin;
    private readonly string _home;
    private readonly string _scratch;
    private readonly string _countFile;
    private readonly string _dumpFile;
    private readonly string _runner;

    public RunnerExportIsolationTests()
    {
        _stubBin = Path.Combine(Path.GetTempPath(), $"credprox-m46-gatestub-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_stubBin);
        SecretPropagationStubs.WriteExec(_stubBin, "az", GraphAppScriptTests.StubAz);
        SecretPropagationStubs.WriteExec(_stubBin, "dotnet", StubDotnetNames);
        SecretPropagationStubs.WriteExec(_stubBin, "curl", SecretPropagationStubs.StubCurl);
        _home = RunnerLoadedSecretScanTests.MakeUnionHome("00000000-0000-0000-0000-000000000000");
        _scratch = Path.Combine(Path.GetTempPath(), $"credprox-m46-gate-scratch-{Guid.NewGuid():N}");
        _countFile = Path.Combine(_stubBin, "curl-count");
        _dumpFile = Path.Combine(Path.GetTempPath(), $"credprox-m46-envdump-{Guid.NewGuid():N}.txt");
        _runner = SecretPropagationStubs.LocateRunner();
    }

    [Fact]
    public void ExportIsolationChild_SeesExactlyItsOwnThreeVariables()
    {
        var run = Run("githubapp");
        Assert.True(run.Exit == 0, $"the githubapp leg must pass against the stub: exit={run.Exit} out={run.Out} err={run.Err}");
        var seen = ReadDump();
        Assert.Contains("APP_ID", seen);
        Assert.Contains("INSTALLATION_ID", seen);
        Assert.Contains("PRIVATE_KEY_BASE64", seen);
        Assert.DoesNotContain("TENANT_ID", seen);
        Assert.DoesNotContain("ANTHROPIC_API_KEY", seen);
    }

    [Fact]
    public void GraphChild_SeesExactlyItsOwnOneVariable()
    {
        var run = Run("graph");
        Assert.True(run.Exit == 0, $"the graph leg must pass against the stub: exit={run.Exit} out={run.Out} err={run.Err}");
        var seen = ReadDump();
        Assert.Contains("TENANT_ID", seen);
        Assert.DoesNotContain("APP_ID", seen);
        Assert.DoesNotContain("INSTALLATION_ID", seen);
        Assert.DoesNotContain("PRIVATE_KEY_BASE64", seen);
        Assert.DoesNotContain("ANTHROPIC_API_KEY", seen);
    }

    private HashSet<string> ReadDump()
    {
        Assert.True(File.Exists(_dumpFile), "the fake dotnet never ran (no env-name dump)");
        return File.ReadAllLines(_dumpFile).ToHashSet(StringComparer.Ordinal);
    }

    private sealed record RunnerRun(int Exit, string Out, string Err);

    private RunnerRun Run(string vendor)
    {
        var azLogPath = Path.Combine(Path.GetTempPath(), $"credprox-m46-azlog-{Guid.NewGuid():N}.log");
        if (File.Exists(_dumpFile))
        {
            File.Delete(_dumpFile);
        }

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
        psi.Environment["STUB_AZ_LOG"] = azLogPath;
        psi.Environment["STUB_ENV_DUMP"] = _dumpFile;
        psi.Environment["STUB_SECRET"] = "canary-gate-secret-0123456789";
        psi.Environment["STUB_APP_ID"] = "stub-app-id";
        psi.Environment["STUB_AZ_SIGNED_IN"] = "1";
        psi.Environment["STUB_CRED"] = "1";
        psi.Environment["STUB_APP_LEFT"] = "0";
        psi.Environment["STUB_SP_LEFT"] = "0";
        psi.Environment["STUB_CREATE_FAIL"] = "0";
        psi.Environment["STUB_PLANT"] = string.Empty;
        psi.Environment["STUB_DESTROY_PLANT"] = string.Empty;
        psi.Environment["STUB_EXISTING_IDS"] = "stub-app-id";
        psi.Environment["STUB_CURL_CODES"] = "200";
        psi.Environment["STUB_CURL_COUNT"] = _countFile;
        // hermetic against the harness env itself: no vendor variable may ride in
        // from the test process and fake an isolation break:
        foreach (var name in AllNames)
        {
            psi.Environment.Remove(name);
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
            if (File.Exists(_dumpFile))
            {
                File.Delete(_dumpFile);
            }
        }
        catch (IOException)
        {
            // scratch file
        }
    }
}

// The stale per-vendor NOTE must reach a run that never starts: the old order put
// it below the missing-file SKIP, so the exact situation the NOTE exists for —
// someone left a per-vendor file behind and has no central file yet — printed the
// SKIP and stayed silent about the dead file. The loop stats files and reads
// nothing, so it now runs above every gate.
[Trait("Layer", "Offline")]
public sealed class RunnerStaleVendorNoteTests : ExecutesLiveRunner, IDisposable
{
    // never read by anything, so it must never appear in any output:
    private const string DeadFileCanary = "dead-vendor-file-canary-0123456789abcdefg";

    private readonly string _home;
    private readonly string _runner;

    public RunnerStaleVendorNoteTests()
    {
        _home = Path.Combine(Path.GetTempPath(), $"credprox-m46-stale-home-{Guid.NewGuid():N}");
        var confDir = Path.Combine(_home, ".config", "credprox-live");
        Directory.CreateDirectory(confDir);
        // ONLY a stale per-vendor file — the central live.env is absent:
        File.WriteAllText(
            Path.Combine(confDir, "githubapp.env"),
            $"PRIVATE_KEY_BASE64={DeadFileCanary}\n");
        _runner = SecretPropagationStubs.LocateRunner();
    }

    [Fact]
    public void StaleVendorFile_NamedBeforeTheSkip_AndNeverRead()
    {
        var run = SyncRun();
        Assert.Equal(2, run.Exit);
        Assert.Contains("githubapp.env exists but is IGNORED", run.Out, StringComparison.Ordinal);
        Assert.Contains("live.env does not exist", run.Out, StringComparison.Ordinal);
        // the NOTE must PRECEDE the SKIP — after it, it could never print:
        Assert.True(
            run.Out.IndexOf("exists but is IGNORED", StringComparison.Ordinal)
            < run.Out.IndexOf("does not exist", StringComparison.Ordinal),
            "the stale-file NOTE must print before the missing-file SKIP");
        // naming the file must not mean reading it:
        Assert.DoesNotContain(DeadFileCanary, run.Out, StringComparison.Ordinal);
        Assert.DoesNotContain(DeadFileCanary, run.Err, StringComparison.Ordinal);
    }

    private sealed record SyncRunResult(int Exit, string Out, string Err);

    private SyncRunResult SyncRun()
    {
        var psi = new ProcessStartInfo
        {
            FileName = "/bin/bash",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add(_runner);
        psi.ArgumentList.Add("githubapp");
        psi.Environment["PATH"] = "/usr/bin:/bin";
        psi.Environment["HOME"] = _home;

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("live-run.sh did not start");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        Assert.True(process.WaitForExit(60_000), "live-run.sh did not exit within 60 s");
        return new SyncRunResult(process.ExitCode, stdout.Result, stderr.Result);
    }

    public void Dispose()
    {
        SecretPropagationStubs.TryDelete(_home);
    }
}

// Post-release item 3 (2026-11-25): the PASS tail read only the FIRST "OBSERVED "
// line of the run log (grep -m1), so when a vendor's live cells each write their
// own line the run passed while the PASS record silently carried only the first
// cell's result. The tail now aggregates: every OBSERVED payload joins into the
// one PASS line, and a log with neither an OBSERVED nor a skip line still FAILs.
[Trait("Layer", "Offline")]
public sealed class RunnerObservedTailTests : ExecutesLiveRunner, IDisposable
{
    // one fake dotnet, two shapes: STUB_OBSERVE=2 prints one OBSERVED line per
    // "cell"; STUB_OBSERVE=0 prints neither an OBSERVED nor a skip line:
    private const string StubDotnetTails = """
        #!/usr/bin/env bash
        if [ -n "${STUB_AZ_LOG:-}" ]; then printf 'dotnet %s\n' "$*" >> "$STUB_AZ_LOG"; fi
        if [ "${STUB_OBSERVE:-2}" = "0" ]; then exit 0; fi
        echo "OBSERVED a2_first=alpha"
        echo "OBSERVED a2_second=beta"
        exit 0
        """;

    private readonly string _stubBin;
    private readonly string _home;
    private readonly string _scratch;
    private readonly string _countFile;
    private readonly string _runner;
    // PASS runs keep their log as evidence now (item 4), so this class must clean up:
    private readonly List<string> _runnerLogs = [];

    public RunnerObservedTailTests()
    {
        _stubBin = Path.Combine(Path.GetTempPath(), $"credprox-m46-gatestub-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_stubBin);
        SecretPropagationStubs.WriteExec(_stubBin, "az", GraphAppScriptTests.StubAz);
        SecretPropagationStubs.WriteExec(_stubBin, "dotnet", StubDotnetTails);
        SecretPropagationStubs.WriteExec(_stubBin, "curl", SecretPropagationStubs.StubCurl);
        _home = RunnerLoadedSecretScanTests.MakeUnionHome("00000000-0000-0000-0000-000000000000");
        _scratch = Path.Combine(Path.GetTempPath(), $"credprox-m46-gate-scratch-{Guid.NewGuid():N}");
        _countFile = Path.Combine(_stubBin, "curl-count");
        _runner = SecretPropagationStubs.LocateRunner();
    }

    [Fact]
    public void PassTail_CarriesEveryObservedLineNotJustTheFirst()
    {
        var run = Run("2");
        Assert.True(run.Exit == 0, $"the two-line leg must pass: exit={run.Exit} out={run.Out} err={run.Err}");
        var passLine = run.Out.Split('\n')
            .Where(l => l.StartsWith("PASS graph:", StringComparison.Ordinal))
            .ToList();
        Assert.Single(passLine);
        Assert.Contains("a2_first=alpha", passLine[0], StringComparison.Ordinal);
        // the bug this cell exists for: the second cell's result must not vanish:
        Assert.Contains("a2_second=beta", passLine[0], StringComparison.Ordinal);
    }

    [Fact]
    public void NoObservedAndNoSkipLine_FailsNeverSilentPass()
    {
        var run = Run("0");
        Assert.Equal(1, run.Exit);
        Assert.Contains("FAIL: the live cell neither ran nor skipped cleanly", run.Out, StringComparison.Ordinal);
        Assert.DoesNotContain("PASS graph", run.Out, StringComparison.Ordinal);
    }

    private sealed record RunnerRun(int Exit, string Out, string Err);

    private RunnerRun Run(string observe)
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
        psi.Environment["PATH"] = _stubBin + ":/usr/bin:/bin";
        psi.Environment["HOME"] = _home;
        psi.Environment["CREDPROX_M46_SCRATCH"] = _scratch;
        psi.Environment["STUB_AZ_LOG"] = azLogPath;
        psi.Environment["STUB_OBSERVE"] = observe;
        psi.Environment["STUB_SECRET"] = "canary-gate-secret-0123456789";
        psi.Environment["STUB_APP_ID"] = "stub-app-id";
        psi.Environment["STUB_AZ_SIGNED_IN"] = "1";
        psi.Environment["STUB_CRED"] = "1";
        psi.Environment["STUB_APP_LEFT"] = "0";
        psi.Environment["STUB_SP_LEFT"] = "0";
        psi.Environment["STUB_CREATE_FAIL"] = "0";
        psi.Environment["STUB_PLANT"] = string.Empty;
        psi.Environment["STUB_DESTROY_PLANT"] = string.Empty;
        psi.Environment["STUB_EXISTING_IDS"] = "stub-app-id";
        psi.Environment["STUB_CURL_CODES"] = "200";
        psi.Environment["STUB_CURL_COUNT"] = _countFile;

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("live-run.sh did not start");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        Assert.True(process.WaitForExit(120_000), "live-run.sh did not exit within 120 s");
        if (File.Exists(azLogPath))
        {
            File.Delete(azLogPath);
        }

        foreach (var line in stdout.Result.Split('\n'))
        {
            if (line.StartsWith("log: ", StringComparison.Ordinal))
            {
                _runnerLogs.Add(line[5..].Trim());
                break;
            }
        }

        return new RunnerRun(process.ExitCode, stdout.Result, stderr.Result);
    }

    public void Dispose()
    {
        foreach (var path in _runnerLogs)
        {
            try
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
            catch (IOException)
            {
                // scratch tree
            }
        }

        foreach (var dir in new[] { _stubBin, _home, _scratch })
        {
            SecretPropagationStubs.TryDelete(dir);
        }
    }
}

// Post-release item 4 (2026-11-25): run logs accumulated forever - every run
// printed its path and removed nothing (961 orphans observed in /tmp). The log
// name now carries the vendor, and each run sweeps its OWN pattern, plain files
// only, older than 24h. Logs stay kept as evidence - the leak-scan witnesses
// read the log back after a PASS run - so hygiene is bounded growth, not deletion.
[Trait("Layer", "Offline")]
public sealed class RunnerRunLogHygieneTests : ExecutesLiveRunner, IDisposable
{
    private readonly string _stubBin;
    private readonly string _home;
    private readonly string _scratch;
    private readonly string _countFile;
    private readonly string _runner;
    private readonly List<string> _planted = [];

    public RunnerRunLogHygieneTests()
    {
        _stubBin = Path.Combine(Path.GetTempPath(), $"credprox-m46-gatestub-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_stubBin);
        SecretPropagationStubs.WriteExec(_stubBin, "az", GraphAppScriptTests.StubAz);
        SecretPropagationStubs.WriteExec(_stubBin, "dotnet", SecretPropagationStubs.StubDotnet);
        SecretPropagationStubs.WriteExec(_stubBin, "curl", SecretPropagationStubs.StubCurl);
        _home = RunnerLoadedSecretScanTests.MakeUnionHome("00000000-0000-0000-0000-000000000000");
        _scratch = Path.Combine(Path.GetTempPath(), $"credprox-m46-gate-scratch-{Guid.NewGuid():N}");
        _countFile = Path.Combine(_stubBin, "curl-count");
        _runner = SecretPropagationStubs.LocateRunner();
    }

    [Fact]
    public void RunLog_NamedByVendor_KeptAfterPass()
    {
        var run = Run();
        Assert.True(run.Exit == 0, $"the stub leg must pass: exit={run.Exit} out={run.Out} err={run.Err}");
        var path = RunnerLoadedSecretScanTests.ExtractRunnerLogPath(run.Out);
        _planted.Add(path);
        Assert.Contains("-graph.", Path.GetFileName(path), StringComparison.Ordinal);
        // evidence stays: the PASS tail must not eat the file the witnesses read back
        Assert.True(File.Exists(path), $"the PASS run's log must remain for inspection: {path}");
    }

    [Fact]
    public void StaleOwnPatternLog_Swept_WhileFreshLogsStay()
    {
        var tmp = Path.GetTempPath();
        // the sweep must cover BOTH name shapes: the historical dotted one (the
        // 961-file pile) and the vendor-dashed one this run itself creates:
        var staleDotted = Path.Combine(tmp, $"credprox-live-run.{Guid.NewGuid():N}.log");
        var staleDashed = Path.Combine(tmp, $"credprox-live-run-sweep.{Guid.NewGuid():N}.log");
        var fresh = Path.Combine(tmp, $"credprox-live-run-sweep.{Guid.NewGuid():N}.log");
        File.WriteAllText(staleDotted, "stale orphan\n");
        File.WriteAllText(staleDashed, "stale orphan\n");
        File.WriteAllText(fresh, "fresh log\n");
        File.SetLastWriteTimeUtc(staleDotted, DateTime.UtcNow.AddHours(-26));
        File.SetLastWriteTimeUtc(staleDashed, DateTime.UtcNow.AddHours(-26));
        _planted.Add(staleDotted);
        _planted.Add(staleDashed);
        _planted.Add(fresh);
        try
        {
            var run = Run();
            Assert.True(run.Exit == 0, $"the stub leg must pass: exit={run.Exit} out={run.Out} err={run.Err}");
            _planted.Add(RunnerLoadedSecretScanTests.ExtractRunnerLogPath(run.Out));
            Assert.False(File.Exists(staleDotted), "a stale dotted-shape run log must be swept");
            Assert.False(File.Exists(staleDashed), "a stale vendor-dashed run log must be swept");
            Assert.True(File.Exists(fresh), "the sweep must not touch logs younger than 24h");
        }
        finally
        {
            // a sweep removes the stale files mid-test; never fail on the cleanup
            if (File.Exists(fresh))
            {
                File.Delete(fresh);
            }
        }
    }

    private sealed record RunnerRun(int Exit, string Out, string Err);

    private RunnerRun Run()
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
        psi.Environment["PATH"] = _stubBin + ":/usr/bin:/bin";
        psi.Environment["HOME"] = _home;
        psi.Environment["CREDPROX_M46_SCRATCH"] = _scratch;
        psi.Environment["STUB_AZ_LOG"] = azLogPath;
        psi.Environment["STUB_SECRET"] = "canary-gate-secret-0123456789";
        psi.Environment["STUB_APP_ID"] = "stub-app-id";
        psi.Environment["STUB_AZ_SIGNED_IN"] = "1";
        psi.Environment["STUB_CRED"] = "1";
        psi.Environment["STUB_APP_LEFT"] = "0";
        psi.Environment["STUB_SP_LEFT"] = "0";
        psi.Environment["STUB_CREATE_FAIL"] = "0";
        psi.Environment["STUB_PLANT"] = string.Empty;
        psi.Environment["STUB_DESTROY_PLANT"] = string.Empty;
        psi.Environment["STUB_EXISTING_IDS"] = "stub-app-id";
        psi.Environment["STUB_CURL_CODES"] = "200";
        psi.Environment["STUB_CURL_COUNT"] = _countFile;

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
        foreach (var path in _planted)
        {
            try
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
            catch (IOException)
            {
                // scratch files
            }
        }

        foreach (var dir in new[] { _stubBin, _home, _scratch })
        {
            SecretPropagationStubs.TryDelete(dir);
        }
    }
}
