using System.Diagnostics;
using Xunit;

namespace CredProx.LiveTests;

// Witness for the foundrylocal billable passthrough in scripts/live-run.sh:
// the cloud live cell needs CREDPROX_M54_BILLABLE=1 AND ANTHROPIC_API_KEY in the
// test process, and the runner gets both ONLY from the central env file and ONLY
// behind the flag. These cells exec the REAL live-run.sh for the foundrylocal leg
// under canned az, a curl that answers the model preflight (catalog, one chat
// with "choices", the Entra waits) and a dotnet that records the two opt-in
// names it was handed - into a side file, never its stdout, because the runner's
// own leak scan would rightly fail the leg on a key echoed into the log. No az,
// no network, no key beyond an obvious canary; the class name matches NONE of
// live-run.sh's test filters, so a runner leg can never exec these cells.
[Trait("Layer", "Offline")]
public sealed class RunnerBillablePassthroughWitnessTests : ExecutesLiveRunner, IDisposable
{
    // matches none of the runner's leak shapes (no sk-ant-, gh_*, eyJ forms) and
    // is not a secret anywhere: it may only ever appear in the capture file.
    private const string KeyCanary = "canary-m54-billable-key-0123456789abcdef";
    private const string TenantLine = "TENANT_ID=00000000-0000-0000-0000-000000000000";

    // dotnet stub: records the two opt-in names the runner exported into the
    // test process into $STUB_DOTNET_ENV (values NEVER on stdout - the runner
    // tees test stdout into the scanned log), then reports like a passing leg.
    private const string StubDotnetCapture = """
        #!/usr/bin/env bash
        if [ -n "${STUB_AZ_LOG:-}" ]; then printf 'dotnet %s\n' "$*" >> "$STUB_AZ_LOG"; fi
        if [ -n "${STUB_DOTNET_ENV:-}" ]; then
            printf 'M54_BILLABLE=%s\nANTHROPIC=%s\n' "${CREDPROX_M54_BILLABLE:-}" "${ANTHROPIC_API_KEY:-}" > "$STUB_DOTNET_ENV"
        fi
        echo "OBSERVED billable-passthrough-stub"
        exit 0
        """;

    // curl stub: the shared secret-propagation stub's shapes (scripted codes for
    // -o /dev/null probes, canned usable-token body for the Entra waits) PLUS a
    // chat branch, because the foundrylocal model preflight must see 200 and a
    // body carrying "choices" on /v1/chat/completions before the leg is armed.
    private const string StubCurlModelGate = """
        #!/usr/bin/env bash
        if [ -n "${STUB_AZ_LOG:-}" ]; then printf 'curl %s\n' "$*" >> "$STUB_AZ_LOG"; fi
        cat >/dev/null
        case "$*" in
            *"/v1/chat/completions"*)
                printf '%s\n%s' '{"choices":[{"message":{"content":"pong"}}]}' '200'
                ;;
            *-o\ /dev/null*)
                n=0
                if [ -n "${STUB_CURL_COUNT:-}" ] && [ -f "$STUB_CURL_COUNT" ]; then n="$(cat "$STUB_CURL_COUNT")"; fi
                n=$((n+1)); printf '%s' "$n" > "$STUB_CURL_COUNT"
                codes=(${STUB_CURL_CODES:-200})
                i=$((n-1)); if [ "$i" -ge "${#codes[@]}" ]; then i=$(( ${#codes[@]} - 1 )); fi
                printf '%s' "${codes[$i]}"
                ;;
            *)
                printf '%s' '{"token_type":"Bearer","expires_in":3599,"access_token":"e30.eyJyb2xlcyI6WyJkb2NzLXJlYWQiLCJtb2RlbC1jYWxsIl19.canary-not-a-secret"}'
                ;;
        esac
        """;

    private readonly string _stubBin;
    private readonly string _scratch;
    private readonly string _countFile;
    private readonly string _runner;
    private string? _home;
    private string? _runnerLog;

    public RunnerBillablePassthroughWitnessTests()
    {
        _stubBin = Path.Combine(Path.GetTempPath(), $"credprox-m54-bpstub-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_stubBin);
        SecretPropagationStubs.WriteExec(_stubBin, "az", AgentTokensScriptTests.StubAz);
        SecretPropagationStubs.WriteExec(_stubBin, "dotnet", StubDotnetCapture);
        SecretPropagationStubs.WriteExec(_stubBin, "curl", StubCurlModelGate);
        _scratch = Path.Combine(Path.GetTempPath(), $"credprox-m54-bp-scratch-{Guid.NewGuid():N}");
        _countFile = Path.Combine(_stubBin, "curl-count");
        _runner = SecretPropagationStubs.LocateRunner();
    }

    [Fact]
    public void GoAheadAndKey_ReachTheTestProcess_NeverAnyLog()
    {
        var run = Run(new[] { TenantLine, "CREDPROX_M54_BILLABLE=1", $"ANTHROPIC_API_KEY={KeyCanary}" });
        Assert.True(run.Exit == 0, $"the armed leg must pass: exit={run.Exit} out={run.Out} err={run.Err}");
        Assert.Contains("OBSERVED billable-passthrough-stub", run.Out, StringComparison.Ordinal);
        Assert.Contains("foundrylocal destroy: read-back clean", run.Out, StringComparison.Ordinal);
        // a leg that exited 0 must have opened its log - without this the
        // absence checks below could pass vacuously:
        Assert.NotEmpty(run.Log);
        // the two deletes Dispose performs can only be witnessed if the paths
        // they act on are visible here: the parse must have found the runner's
        // own log (a line-start match dies on the glued curl -w tail and would
        // leave this empty), and the capture must live inside the stub dir the
        // directory sweep removes (a top-level /tmp file would sweep nothing):
        Assert.NotEmpty(run.RunnerLog);
        Assert.StartsWith(_stubBin, run.Capture, StringComparison.Ordinal);
        // the capture can carry a key value, so it must not sit world-readable
        // behind a process umask - the same exact 600 the env file gets:
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(run.Capture));
        var captured = Capture(run.Capture);
        Assert.Equal("1", captured["M54_BILLABLE"]);
        Assert.Equal(KeyCanary, captured["ANTHROPIC"]);
        // the key reached the TEST PROCESS only: not stdout, not stderr, not the
        // runner's own scanned log file (its leak scan already proves the log,
        // this proves the runner's terminal output too):
        Assert.DoesNotContain(KeyCanary, run.Out + run.Err + run.Log, StringComparison.Ordinal);
    }

    [Fact]
    public void KeyWithoutGoAhead_StaysCompletelyInsideTheRunner()
    {
        // the stray-key shape: ANTHROPIC_API_KEY present in the central file but
        // no flag - neither name may reach the test process, so the billable
        // cell cannot be armed without the owner's go-ahead;
        var run = Run(new[] { TenantLine, $"ANTHROPIC_API_KEY={KeyCanary}" });
        Assert.True(run.Exit == 0, $"the unarmed leg must still pass: exit={run.Exit} out={run.Out} err={run.Err}");
        Assert.Contains("OBSERVED billable-passthrough-stub", run.Out, StringComparison.Ordinal);
        Assert.NotEmpty(run.Log);
        var captured = Capture(run.Capture);
        Assert.Equal(string.Empty, captured["M54_BILLABLE"]);
        Assert.Equal(string.Empty, captured["ANTHROPIC"]);
        Assert.DoesNotContain(KeyCanary, run.Out + run.Err + run.Log, StringComparison.Ordinal);
    }

    [Fact]
    public void GoAheadWithoutKey_CarriesTheFlagAlone()
    {
        // the flag alone arms nothing billable (the cell still skips, naming the
        // missing key - the gate witness covers that skip); the runner's job is
        // just to carry what the central file set, flag without key included.
        var run = Run(new[] { TenantLine, "CREDPROX_M54_BILLABLE=1" });
        Assert.True(run.Exit == 0, $"the flag-only leg must pass: exit={run.Exit} out={run.Out} err={run.Err}");
        Assert.Contains("OBSERVED billable-passthrough-stub", run.Out, StringComparison.Ordinal);
        var captured = Capture(run.Capture);
        Assert.Equal("1", captured["M54_BILLABLE"]);
        Assert.Equal(string.Empty, captured["ANTHROPIC"]);
    }

    private static Dictionary<string, string> Capture(string captureFile)
    {
        var lines = File.ReadAllLines(captureFile);
        Assert.Equal(2, lines.Length);
        var map = new Dictionary<string, string>();
        foreach (var line in lines)
        {
            var split = line.IndexOf('=', StringComparison.Ordinal);
            Assert.True(split > 0, $"capture line without a name: {line}");
            map[line[..split]] = line[(split + 1)..];
        }

        return map;
    }

    // RunnerLog is the runner's OWN log PATH as the parse found it (empty when
    // the parse finds nothing) - the cells assert on it so a dead parse burns:
    private sealed record RunnerRun(int Exit, string Out, string Err, string Log, string RunnerLog, string Capture);

    private RunnerRun Run(string[] envFileLines)
    {
        _home = Path.Combine(Path.GetTempPath(), $"credprox-m54-bp-home-{Guid.NewGuid():N}");
        var confDir = Path.Combine(_home, ".config", "credprox-live");
        Directory.CreateDirectory(confDir);
        var envFile = Path.Combine(confDir, "live.env");
        File.WriteAllText(envFile, string.Join('\n', envFileLines) + "\n");
        File.SetUnixFileMode(envFile, UnixFileMode.UserRead | UnixFileMode.UserWrite); // exactly 600

        var azLogPath = Path.Combine(Path.GetTempPath(), $"credprox-m54-bp-azlog-{Guid.NewGuid():N}.log");
        // inside the stub dir, so the directory cleanup in Dispose sweeps it too —
        // the values never leave a loose file in the shared temp dir:
        var capturePath = Path.Combine(_stubBin, $"dotnetenv-{Guid.NewGuid():N}.txt");
        var psi = new ProcessStartInfo
        {
            FileName = "/bin/bash",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add(_runner);
        psi.ArgumentList.Add("foundrylocal");
        // the stub dir LEADS PATH: it shadows the machine's az, any real dotnet
        // and the real curl (nothing may reach a tenant, the network or a model);
        psi.Environment["PATH"] = _stubBin + ":/usr/bin:/bin";
        psi.Environment["HOME"] = _home;
        psi.Environment["CREDPROX_M46_SCRATCH"] = _scratch;
        psi.Environment["STUB_AZ_LOG"] = azLogPath;
        psi.Environment["STUB_DOTNET_ENV"] = capturePath;
        psi.Environment["STUB_CURL_COUNT"] = _countFile;
        // hermetic pins, the same set the canned agenttokens legs run with:
        psi.Environment["STUB_AZ_SIGNED_IN"] = "1";
        psi.Environment["STUB_AUD"] = "api://aaaaaaaa-0000-0000-0000-000000000001";
        psi.Environment["STUB_URI"] = "1";
        psi.Environment["STUB_ROLE"] = "2";
        psi.Environment["STUB_APP_LEFT"] = "0";
        psi.Environment["STUB_SP_LEFT"] = "0";
        psi.Environment["STUB_CURL_CODES"] = "200";

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("live-run.sh did not start");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        Assert.True(process.WaitForExit(120_000), "live-run.sh did not exit within 120 s");
        var azLog = File.Exists(azLogPath) ? File.ReadAllText(azLogPath) : string.Empty;
        File.Delete(azLogPath);
        // the stub wrote the capture with the process umask (664 was measured at
        // umask 0002); it can carry a key value, so it gets the env file's exact 600:
        File.SetUnixFileMode(capturePath, UnixFileMode.UserRead | UnixFileMode.UserWrite); // exactly 600
        var runnerLog = RunnerLogPath(stdout.Result);
        _runnerLog = runnerLog;
        return new RunnerRun(
            process.ExitCode,
            stdout.Result,
            stderr.Result,
            azLog,
            runnerLog,
            capturePath);
    }

    // the runner mktemp-creates its log in the shared temp dir and echoes
    // "log: <path>" — but the model preflight has just printed the HTTP code
    // with NO trailing newline (curl -w, canned and real alike), so in stdout
    // that echo is glued to the tail of the code: the marker must be found
    // anywhere on the line, and a line-start match never fires. The PATH is
    // what Dispose must keep — reading the content here instead would throw
    // the name away and orphan one log per run:
    private static string RunnerLogPath(string stdout)
    {
        const string Marker = "log: ";
        var at = stdout.IndexOf(Marker, StringComparison.Ordinal);
        if (at < 0)
        {
            return string.Empty;
        }

        var rest = stdout[(at + Marker.Length)..];
        var lineEnd = rest.IndexOf('\n');
        var path = (lineEnd < 0 ? rest : rest[..lineEnd]).Trim();
        return File.Exists(path) ? path : string.Empty;
    }

    public void Dispose()
    {
        foreach (var dir in new[] { _stubBin, _home, _scratch })
        {
            if (dir is not null)
            {
                SecretPropagationStubs.TryDelete(dir);
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
