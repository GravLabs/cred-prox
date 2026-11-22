using System.Diagnostics;
using Xunit;

namespace CredProx.LiveTests;

// Live finding 2026-11-22: after live-graph-app.sh create, the live cell started
// against a brand-new Entra client secret that had not propagated yet, the token
// endpoint answered 401, CredProx could only answer 502 credential_unavailable,
// and the run failed on propagation rather than on the code. live-run.sh now
// polls the tenant's v2 token endpoint with client_credentials (every 5 s, up to
// CREDPROX_M46_SECRET_WAIT_SECONDS, default 120) after create and before the
// live cell. These classes exec the REAL live-run.sh against the canned az stubs
// plus a fake curl (which scripts its http codes and logs its argv) plus a fake
// dotnet, under a sandbox HOME - no az, no network, the real
// ~/.config/credprox-live is never read. Class names match NONE of live-run.sh's
// test filters, so a runner leg can never exec these cells and recurse.
internal static class SecretPropagationStubs
{
    // Fake curl: appends its argv (never its stdin - the secret arrives on
    // stdin and is drained here), then prints the n-th scripted http code,
    // repeating the last one forever. The runner captures only this stdout.
    public const string StubCurl = """
        #!/usr/bin/env bash
        if [ -n "${STUB_AZ_LOG:-}" ]; then printf 'curl %s\n' "$*" >> "$STUB_AZ_LOG"; fi
        cat >/dev/null
        n=0
        if [ -n "${STUB_CURL_COUNT:-}" ] && [ -f "$STUB_CURL_COUNT" ]; then n="$(cat "$STUB_CURL_COUNT")"; fi
        n=$((n+1)); printf '%s' "$n" > "$STUB_CURL_COUNT"
        codes=(${STUB_CURL_CODES:-200})
        i=$((n-1)); if [ "$i" -ge "${#codes[@]}" ]; then i=$(( ${#codes[@]} - 1 )); fi
        printf '%s' "${codes[$i]}"
        """;

    public const string StubDotnet = """
        #!/usr/bin/env bash
        if [ -n "${STUB_AZ_LOG:-}" ]; then printf 'dotnet %s\n' "$*" >> "$STUB_AZ_LOG"; fi
        echo "OBSERVED secret-propagation-stub"
        exit 0
        """;

    public static void WriteExec(string stubBin, string name, string body)
    {
        var path = Path.Combine(stubBin, name);
        File.WriteAllText(path, body);
        File.SetUnixFileMode(
            path,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
            | UnixFileMode.GroupRead | UnixFileMode.GroupExecute
            | UnixFileMode.OtherRead | UnixFileMode.OtherExecute); // 755
    }

    // sandbox HOME with the exact-600 central file (the az vendors need only
    // TENANT_ID from it); the machine's real ~/.config/credprox-live is never
    // pointed at:
    public static string MakeSandboxHome()
    {
        var home = Path.Combine(Path.GetTempPath(), $"credprox-m46-prop-home-{Guid.NewGuid():N}");
        var confDir = Path.Combine(home, ".config", "credprox-live");
        Directory.CreateDirectory(confDir);
        var envFile = Path.Combine(confDir, "live.env");
        File.WriteAllText(envFile, "TENANT_ID=00000000-0000-0000-0000-000000000000\n");
        File.SetUnixFileMode(envFile, UnixFileMode.UserRead | UnixFileMode.UserWrite); // exactly 600
        return home;
    }

    // same walk-up discipline as RunnerLeakScanTests.LocateRunner, for live-run.sh:
    public static string LocateRunner()
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

    public static void TryDelete(string dir)
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
}

[Trait("Layer", "Offline")]
public sealed class SecretPropagationGraphTests : IDisposable, IExecutesLiveRunner
{
    // an obvious canary that matches none of the runner's leak shapes: it must
    // reach the token endpoint on STDIN only - never the logged argv, never the
    // terminal:
    private const string CanarySecret = "canary-propagation-secret-0123456789";

    private readonly string _stubBin;
    private readonly string _home;
    private readonly string _scratch;
    private readonly string _countFile;
    private readonly string _runner;

    public SecretPropagationGraphTests()
    {
        _stubBin = Path.Combine(Path.GetTempPath(), $"credprox-m46-propstub-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_stubBin);
        SecretPropagationStubs.WriteExec(_stubBin, "az", GraphAppScriptTests.StubAz);
        SecretPropagationStubs.WriteExec(_stubBin, "dotnet", SecretPropagationStubs.StubDotnet);
        SecretPropagationStubs.WriteExec(_stubBin, "curl", SecretPropagationStubs.StubCurl);
        _home = SecretPropagationStubs.MakeSandboxHome();
        _scratch = Path.Combine(Path.GetTempPath(), $"credprox-m46-prop-scratch-{Guid.NewGuid():N}");
        _countFile = Path.Combine(_stubBin, "curl-count");
        _runner = SecretPropagationStubs.LocateRunner();
    }

    [Fact]
    public void FirstTry200_PollsBeforeTheCell_AndSecretStaysOffArgv()
    {
        var run = Run("200");
        Assert.True(run.Exit == 0, $"the run must pass against a usable secret: exit={run.Exit} out={run.Out} err={run.Err}");
        Assert.Contains("graph client secret usable after", run.Out, StringComparison.Ordinal);
        Assert.Contains("PASS graph", run.Out, StringComparison.Ordinal);
        // the wait really hit the tenant v2 endpoint with the graph scope, and
        // the secret went through on stdin only - the argv line names the
        // stdin marker, never the value:
        Assert.Contains("oauth2/v2.0/token", run.AzLog, StringComparison.Ordinal);
        Assert.Contains("client_secret@-", run.AzLog, StringComparison.Ordinal);
        Assert.Contains("scope=https://graph.microsoft.com/.default", run.AzLog, StringComparison.Ordinal);
        Assert.DoesNotContain(CanarySecret, run.AzLog, StringComparison.Ordinal);
        Assert.DoesNotContain(CanarySecret, run.Out, StringComparison.Ordinal);
        Assert.DoesNotContain(CanarySecret, run.Err, StringComparison.Ordinal);
        Assert.Equal("1", File.ReadAllText(_countFile));
    }

    [Fact]
    public void RefusedOnce_RetriesAndProceedsToTheCell()
    {
        var run = Run("401 200");
        Assert.True(run.Exit == 0, $"the run must pass after one refusal: exit={run.Exit} out={run.Out} err={run.Err}");
        Assert.Contains("graph client secret usable after", run.Out, StringComparison.Ordinal);
        var pollLines = run.AzLog.Split('\n').Count(l => l.StartsWith("curl ", StringComparison.Ordinal));
        Assert.Equal(2, pollLines);
        Assert.Equal("2", File.ReadAllText(_countFile));
    }

    [Fact]
    public void NeverUsable_TimeoutFails_AndDestroyStillRuns_BeforeTheCell()
    {
        // the budget seam is shrunk to 2 s; the poll interval stays the shipped
        // 5 s, so the cell is one refusal, one sleep, one over-budget check:
        var run = Run("401", new() { ["CREDPROX_M46_SECRET_WAIT_SECONDS"] = "2" });
        Assert.Equal(1, run.Exit);
        Assert.Contains("the graph client secret never minted a token within 2 s", run.Out, StringComparison.Ordinal);
        Assert.DoesNotContain("secret usable after", run.Out, StringComparison.Ordinal);
        // destroy was armed before create and the FAIL still ran it, deleting
        // the id the create minted and reading back zero:
        Assert.Contains("graph destroy: read-back clean", run.Out, StringComparison.Ordinal);
        Assert.Contains("ad app delete --id stub-app-id", run.AzLog, StringComparison.Ordinal);
        // the live cell was never reached:
        Assert.DoesNotContain("dotnet ", run.AzLog, StringComparison.Ordinal);
    }

    private sealed record RunnerRun(int Exit, string Out, string Err, string AzLog);

    private RunnerRun Run(string curlCodes, Dictionary<string, string>? extraEnv = null)
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
        // the stub dir LEADS the PATH: it shadows the machine's az, any real
        // dotnet AND the real curl (nothing here may reach the network);
        // system dirs stay behind it for the scripts' ordinary tools:
        psi.Environment["PATH"] = _stubBin + ":/usr/bin:/bin";
        psi.Environment["HOME"] = _home;
        psi.Environment["CREDPROX_M46_SCRATCH"] = _scratch;
        psi.Environment["STUB_AZ_LOG"] = azLogPath;
        psi.Environment["STUB_SECRET"] = CanarySecret;
        psi.Environment["STUB_APP_ID"] = "stub-app-id";
        // hermetic pins (same discipline as RunnerLeakScanTests.Run):
        psi.Environment["STUB_AZ_SIGNED_IN"] = "1";
        psi.Environment["STUB_CRED"] = "1";
        psi.Environment["STUB_APP_LEFT"] = "0";
        psi.Environment["STUB_SP_LEFT"] = "0";
        psi.Environment["STUB_CREATE_FAIL"] = "0";
        psi.Environment["STUB_PLANT"] = string.Empty;
        psi.Environment["STUB_DESTROY_PLANT"] = string.Empty;
        // create minted this id, so the destroy phase sees exactly it in the
        // pre-delete list and must delete it (the left read-back stays 0):
        psi.Environment["STUB_EXISTING_IDS"] = "stub-app-id";
        psi.Environment["STUB_CURL_CODES"] = curlCodes;
        psi.Environment["STUB_CURL_COUNT"] = _countFile;
        if (extraEnv is not null)
        {
            foreach (var (key, value) in extraEnv)
            {
                psi.Environment[key] = value;
            }
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

    public void Dispose()
    {
        foreach (var dir in new[] { _stubBin, _home, _scratch })
        {
            SecretPropagationStubs.TryDelete(dir);
        }
    }
}

[Trait("Layer", "Offline")]
public sealed class SecretPropagationClientTests : IDisposable, IExecutesLiveRunner
{
    // the canned agenttokens az mints these ids; the audience read-back pins
    // the same value the create stamps into resource-audience.txt:
    private const string ResourceAppId = "aaaaaaaa-0000-0000-0000-000000000001";

    private readonly string _stubBin;
    private readonly string _home;
    private readonly string _scratch;
    private readonly string _countFile;
    private readonly string _runner;

    public SecretPropagationClientTests()
    {
        _stubBin = Path.Combine(Path.GetTempPath(), $"credprox-m46-propstub-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_stubBin);
        SecretPropagationStubs.WriteExec(_stubBin, "az", AgentTokensScriptTests.StubAz);
        SecretPropagationStubs.WriteExec(_stubBin, "dotnet", SecretPropagationStubs.StubDotnet);
        SecretPropagationStubs.WriteExec(_stubBin, "curl", SecretPropagationStubs.StubCurl);
        _home = SecretPropagationStubs.MakeSandboxHome();
        _scratch = Path.Combine(Path.GetTempPath(), $"credprox-m46-prop-scratch-{Guid.NewGuid():N}");
        _countFile = Path.Combine(_stubBin, "curl-count");
        _runner = SecretPropagationStubs.LocateRunner();
    }

    [Fact]
    public void TwoClientSecrets_BothWaited_WithTheResourceAudienceScope()
    {
        var run = Run("200");
        Assert.True(run.Exit == 0, $"the run must pass with both secrets usable: exit={run.Exit} out={run.Out} err={run.Err}");
        // BOTH run-created secrets were waited for, each on its first poll:
        Assert.Contains("mapped secret usable after", run.Out, StringComparison.Ordinal);
        Assert.Contains("unmapped secret usable after", run.Out, StringComparison.Ordinal);
        var pollLines = run.AzLog.Split('\n').Count(l => l.StartsWith("curl ", StringComparison.Ordinal));
        Assert.Equal(2, pollLines);
        // the scope is the resource app's own id with .default - the bare form
        // the live cell itself mints with - not the api:// form and not the
        // graph scope (the create's own az rest PATCH may legitimately reach
        // the graph management API; that az traffic is not a token poll):
        Assert.Contains($"scope={ResourceAppId}/.default", run.AzLog, StringComparison.Ordinal);
        Assert.DoesNotContain("scope=https://graph.microsoft.com", run.AzLog, StringComparison.Ordinal);
        // the lifecycle destroyed all three apps again, read-back clean:
        Assert.Contains("agenttokens destroy: read-back clean", run.Out, StringComparison.Ordinal);
    }

    private sealed record RunnerRun(int Exit, string Out, string Err, string AzLog);

    private RunnerRun Run(string curlCodes)
    {
        var azLogPath = Path.Combine(Path.GetTempPath(), $"credprox-m46-azlog-{Guid.NewGuid():N}.log");
        var psi = new ProcessStartInfo
        {
            FileName = "/bin/bash",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add(_runner);
        psi.ArgumentList.Add("agenttokens");
        psi.Environment["PATH"] = _stubBin + ":/usr/bin:/bin";
        psi.Environment["HOME"] = _home;
        psi.Environment["CREDPROX_M46_SCRATCH"] = _scratch;
        psi.Environment["STUB_AZ_LOG"] = azLogPath;
        // hermetic pins of this stub's canned arms (the aud pin equals the
        // stub's own internal resource id, matching what the create read-back
        // stamps into resource-audience.txt):
        psi.Environment["STUB_AZ_SIGNED_IN"] = "1";
        psi.Environment["STUB_AUD"] = $"api://{ResourceAppId}";
        psi.Environment["STUB_URI"] = "1";
        psi.Environment["STUB_ROLE"] = "1";
        psi.Environment["STUB_ASSIGN"] = "1";
        psi.Environment["STUB_APP_LEFT"] = "0";
        psi.Environment["STUB_SP_LEFT"] = "0";
        psi.Environment["STUB_CURL_CODES"] = curlCodes;
        psi.Environment["STUB_CURL_COUNT"] = _countFile;

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("live-run.sh did not start");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        Assert.True(process.WaitForExit(120_000), "live-run.sh did not exit within 120 s");
        var azLog = File.Exists(azLogPath) ? File.ReadAllText(azLogPath) : string.Empty;
        File.Delete(azLogPath);
        return new RunnerRun(process.ExitCode, stdout.Result, stderr.Result, azLog);
    }

    public void Dispose()
    {
        foreach (var dir in new[] { _stubBin, _home, _scratch })
        {
            SecretPropagationStubs.TryDelete(dir);
        }
    }
}
