using System.Diagnostics;
using Xunit;

namespace CredProx.LiveTests;

// Witness for the VAULT-STATE read-back family (post-release item 1, 2026-11-25):
// the list-deleted read-back in the two round-2-era destroy scripts and the aca
// destroy arm has THREE states, and the fail-open one is the bug this family
// pins: the old two-arm shape printed PURGED whenever list-deleted could not
// answer (its RBAC is separate from delete/purge; 2>/dev/null swallowed the
// error into an empty string that matched neither "1" nor anything else), so a
// caller's OK marker could ride a still-live soft-delete name lock. The live
// script runs under a canned az whose list-deleted is scripted per cell: clean
// PURGED, SOFT-DELETED RECOVER, and a canned list-deleted ERROR that must
// print could-not-verify and exit non-zero. The r2/aca fixes are pinned as
// script text (execing those arms means stubbing a dozen more az verbs and a
// full ARM poll loop - the runner-level classes already cover those arms live);
// the aca text pin additionally proves the scratch tear-down sits BELOW the
// read-back and runs only when the read-back answered. The class name carries
// no live-run.sh filter token, it never execs the runner, and it never names
// the runner locator (whose textual guard greps every test file, comments
// included). No real az, no network, no tenant.
[Trait("Layer", "Offline")]
public sealed class VaultDestroyReadBackTests : IDisposable
{
    // Canned az: every verb logs and answers rc 0 EXCEPT list-deleted, which
    // fails outright when STUB_LIST_FAIL is set and otherwise prints the
    // scripted count. The error text on stderr is a canned RBAC refusal -
    // nothing here is, or reaches, a real credential or resource.
    private const string StubAz = """
        #!/usr/bin/env bash
        if [ -n "${STUB_AZ_LOG:-}" ]; then printf 'az %s\n' "$*" >> "$STUB_AZ_LOG"; fi
        case "$*" in
            keyvault\ list-deleted*)
                if [ -n "${STUB_LIST_FAIL:-}" ]; then
                    echo "ERROR: cannot list deleted vaults (RBAC id not granted)" >&2
                    exit 1
                fi
                printf '%s' "${STUB_LIST_COUNT:-0}"
                ;;
            *)
                exit 0
                ;;
        esac
        """;

    private readonly string _stubBin;
    private readonly string _destroyScript;
    private readonly string _r2Script;
    private readonly string _acaScript;

    public VaultDestroyReadBackTests()
    {
        _stubBin = Path.Combine(Path.GetTempPath(), $"credprox-vdrb-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_stubBin);
        SecretPropagationStubs.WriteExec(_stubBin, "az", StubAz);
        var root = RepoRoot();
        _destroyScript = Path.Combine(root, "scripts", "live-infra-destroy.sh");
        _r2Script = Path.Combine(root, "scripts", "live-infra-destroy-r2.sh");
        _acaScript = Path.Combine(root, "scripts", "live-m46-aca.sh");
        Assert.True(File.Exists(_destroyScript), $"the round-1 destroy is not where this witness expects it: {_destroyScript}");
        Assert.True(File.Exists(_r2Script), $"the round-2 destroy is not where this witness expects it: {_r2Script}");
        Assert.True(File.Exists(_acaScript), $"the aca lifecycle script is not where this witness expects it: {_acaScript}");
    }

    [Fact]
    public void Destroy_ListSaysZero_PrintsPurged_ExitsZero()
    {
        // The clean PURGED arm: list-deleted answers 0, the state IS verified,
        // and only then may the script claim the name lock is cleared.
        var run = RunDestroy(new() { ["STUB_LIST_COUNT"] = "0" });
        Assert.Equal(0, run.Exit);
        Assert.Contains("deleted and PURGED (name lock cleared", run.Out, StringComparison.Ordinal);
        Assert.DoesNotContain("could-not-verify", run.Out, StringComparison.Ordinal);
        Assert.DoesNotContain("SOFT-DELETED", run.Out, StringComparison.Ordinal);
    }

    [Fact]
    public void Destroy_ListSaysOne_PrintsSoftDeleted_ExitsZero()
    {
        // The SOFT-DELETED RECOVER arm: purge was refused, the vault name is
        // locked, and the next apply must recover - the line names that path
        // and the exit stays 0 because the state WAS read cleanly.
        var run = RunDestroy(new() { ["STUB_LIST_COUNT"] = "1" });
        Assert.Equal(0, run.Exit);
        Assert.Contains("deleted but SOFT-DELETED", run.Out, StringComparison.Ordinal);
        Assert.DoesNotContain("could-not-verify", run.Out, StringComparison.Ordinal);
        Assert.DoesNotContain("PURGED (name lock cleared", run.Out, StringComparison.Ordinal);
    }

    [Fact]
    public void Destroy_ListDeletedFails_CouldNotVerify_NonZero_NeverPurged()
    {
        // The fail-open this family closes (the two-arm shape printed PURGED
        // here via the empty-string else): the read-back itself errored, so
        // the state is UNKNOWN - the line must say could-not-verify, the exit
        // must be non-zero, and neither verdict word may appear.
        var run = RunDestroy(new() { ["STUB_LIST_FAIL"] = "1" });
        Assert.NotEqual(0, run.Exit);
        Assert.Contains("could-not-verify:", run.Out, StringComparison.Ordinal);
        Assert.Contains("apply must RECOVER", run.Out, StringComparison.Ordinal);
        Assert.DoesNotContain("PURGED", run.Out, StringComparison.Ordinal);
        Assert.DoesNotContain("SOFT-DELETED", run.Out, StringComparison.Ordinal);
        Assert.DoesNotContain("destroyed:", run.Out, StringComparison.Ordinal);
    }

    [Fact]
    public void ScriptText_R2CarriesThreeArms_InitialisedBefore_VerdictRidesExit()
    {
        // r2 keeps a real exit-carrier (the resource read-backs below the vault
        // block end in exit "$DESTROY_FAIL"), so the vault arm must (a) use the
        // capture-guard three-arm shape, (b) initialise DESTROY_FAIL BEFORE the
        // read-back - the old in-loop init would wipe a vault-state failure -
        // and (c) keep the single exit line that carries it.
        var text = File.ReadAllText(_r2Script);
        Assert.Contains("if ! LIST_DELETED_COUNT=\"$(az keyvault list-deleted", text, StringComparison.Ordinal);
        Assert.Contains("could-not-verify:", text, StringComparison.Ordinal);
        Assert.Contains("DESTROY_FAIL=1", text, StringComparison.Ordinal);
        Assert.Equal(1, text.Split("DESTROY_FAIL=0").Length - 1);
        Assert.True(
            text.IndexOf("DESTROY_FAIL=0", StringComparison.Ordinal)
            < text.IndexOf("could-not-verify:", StringComparison.Ordinal),
            "DESTROY_FAIL must be initialised before the vault read-back, or the loop init below would erase a could-not-verify state");
        Assert.EndsWith("exit \"$DESTROY_FAIL\"", text.TrimEnd(), StringComparison.Ordinal);
    }

    [Fact]
    public void ScriptText_AcaScratchTornBelowReadBack_OnlyWhenItAnswered()
    {
        // The aca destroy arm carries the same three states, and its scratch
        // tear-down moved BELOW the read-back: a could-not-verify run RETAINS
        // the scratch (the retry needs the recorded names), and each answered
        // arm tears it in its own branch. Pinned textually inside the destroy
        // region: both rm lines sit after the list-deleted capture.
        var text = File.ReadAllText(_acaScript);
        var start = text.IndexOf("\ndestroy)\n", StringComparison.Ordinal);
        Assert.True(start >= 0, "the aca destroy case is not where this pin expects it");
        var end = text.IndexOf("\n  ;;", start, StringComparison.Ordinal);
        Assert.True(end > start, "the aca destroy case does not close where this pin expects it");
        var region = text[start..end];
        Assert.Contains("if ! LIST_DELETED_COUNT=\"$(az keyvault list-deleted", region, StringComparison.Ordinal);
        Assert.Contains("could-not-verify:", region, StringComparison.Ordinal);
        Assert.Contains("SCRATCH retained for the retry", region, StringComparison.Ordinal);
        var readBackAt = region.IndexOf("list-deleted", StringComparison.Ordinal);
        Assert.True(readBackAt >= 0, "the read-back vanished from the destroy region");
        var tearDowns = 0;
        var at = 0;
        while ((at = region.IndexOf("rm -rf \"$SCRATCH\"", at, StringComparison.Ordinal)) >= 0)
        {
            Assert.True(at > readBackAt, "a scratch tear-down sits ABOVE the list-deleted read-back - a could-not-verify run would lose the recorded names");
            tearDowns++;
            at += 1;
        }

        Assert.Equal(2, tearDowns);
    }

    private sealed record RunResult(int Exit, string Out, string Err);

    private RunResult RunDestroy(Dictionary<string, string> stubEnv)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "/bin/bash",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add(_destroyScript);
        // the stub dir LEADS PATH: the canned az shadows the machine's real
        // one; nothing here can reach a tenant, the network or a resource.
        psi.Environment["PATH"] = _stubBin + ":/usr/bin:/bin";
        psi.Environment["STUB_AZ_LOG"] = Path.Combine(_stubBin, $"azlog-{Guid.NewGuid():N}.log");
        foreach (var (name, value) in stubEnv)
        {
            psi.Environment[name] = value;
        }

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("live-infra-destroy.sh did not start");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        Assert.True(process.WaitForExit(30_000), "live-infra-destroy.sh did not exit within 30 s");
        return new RunResult(process.ExitCode, stdout.Result, stderr.Result);
    }

    private static string RepoRoot()
    {
        var parts = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar)
            .Split(Path.DirectorySeparatorChar);
        var binIndex = Array.IndexOf(parts, "bin");
        Assert.True(binIndex >= 3, $"unexpected test assembly location '{AppContext.BaseDirectory}'");
        return string.Join(Path.DirectorySeparatorChar, parts[..(binIndex - 2)]);
    }

    public void Dispose()
    {
        SecretPropagationStubs.TryDelete(_stubBin);
    }
}
