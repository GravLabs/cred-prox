using System.Diagnostics;
using Xunit;

namespace CredProx.LiveTests;

// The ACA vendor's machine-local contract, proven offline against planted files
// in the temp directory (same shape as the graph/agenttokens contract cells).
[Trait("Layer", "Offline")]
public sealed class AcaEnvContractTests : IDisposable
{
    private readonly string _tempPath = Path.Combine(
        Path.GetTempPath(),
        $"credprox-live-aca-{Guid.NewGuid():N}.env");

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
        var absent = LiveEnv.Probe(AcaEnv.Vendor, AcaEnv.RequiredKeys, _tempPath + ".absent");
        Assert.False(absent.Available);
        Assert.Contains("~/.config/credprox-live/live.env", absent.SkipReason, StringComparison.Ordinal);
        Assert.Contains("TENANT_ID", absent.SkipReason, StringComparison.Ordinal);

        File.WriteAllLines(_tempPath, new[] { "TENANT_ID=00000000-0000-0000-0000-000000000000" });
        File.SetUnixFileMode(
            _tempPath,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead); // 644
        var loose = LiveEnv.Probe(AcaEnv.Vendor, AcaEnv.RequiredKeys, _tempPath);
        Assert.False(loose.Available);
        Assert.Contains("mode 644, must be exactly 600", string.Join("; ", loose.Problems), StringComparison.Ordinal);

        File.SetUnixFileMode(_tempPath, UnixFileMode.UserRead | UnixFileMode.UserWrite); // 600
        var probe = LiveEnv.Probe(AcaEnv.Vendor, AcaEnv.RequiredKeys, _tempPath);
        Assert.True(probe.Available, string.Join("; ", probe.Problems));
        Assert.Equal("00000000-0000-0000-0000-000000000000", probe.Values["TENANT_ID"]);
    }

    [Fact]
    public void ValueProblems_NameBadShapesWithoutEchoingValues()
    {
        var domain = AcaEnv.ValueProblems(new Dictionary<string, string>
        {
            ["TENANT_ID"] = "contoso.onmicrosoft.com",
        });
        Assert.Single(domain);
        Assert.Contains("TENANT_ID", domain[0], StringComparison.Ordinal);
        Assert.DoesNotContain("contoso", domain[0], StringComparison.Ordinal);

        var good = AcaEnv.ValueProblems(new Dictionary<string, string>
        {
            ["TENANT_ID"] = "00000000-0000-0000-0000-000000000000",
        });
        Assert.Empty(good);
    }
}

// The offline contract for scripts/live-m46-aca.sh, driven against a stub az (and a
// stub docker) shadowed at the front of PATH — nothing here can touch a subscription.
// The claims proven: --dry-run performs ZERO az/docker invocations even with no az
// on PATH at all; both sign-in gates die before any write verb; the apply step
// resolves every role definition id live and refuses when one comes back empty;
// vault material travels only through --file uploads (the minted values appear
// nowhere in the output, the error stream or the call log, and the scratch handoff
// is 700/600); the push digest read-back and every deploy identity read-back
// decide the exit code; the verify leg strips the log-routing prefix, counts the
// C-lines, never re-starts an accepted-empty job, and fails on a job that does not
// finish; and destroy's read-backs (vault purge shape, each resource gone, run
// identities' role assignments zero, resource group gone) decide its exit code.
[Trait("Layer", "Offline")]
public sealed class AcaScriptTests : IDisposable
{
    // Canned ids and digests — stub-fixture constants, never live facts (the
    // real script resolves all ids at run time; the point of the pins below is
    // that the canned ones are DISTINCT per role name and actually reach the
    // deployment call).
    private const string OfficerPrincipal = "11111111-1111-1111-1111-111111111111";
    private const string OfficerRoleId = "22222222-2222-2222-2222-222222222222";
    private const string VaultUserRoleDefinitionId = "33333333-3333-3333-3333-333333333333";
    private const string AcrPullRoleId = "44444444-4444-4444-4444-444444444444";
    // INTERNAL (not private): RunnerRunCreatedScanTests drives the real runner
    // through the same canned world and must pin the stamp read-back to this
    // exact head rather than carry a second copy that could drift.
    internal const string AcaDigestHead = "aaaaaaaaaaaa"; // first 12 hex of the canned app digest

    private static readonly string ScriptPath = LocateScript();
    private readonly string _stubBin;
    private readonly string _scratch;

    public AcaScriptTests()
    {
        _stubBin = Path.Combine(Path.GetTempPath(), $"credprox-m46-aca-stubbin-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_stubBin);
        WriteStub("az", StubAz);
        WriteStub("docker", StubDocker);
        _scratch = Path.Combine(Path.GetTempPath(), $"credprox-m46-aca-scratch-{Guid.NewGuid():N}");
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

    private void WriteStub(string name, string body)
    {
        var path = Path.Combine(_stubBin, name);
        File.WriteAllText(path, body);
        File.SetUnixFileMode(
            path,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
            | UnixFileMode.GroupRead | UnixFileMode.GroupExecute
            | UnixFileMode.OtherRead | UnixFileMode.OtherExecute); // 755
    }

    [Fact]
    public void DryRun_NoAzOnPath_PrintsPlanAndTouchesNothing()
    {
        var run = Run("--dry-run", withAz: false);
        Assert.True(run.Exit == 0, $"--dry-run must exit 0 without az on PATH: exit={run.Exit} err={run.Err}");
        Assert.Contains("plan (no writes performed)", run.Out, StringComparison.Ordinal);
        Assert.Contains("az group exists == false", run.Out, StringComparison.Ordinal);
        Assert.DoesNotContain("keyvault secret set", run.Log, StringComparison.Ordinal);
        Assert.DoesNotContain("docker", run.Log, StringComparison.Ordinal);
        Assert.False(Directory.Exists(_scratch), "--dry-run must not create the scratch dir");
    }

    [Fact]
    public void UnknownVerb_PrintsUsageAndExitsTwo()
    {
        var run = Run("obliterate");
        Assert.Equal(2, run.Exit);
        Assert.Contains("apply|material|push|deploy|verify|destroy", run.Out, StringComparison.Ordinal);
    }

    [Fact]
    public void Apply_SignedOut_DiesBeforeAnyWrite()
    {
        var run = Run("apply", new() { ["STUB_AZ_SIGNED_IN"] = "0" });
        Assert.Equal(1, run.Exit);
        Assert.Contains("az sign-in required", run.Out, StringComparison.Ordinal); // the script echoes refusals to stdout
        Assert.DoesNotContain("group create", run.Log, StringComparison.Ordinal);
    }

    [Fact]
    public void Apply_ContainerappExtensionMissing_DiesBeforeAnyWrite()
    {
        var run = Run("apply", new() { ["STUB_EXT"] = "0" });
        Assert.Equal(1, run.Exit);
        Assert.Contains("az containerapp command group absent", run.Out, StringComparison.Ordinal); // the script echoes refusals to stdout
        Assert.DoesNotContain("group create", run.Log, StringComparison.Ordinal);
    }

    [Fact]
    public void Apply_ResolvesRoleIdsLive_MaterialsThroughFileOnly_AndNeverEchoesValues()
    {
        var run = Run("apply");
        Assert.True(run.Exit == 0, $"apply must exit 0: exit={run.Exit} err={run.Err}");
        Assert.Contains("rg: credprox-m46-aca ready", run.Out, StringComparison.Ordinal);
        Assert.Contains("7 resources", run.Out, StringComparison.Ordinal);

        // Every id in the deployment call is the canned LIVE-RESOLVED value for
        // its own role name - three distinct GUIDs plus the officer principal.
        Assert.Contains($"officerPrincipalId={OfficerPrincipal}", run.Log, StringComparison.Ordinal);
        Assert.Contains($"officerRoleId={OfficerRoleId}", run.Log, StringComparison.Ordinal);
        Assert.Contains($"vaultUserRoleDefinitionId={VaultUserRoleDefinitionId}", run.Log, StringComparison.Ordinal);
        Assert.Contains($"acrPullRoleId={AcrPullRoleId}", run.Log, StringComparison.Ordinal);

        // names only ever reach the log; the three uploads carry --file paths
        foreach (var name in new[]
        {
            "CredProx--Secrets--demoCallerKeyHash",
            "CredProx--Secrets--acme-vendor-key",
            "CredProxTest--aca-caller-key",
        })
        {
            Assert.Contains($"--name {name} --file", run.Log, StringComparison.Ordinal);
        }

        Assert.Contains("3 secrets present (expected 3)", run.Out, StringComparison.Ordinal);

        // the scratch handoff: 700 dir, 600 file, both keys present - and the
        // minted values are in NO output stream (the leak scan's offline twin)
        Assert.Equal(Convert.ToInt32("700", 8), (int)File.GetUnixFileMode(_scratch));
        var handoff = Path.Combine(_scratch, "aca-secrets.env");
        Assert.Equal(Convert.ToInt32("600", 8), (int)File.GetUnixFileMode(handoff));
        var callerKey = string.Empty;
        var vendorKey = string.Empty;
        foreach (var line in File.ReadAllLines(handoff))
        {
            if (line.StartsWith("ACA_CALLER_KEY=", StringComparison.Ordinal))
            {
                callerKey = line["ACA_CALLER_KEY=".Length..];
            }

            if (line.StartsWith("ACA_VENDOR_KEY=", StringComparison.Ordinal))
            {
                vendorKey = line["ACA_VENDOR_KEY=".Length..];
            }
        }

        Assert.NotEmpty(callerKey);
        Assert.NotEmpty(vendorKey);
        Assert.DoesNotContain(callerKey, run.Out + run.Err + run.Log, StringComparison.Ordinal);
        Assert.DoesNotContain(vendorKey, run.Out + run.Err + run.Log, StringComparison.Ordinal);
    }

    [Fact]
    public void Apply_EmptyRoleDefinition_ResolvesNothingAndRefuses()
    {
        var run = Run("apply", new() { ["STUB_ROLE_OK"] = "0" });
        Assert.Equal(1, run.Exit);
        Assert.Contains("principal or role definition unresolved", run.Out, StringComparison.Ordinal); // the script echoes refusals to stdout
        Assert.DoesNotContain("deployment group create", run.Log, StringComparison.Ordinal);
    }

    [Fact]
    public void Material_VaultAbsent_Refuses()
    {
        var run = Run("material", new() { ["STUB_VAULT"] = "0" });
        Assert.Equal(1, run.Exit);
        Assert.Contains("run apply first", run.Out, StringComparison.Ordinal); // the script echoes refusals to stdout
        Assert.DoesNotContain("keyvault secret set", run.Log, StringComparison.Ordinal);
    }

    [Fact]
    public void Push_AcrAbsent_Refuses()
    {
        var run = Run("push", new() { ["STUB_ACR"] = "0" });
        Assert.Equal(1, run.Exit);
        Assert.Contains("acr credproxm46reg absent", run.Out, StringComparison.Ordinal); // the script echoes refusals to stdout
        Assert.DoesNotContain("docker", run.Log, StringComparison.Ordinal);
    }

    [Fact]
    public void Push_Happy_EchoesThreeTagDigests()
    {
        var run = Run("push");
        Assert.True(run.Exit == 0, $"push must exit 0: exit={run.Exit} err={run.Err}");
        // docker push needs registry credentials: the push logs in to its own registry first
        Assert.Contains("acr login -n credproxm46reg", run.Log, StringComparison.Ordinal);
        // ORDER, not just presence: a login after the pushes is today's live failure shape
        var login = run.Log.IndexOf("acr login -n credproxm46reg", StringComparison.Ordinal);
        var firstPush = run.Log.IndexOf("docker push", StringComparison.Ordinal);
        Assert.True(firstPush > login, "az acr login must precede the first docker push");
        foreach (var image in new[] { "credprox-m46-aca", "credprox-m46-stub", "credprox-m46-harness" })
        {
            Assert.Contains($"docker push credproxm46reg.azurecr.io/{image}:latest", run.Log, StringComparison.Ordinal);
        }

        Assert.Contains($"pushed: credprox-m46-aca:latest {AcaDigestHead}", run.Out, StringComparison.Ordinal);
        Assert.Contains("pushed: credprox-m46-stub:latest bbbbbbbbbbbb", run.Out, StringComparison.Ordinal);
        Assert.Contains("pushed: credprox-m46-harness:latest cccccccccccc", run.Out, StringComparison.Ordinal);
    }

    [Fact]
    public void Push_DigestReadBackMismatch_ExitsOne()
    {
        // the pushes "succeeded" but the registry cannot echo a digest: the
        // read-back exists exactly for this half-landed state
        var run = Run("push", new() { ["STUB_DIGEST"] = "0" });
        Assert.Equal(1, run.Exit);
        Assert.Contains("pushed digest read-back mismatched: credprox-m46-aca:latest", run.Out, StringComparison.Ordinal); // the script echoes refusals to stdout
    }

    [Fact]
    public void Deploy_Happy_IdentitiesAssignedBeforeSpec_AndEveryReadBackTrue()
    {
        var run = Run("deploy");
        Assert.True(run.Exit == 0, $"deploy must exit 0: exit={run.Exit} err={run.Err}");
        Assert.Contains("created credprox-m46-app", run.Out, StringComparison.Ordinal);
        Assert.Contains("created credprox-m46-verify", run.Out, StringComparison.Ordinal);
        Assert.Contains("kubelet identity selected: true (expected true)", run.Out, StringComparison.Ordinal);
        Assert.Contains("identities attached: 2 (expected 2)", run.Out, StringComparison.Ordinal);
        Assert.Contains($"stamp==registry-current: True", run.Out, StringComparison.Ordinal);
        Assert.Contains("credprox-m46-app--g1", run.Out, StringComparison.Ordinal);

        // identity ATTACH precedes the spec that selects it (live finding:
        // --yaml does not carry userAssignedIdentities reliably)
        var assign = run.Log.IndexOf("containerapp identity assign", StringComparison.Ordinal);
        var update = run.Log.IndexOf("containerapp update", StringComparison.Ordinal);
        Assert.True(assign >= 0 && update > assign, "identity assign must precede the spec update");
        var jobCreate = run.Log.IndexOf("containerapp job create", StringComparison.Ordinal);
        var jobAssign = run.Log.IndexOf("containerapp job identity assign", StringComparison.Ordinal);
        Assert.True(jobAssign > jobCreate, "the job attaches its identities after create");
    }

    [Fact]
    public void Deploy_CreateRefused_ExitsOne_BeforeAnyIdentityAssign()
    {
        // live finding 2026-11-22: the CLI refused the app spec, the script
        // printed "created" and walked on into identity assign on an app that
        // did not exist. A refused create must stop deploy there.
        var run = Run("deploy", new() { ["STUB_CREATE_REFUSED"] = "1" });
        Assert.Equal(1, run.Exit);
        Assert.Contains("create refused: credprox-m46-app does not exist after create", run.Out, StringComparison.Ordinal);
        Assert.DoesNotContain("created credprox-m46-app", run.Out, StringComparison.Ordinal);
        Assert.DoesNotContain("containerapp identity assign", run.Log, StringComparison.Ordinal);
    }

    [Fact]
    public void AcacheckReadsTheCallerKeySecretTheMaterialStepWrites()
    {
        // live finding 2026-11-22: material wrote CredProxTest--aca-caller-key,
        // acacheck fetched the M29 name CredProx--Secrets--caller-key, and the job
        // failed in-cluster. The loopback cell hands the key through env, so only
        // this cross-file pin connects the two names.
        var root = Path.GetDirectoryName(Path.GetDirectoryName(ScriptPath)!)!;
        var script = File.ReadAllText(ScriptPath);
        var harness = File.ReadAllText(Path.Combine(root, "tools", "aca-live-harness", "Program.cs"));
        var written = System.Text.RegularExpressions.Regex.Match(script,
            @"secret set --vault-name ""\$VAULT"" --name '([^']+)' --file ""\$D/caller\.key""");
        Assert.True(written.Success, "the material step must upload caller.key under a named secret");
        Assert.Contains($"AcaCallerKeySecretName = \"{written.Groups[1].Value}\"", harness, StringComparison.Ordinal);

        // the harness README is what whoever debugs the next verify failure
        // reads: the acacheck row must carry the written name, never the
        // retired M29 one (that stale cell cost run four its diagnosis). The
        // battery row legitimately keeps the M29 name - only this row is pinned.
        var readme = File.ReadAllText(Path.Combine(root, "tools", "aca-live-harness", "README.md"));
        var acacheckRow = System.Text.RegularExpressions.Regex.Match(readme, @"(?m)^\| `--mode acacheck .*`.*$");
        Assert.True(acacheckRow.Success, "the README keeps the acacheck row on one line");
        Assert.Contains(written.Groups[1].Value, acacheckRow.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("CredProx--Secrets--caller-key", acacheckRow.Value, StringComparison.Ordinal);
    }

    [Fact]
    public void AcacheckReadsTheVendorKeySecretTheMaterialStepWrites()
    {
        // INFO from the 23c70ef check: the vendor key is OPTIONAL for acacheck,
        // so a renamed material secret only warns while C2 still passes on
        // shape - the cross-file pin is the only signal a rename would leave.
        var root = Path.GetDirectoryName(Path.GetDirectoryName(ScriptPath)!)!;
        var script = File.ReadAllText(ScriptPath);
        var harness = File.ReadAllText(Path.Combine(root, "tools", "aca-live-harness", "Program.cs"));
        var written = System.Text.RegularExpressions.Regex.Match(script,
            @"secret set --vault-name ""\$VAULT"" --name '([^']+)' --file ""\$D/vendor\.key""");
        Assert.True(written.Success, "the material step must upload vendor.key under a named secret");
        Assert.Contains($"AcaVendorKeySecretName = \"{written.Groups[1].Value}\"", harness, StringComparison.Ordinal);
        Assert.Contains("GetSecret(AcaVendorKeySecretName)", harness, StringComparison.Ordinal);
        var literals = harness.Split(new[] { "CredProx--Secrets--acme-vendor-key" }, StringSplitOptions.None).Length - 1;
        Assert.Equal(1, literals); // exactly the const line - fetch and warn both speak the const
        // m46m INFO: the vendor half of the README's acacheck row was unpinned,
        // and the NAMES array apply prints was free to drift from what material
        // actually uploads. Both must speak the name material writes:
        var readme = File.ReadAllText(Path.Combine(root, "tools", "aca-live-harness", "README.md"));
        var acacheckRow = System.Text.RegularExpressions.Regex.Match(readme, @"(?m)^\| `--mode acacheck .*`.*$");
        Assert.True(acacheckRow.Success, "the README keeps the acacheck row on one line");
        Assert.Contains(written.Groups[1].Value, acacheckRow.Value, StringComparison.Ordinal);
        var names = System.Text.RegularExpressions.Regex.Match(script, @"(?m)^NAMES=\(([^\n]*)\)");
        Assert.True(names.Success, "the script keeps its NAMES array on one line");
        Assert.Contains(written.Groups[1].Value, names.Groups[1].Value, StringComparison.Ordinal);
    }

    [Fact]
    public void VerifyPollBudget_OutlastsTheJobReplicaTimeout()
    {
        // INFO from the 23c70ef check: a verify job can still succeed after the
        // 480 s poll cap gives up, printing a did-not-finish failure on a job
        // that was going to pass. The two caps must agree that the POLL gives
        // up second.
        var root = Path.GetDirectoryName(Path.GetDirectoryName(ScriptPath)!)!;
        var script = File.ReadAllText(ScriptPath);
        var pollS = System.Text.RegularExpressions.Regex.Match(script, @"ACA_VERIFY_S=""\$\{CREDPROX_M46_ACA_VERIFY_POLL_S:-(\d+)\}""");
        var pollN = System.Text.RegularExpressions.Regex.Match(script, @"ACA_VERIFY_N=""\$\{CREDPROX_M46_ACA_VERIFY_N:-(\d+)\}""");
        Assert.True(pollS.Success && pollN.Success, "the verify poll keeps its two env-default vars");
        var template = File.ReadAllText(Path.Combine(root, "infra", "azure", "aca-m46-job.yaml.tmpl"));
        var timeout = System.Text.RegularExpressions.Regex.Match(template, @"replicaTimeout: (\d+)");
        Assert.True(timeout.Success, "the job template declares a replicaTimeout");
        Assert.True(long.Parse(pollS.Groups[1].Value) * long.Parse(pollN.Groups[1].Value) > long.Parse(timeout.Groups[1].Value),
            "the poll cap must outlast the job timeout, or a slow success reads as a failure");
        // 713762b INFO: the two default lines alone do not prove the loop drives
        // itself off them - a hard-coded re-introduction would leave the defaults
        // green while the budget lies. The loop must consume both vars:
        var useN = System.Text.RegularExpressions.Regex.Match(script, @"for _ in \$\(seq 1 ""\$ACA_VERIFY_N""\)");
        var useS = System.Text.RegularExpressions.Regex.Match(script, @"sleep ""\$ACA_VERIFY_S""");
        Assert.True(useN.Success && useS.Success, "the verify poll loop must drive itself from ACA_VERIFY_N/ACA_VERIFY_S, not literals");
    }

    [Fact]
    public void SmokeBatteryPollBudget_OutlastsTheR2JobReplicaTimeout()
    {
        // 0babf52 INFO: the smoke battery wait carried the same gap the ACA
        // verify poll was fixed for - a 480 s cap in front of the r2 job's
        // 900 s replicaTimeout, so a slow success read as a give-up. Same rule,
        // same cross-file shape: the wait loop's count times its sleep must
        // outlast the template's timeout.
        var root = Path.GetDirectoryName(Path.GetDirectoryName(ScriptPath)!)!;
        var smoke = File.ReadAllText(Path.Combine(root, "scripts", "live-azure-smoke.sh"));
        var wait = System.Text.RegularExpressions.Regex.Match(smoke, @"for i in \$\(seq 1 (\d+)\);[^\n]*\n\s*sleep (\d+)");
        Assert.True(wait.Success, "the battery wait keeps its count-then-sleep shape");
        var template = File.ReadAllText(Path.Combine(root, "infra", "azure", "aca-job-r2.yaml.tmpl"));
        var timeout = System.Text.RegularExpressions.Regex.Match(template, @"replicaTimeout: (\d+)");
        Assert.True(timeout.Success, "the r2 job template declares a replicaTimeout");
        Assert.True(long.Parse(wait.Groups[1].Value) * long.Parse(wait.Groups[2].Value) > long.Parse(timeout.Groups[1].Value),
            "the smoke wait must outlast the r2 replicaTimeout, or a slow success reads as a failure");
    }

    [Fact]
    public void AppTemplate_ProbesAreAList_OfTypedProbes()
    {
        // live finding 2026-11-22: probes written as a map keyed
        // liveness/readiness is valid YAML but the Container Apps schema wants a
        // list, and the CLI refused it with "Invalid YAML provided".
        var template = File.ReadAllText(Path.Combine(Path.GetDirectoryName(Path.GetDirectoryName(ScriptPath)!)!,
            "infra", "azure", "aca-m46-app.yaml.tmpl"));
        Assert.Matches(@"(?m)^\s+probes:\r?\n\s+- type: Liveness$", template);
        Assert.Matches(@"(?m)^\s+- type: Readiness$", template);
        Assert.DoesNotMatch(@"(?m)^\s+(liveness|readiness):\s*$", template);
    }

    [Fact]
    public void Deploy_KubeletNotSelected_ExitsOne()
    {
        // the canned read-back says the pull path never selected the kubelet
        // identity: deploy must not walk past the False it printed
        var run = Run("deploy", new() { ["STUB_KUBELET"] = "false" });
        Assert.Equal(1, run.Exit);
        Assert.Contains("kubelet identity selected: false (expected true)", run.Out, StringComparison.Ordinal);
        Assert.Contains("read-back mismatch - refusing to proceed", run.Out, StringComparison.Ordinal); // the script echoes refusals to stdout
        Assert.DoesNotContain("containerapp job create", run.Log, StringComparison.Ordinal);
    }

    [Fact]
    public void Verify_Happy_StripsLogPrefixAndPrintsObserved()
    {
        var run = Run("verify");
        Assert.True(run.Exit == 0, $"verify must exit 0: exit={run.Exit} err={run.Err}");
        Assert.Contains("OBSERVED 3/3 acacheck checks passed, job Succeeded", run.Out, StringComparison.Ordinal);
        // the routing prefix is stripped or every line-anchored count silently
        // misses (live finding 2026-11-06):
        Assert.Contains("\nC1 PASS health unauthenticated", "\n" + run.Out, StringComparison.Ordinal);
        Assert.DoesNotContain("stdout F C1", run.Out, StringComparison.Ordinal);
        Assert.Contains("acacheck UTC ", run.Out, StringComparison.Ordinal);
    }

    [Fact]
    public void Verify_FailingCheck_ExitsOne()
    {
        var run = Run("verify", new() { ["STUB_LOGS"] = "fail" });
        Assert.Equal(1, run.Exit);
        Assert.Contains("aca verify: FAIL (status=Succeeded pass=2 fail=1)", run.Out, StringComparison.Ordinal); // the script echoes refusals to stdout
        // live finding 2026-11-22: a failed verify must say WHY before destroy
        // erases the app - revision health and the proxy's own lines
        Assert.Contains("credprox-m46-app--g1\tUnhealthy\tFailed\t0", run.Out, StringComparison.Ordinal);
        Assert.Contains("stub proxy console: startup failed", run.Out, StringComparison.Ordinal);
        Assert.Contains("stub system event: container crashing", run.Out, StringComparison.Ordinal);
        Assert.Contains("containerapp logs show -n credprox-m46-app -g credprox-m46-aca --container proxy --type console", run.Log, StringComparison.Ordinal);
        // INFO-1 from the 268d470 check: the stub answers the revision list off a
        // healthState SUBSTRING, so a renamed or narrowed JMESPath field stays
        // green on output alone - pin the exact query as invoked (quotes are the
        // shell's, absent from the stub's argv join):
        Assert.Contains(
            "containerapp revision list -n credprox-m46-app -g credprox-m46-aca --query [].[name, properties.healthState, properties.runningState, properties.replicas] -o tsv",
            run.Log, StringComparison.Ordinal);
    }

    [Fact]
    public void Verify_Happy_ReadsNoDiagnostics()
    {
        var run = Run("verify");
        Assert.Equal(0, run.Exit);
        Assert.DoesNotContain("containerapp logs show", run.Log, StringComparison.Ordinal);
    }

    [Fact]
    public void AppTemplate_NamesTheVaultIdentityForDefaultAzureCredential()
    {
        // live finding 2026-11-22: the shipped sample builds new DefaultAzureCredential(),
        // which reads AZURE_CLIENT_ID; the app carries two user-assigned identities, so
        // without it the vault provider cannot pick one and the proxy never starts.
        var template = File.ReadAllText(Path.Combine(Path.GetDirectoryName(Path.GetDirectoryName(ScriptPath)!)!,
            "infra", "azure", "aca-m46-app.yaml.tmpl"));
        Assert.Matches(@"(?m)^\s+- name: AZURE_CLIENT_ID\r?\n\s+value: ""\$UAI_CLIENT_ID""$", template);
        // INFO-2 from the 268d470 check: nothing in the shipped sample reads
        // MANAGED_IDENTITY_CLIENT_ID - that is the harness's knob, and it stays
        // pinned in the job template; the app container must not carry it. The
        // assert is scoped to the env-entry form because the file header names
        // the variable in prose (prose self-match trap).
        Assert.DoesNotContain("- name: MANAGED_IDENTITY_CLIENT_ID", template, StringComparison.Ordinal);
    }

    [Fact]
    public void Verify_JobDidNotFinish_ExitsOne()
    {
        // STUB_STATUS=Running + the shrunk poll knobs: the bounded wait must
        // report the unfinished job instead of pretending a green run
        var run = Run("verify", new() { ["STUB_STATUS"] = "Running" });
        Assert.Equal(1, run.Exit);
        Assert.Contains("did not finish (last status: Running)", run.Out, StringComparison.Ordinal); // the script echoes refusals to stdout
    }

    [Fact]
    public void Verify_WedgedTerminalStatus_StillDiagnoses()
    {
        // INFO folded for 0.15.1: Stopped/Timeout/Cancelled/Deleting BREAK the
        // poll as terminal, but the did-not-finish exit skipped the whole
        // diagnostics block - nobody said WHY the execution stopped. The same
        // revision, proxy-console and system-event lines must reach the log
        // from that branch too. STUB_STATUS=Stopped: one poll, terminal.
        var run = Run("verify", new() { ["STUB_STATUS"] = "Stopped" });
        Assert.Equal(1, run.Exit);
        Assert.Contains("did not finish (last status: Stopped)", run.Out, StringComparison.Ordinal);
        Assert.Contains("credprox-m46-app--g1\tUnhealthy\tFailed\t0", run.Out, StringComparison.Ordinal);
        Assert.Contains("stub proxy console: startup failed", run.Out, StringComparison.Ordinal);
        Assert.Contains("stub system event: container crashing", run.Out, StringComparison.Ordinal);
    }

    [Fact]
    public void Verify_StartAcceptedEmpty_ResolvesExecutionNameOnce()
    {
        // a start whose answer came back empty already fired the execution:
        // resolve the name from the list, NEVER start again (duplicate rule)
        var run = Run("verify", new() { ["STUB_START"] = "empty" });
        Assert.True(run.Exit == 0, $"accepted-empty start must still verify: exit={run.Exit} err={run.Err}");
        var starts = run.Log.Split('\n').Count(l => l.StartsWith("containerapp job start", StringComparison.Ordinal));
        Assert.Equal(1, starts);
        Assert.Contains("containerapp job execution list", run.Log, StringComparison.Ordinal);
        Assert.Contains("OBSERVED 3/3", run.Out, StringComparison.Ordinal);
    }

    [Fact]
    public void Verify_StartRefused_ExitsOneAfterThreeTries()
    {
        // 40 s of real back-off (2 x 20 s): a provisioning op that clears may
        // succeed on a later attempt; a permanent refusal exits 1
        var run = Run("verify", new() { ["STUB_START"] = "fail" });
        Assert.Equal(1, run.Exit);
        Assert.Contains("could not start credprox-m46-verify", run.Out, StringComparison.Ordinal); // the script echoes refusals to stdout
        var starts = run.Log.Split('\n').Count(l => l.StartsWith("containerapp job start", StringComparison.Ordinal));
        Assert.Equal(3, starts);
    }

    [Fact]
    public void Destroy_Clean_ExitsZeroWithGoneReadBacks()
    {
        var run = Run("destroy");
        Assert.True(run.Exit == 0, $"destroy with zero leftovers must exit 0: exit={run.Exit} err={run.Err}");
        Assert.Contains("deleted and PURGED", run.Out, StringComparison.Ordinal);
        foreach (var name in new[] { "credprox-m46-app", "credprox-m46-verify", "credprox-m46-env", "credproxm46reg" })
        {
            Assert.Contains($"gone: {name}", run.Out, StringComparison.Ordinal);
        }

        Assert.Contains("gone: credprox-m46-* identities", run.Out, StringComparison.Ordinal);
        Assert.Contains("gone: role assignments for a run identity", run.Out, StringComparison.Ordinal);
        Assert.Contains("gone: resource group credprox-m46-aca", run.Out, StringComparison.Ordinal);
        Assert.DoesNotContain("SKIPPED:", run.Out, StringComparison.Ordinal);
        Assert.False(Directory.Exists(_scratch), "destroy removes the scratch handoff");
    }

    [Fact]
    public void Destroy_SoftDeletedVault_NamesTheRecoveryPath()
    {
        var run = Run("destroy", new() { ["STUB_LISTDELETED"] = "1" });
        Assert.True(run.Exit == 0, $"soft-deleted vault is recoverable, not a destroy failure: {run.Err}");
        Assert.Contains("deleted but SOFT-DELETED (purge refused - apply will RECOVER it)", run.Out, StringComparison.Ordinal);
    }

    [Fact]
    public void Destroy_AcrSlowToDelete_ButGroupGone_ExitsZero()
    {
        // Live finding (2026-11-22): registry deletion outlasts its poll, but the
        // resource-group delete removes it. A slow in-group resource is not a
        // leftover; the group-gone read-back is the verdict.
        var run = Run("destroy", new() { ["STUB_ACR_LEFT"] = "1" });
        Assert.True(run.Exit == 0, $"a slow registry inside a deleted group is not a leftover: {run.Out}");
        Assert.Contains("not yet gone: credproxm46reg", run.Out, StringComparison.Ordinal);
        Assert.Contains("gone: resource group credprox-m46-aca", run.Out, StringComparison.Ordinal);
    }

    [Fact]
    public void Destroy_RoleAssignmentLeft_ExitsOne()
    {
        // both run identities are gone but their assignments still resolve:
        // the row's zero-assignments bar flips the exit code
        var run = Run("destroy", new() { ["STUB_ROLE_LEFT"] = "1" });
        Assert.Equal(1, run.Exit);
        Assert.Contains("STILL PRESENT: a role assignment for a run identity", run.Out, StringComparison.Ordinal);
    }

    [Fact]
    public void Destroy_ResourceGroupStillExists_ExitsOne()
    {
        var run = Run("destroy", new() { ["STUB_RG_EXISTS"] = "true" });
        Assert.Equal(1, run.Exit);
        Assert.Contains("STILL PRESENT: resource group credprox-m46-aca", run.Out, StringComparison.Ordinal);
    }

    [Fact]
    public void Destroy_PrincipalsAlreadyGone_SaysSkippedNotChecked()
    {
        // Re-run after a partial cleanup: both identities are already deleted, so
        // the principal queries resolve empty and both role-assignment loops check
        // nothing. That must print as SKIPPED twice and still exit 0 (destroy is
        // the exit-path verb and stays idempotent) - and it must NOT print the
        // "gone" line that only a principal-backed read-back may claim.
        var run = Run("destroy", new() { ["STUB_PRIN"] = "0" });
        Assert.True(run.Exit == 0, $"a destroy re-run with the identities already gone is a clean re-run: exit={run.Exit} err={run.Err}");
        // per-principal echoes: 2 identities at each of the two sites
        Assert.Equal(2, CountLines(run.Out, "SKIPPED: pre-group role-assignment read-back"));
        Assert.Equal(2, CountLines(run.Out, "SKIPPED: post-group role-assignment check"));
        Assert.DoesNotContain("role assignments for a run identity", run.Out, StringComparison.Ordinal);
    }

    [Fact]
    public void Destroy_OnePrincipalGone_SkipsItAndReadsBackTheOther()
    {
        // Half-pair: one identity already deleted, the other still there. The
        // unresolved one prints SKIPPED at both sites; the survivor still earns
        // its two "gone" lines by actually being queried - one silent continue
        // for a missing principal must never let the survivor's line stand in
        // for a check that never ran.
        var run = Run("destroy", new() { ["STUB_PRIN"] = "half" });
        Assert.True(run.Exit == 0, $"a half-clean destroy is clean for what exists: exit={run.Exit} err={run.Err}");
        Assert.Equal(1, CountLines(run.Out, "SKIPPED: pre-group role-assignment read-back"));
        Assert.Equal(1, CountLines(run.Out, "SKIPPED: post-group role-assignment check"));
        Assert.Equal(2, CountLines(run.Out, "gone: role assignments for a run identity"));
    }

    [Fact]
    public void RunnerSkipAwareSummary_CountsInsteadOfQuietGrep()
    {
        // live-run.sh runs under pipefail: tail | grep -q can return 141 when the
        // quiet grep exits early and tail dies on SIGPIPE - the if would take the
        // else branch and print "read-back clean" on a log that DOES hold the
        // anchor (measured 5/5 by the checker on a fat log). aca_destroy cannot be
        // exec'd without a full stubbed live leg, so this pins the shape textually,
        // both polarities: the count reader present, the quiet grep gone.
        var runner = File.ReadAllText(Path.Combine(Path.GetDirectoryName(ScriptPath)!, "live-run.sh"));
        Assert.Contains("grep -c 'SKIPPED: pre-group role-assignment read-back'", runner, StringComparison.Ordinal);
        Assert.DoesNotContain("grep -q \"SKIPPED:", runner, StringComparison.Ordinal);
    }

    private static int CountLines(string haystack, string needle)
    {
        return Array.FindAll(haystack.Split('\n'), line => line.Contains(needle, StringComparison.Ordinal)).Length;
    }

    private sealed record ScriptRun(int Exit, string Out, string Err, string Log);

    private ScriptRun Run(string verb, Dictionary<string, string>? stubEnv = null, bool withAz = true)
    {
        var logPath = Path.Combine(Path.GetTempPath(), $"credprox-m46-aca-azlog-{Guid.NewGuid():N}.log");
        var psi = new ProcessStartInfo
        {
            FileName = "/bin/bash",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add(ScriptPath);
        psi.ArgumentList.Add(verb);
        // withAz: the stub az (+ stub docker) lead so they shadow the machine's
        // real binaries; the system dirs stay behind them for the script's own
        // tools (openssl, sha256sum, sed, grep, seq, envsubst, mktemp).
        psi.Environment["PATH"] = withAz ? _stubBin + ":/usr/bin:/bin" : "/credprox-m46-no-az-here";
        psi.Environment["CREDPROX_M46_ACA_SCRATCH"] = _scratch;
        psi.Environment["STUB_AZ_LOG"] = logPath;
        // the offline poll knobs: every waiting loop in the script is bounded
        // and shape-tested at seconds instead of the live minutes (the SHAPES
        // - poll-to-gone, RG poll, bounded verify wait - are identical)
        psi.Environment["CREDPROX_M46_ACA_POLL_S"] = "1";
        psi.Environment["CREDPROX_M46_ACA_POLL_N"] = "2";
        psi.Environment["CREDPROX_M46_ACA_POLL_RG_N"] = "2";
        psi.Environment["CREDPROX_M46_ACA_VERIFY_POLL_S"] = "0";
        psi.Environment["CREDPROX_M46_ACA_VERIFY_N"] = "2";
        // EVERY stub arm pinned to its happy default - an arm the script fails
        // to invoke shows up as the stub's loud unmatched-invocation error
        psi.Environment["STUB_AZ_SIGNED_IN"] = "1";
        psi.Environment["STUB_EXT"] = "1";
        psi.Environment["STUB_ROLE_OK"] = "1";
        psi.Environment["STUB_VAULT"] = "1";
        psi.Environment["STUB_ACR"] = "1";
        psi.Environment["STUB_DIGEST"] = "1";
        psi.Environment["STUB_APP_EXISTS"] = "0";
        psi.Environment["STUB_JOB_EXISTS"] = "0";
        psi.Environment["STUB_KUBELET"] = "true";
        psi.Environment["STUB_ID_COUNT"] = "2";
        psi.Environment["STUB_STAMP"] = AcaDigestHead;
        psi.Environment["STUB_STATUS"] = "Succeeded";
        psi.Environment["STUB_LOGS"] = "ok";
        psi.Environment["STUB_START"] = "ok";
        psi.Environment["STUB_LISTDELETED"] = "0";
        psi.Environment["STUB_ID_LEFT"] = "0";
        psi.Environment["STUB_ROLE_LEFT"] = "0";
        psi.Environment["STUB_PRIN"] = "1";
        psi.Environment["STUB_RG_EXISTS"] = "false";
        psi.Environment["STUB_ACR_LEFT"] = "0";
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
        Assert.True(process.WaitForExit(120_000), "the script did not exit within 120 s");
        var log = File.Exists(logPath) ? File.ReadAllText(logPath) : string.Empty;
        File.Delete(logPath);
        File.Delete(logPath + ".app");
        return new ScriptRun(process.ExitCode, stdout.Result, stderr.Result, log);
    }

    // Walk up from this assembly's bin folder to the repository root, then into
    // scripts/ (same locating discipline as the other scaffold cells).
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
        var script = Path.Combine(repoRoot, "scripts", "live-m46-aca.sh");
        if (!File.Exists(script))
        {
            throw new InvalidOperationException($"the lifecycle script is not where the test expects it: {script}");
        }

        return script;
    }

    // Canned az answers keyed off the verb line and the display names; env
    // switches drive the failure arms. Every arm is reachable by a cell above -
    // an az call the script makes but this stub does not know exits 3 loudly.
    // The canned GUIDs are fixture constants; the real script resolves ids live.
    // INTERNAL (not private): RunnerRunCreatedScanTests execs the REAL live-run.sh
    // against this exact stub rather than carrying a second copy that could drift
    // from the verbs' shapes (the GraphAppScriptTests precedent).
    internal const string StubAz = """
        #!/usr/bin/env bash
        if [ -n "${STUB_AZ_LOG:-}" ]; then printf '%s\n' "$*" >> "$STUB_AZ_LOG"; fi
        all="$*"
        case "$all" in
            "account get-access-token"*)
                if [ "${STUB_AZ_SIGNED_IN:-1}" = "0" ]; then echo "Please run 'az login'" >&2; exit 1; fi
                # honour -o none like the real CLI does: the script's gate
                # captures stdout, so ANY echo there reads as a failed gate
                case "$all" in
                    *"-o none"*) exit 0;;
                    *) echo '{"accessToken":"stub-token"}'; exit 0;;
                esac;;
            "containerapp -h"*)
                if [ "${STUB_EXT:-1}" = "0" ]; then exit 2; fi
                echo "Group 'az containerapp'."; exit 0;;
            "group create"*) exit 0;;
            "group delete"*) exit 0;;
            "group exists"*) printf '%s\n' "${STUB_RG_EXISTS:-false}"; exit 0;;
            "ad signed-in-user show"*) printf '%s\n' "11111111-1111-1111-1111-111111111111"; exit 0;;
            # (the script's single quotes die at its own word-splitting: $*
            # shows the display names unquoted, exactly as matched here)
            "role definition list --name Key Vault Secrets Officer"*)
                if [ "${STUB_ROLE_OK:-1}" = "0" ]; then exit 0; fi
                printf '%s\n' "22222222-2222-2222-2222-222222222222"; exit 0;;
            "role definition list --name Key Vault Secrets User"*)
                if [ "${STUB_ROLE_OK:-1}" = "0" ]; then exit 0; fi
                printf '%s\n' "33333333-3333-3333-3333-333333333333"; exit 0;;
            "role definition list --name AcrPull"*)
                if [ "${STUB_ROLE_OK:-1}" = "0" ]; then exit 0; fi
                printf '%s\n' "44444444-4444-4444-4444-444444444444"; exit 0;;
            "deployment group create"*) exit 0;;
            "keyvault show"*)
                if [ "${STUB_VAULT:-1}" = "0" ]; then exit 1; fi
                case "$all" in
                    *vaultUri*) echo "https://credprox-m46-kv.vault.azure.net/";;
                esac
                exit 0;;
            "keyvault secret set"*) exit 0;;
            "keyvault secret list"*)
                # the LOW-1 plant door: this is the ONE post-material az call whose
                # stderr is not suppressed (live-m46-aca.sh runs it inside the
                # material echo, no 2>/dev/null), so a plant here reaches the runner
                # log through the apply tee; every destroy read-back runs with
                # 2>/dev/null and cannot carry one. The handoff file holds THIS run's
                # minted values (openssl rand under the sandbox PATH), so the plant is
                # the real secret, not a preset string:
                if [ "${STUB_PLANT_HANDOFF:-0}" = "1" ] && [ -n "${CREDPROX_M46_ACA_SCRATCH:-}" ]; then
                    cat "$CREDPROX_M46_ACA_SCRATCH/aca-secrets.env" >&2
                fi
                printf '%s\n' "3"; exit 0;;
            "keyvault delete"*) exit 0;;
            "keyvault purge"*) exit 0;;
            "keyvault list-deleted"*) printf '%s\n' "${STUB_LISTDELETED:-0}"; exit 0;;
            "resource list"*) printf '%s\n' "7"; exit 0;;
            "resource show"*)
                case "$all" in
                    *"--query id -o"*)
                        printf '%s\n' "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/credprox-m46-aca/providers/Microsoft.App/managedEnvironments/credprox-m46-env"
                        exit 0;;
                    *"--query location -o"*) printf '%s\n' "eastus"; exit 0;;
                    *credproxm46reg*)
                        if [ "${STUB_ACR_LEFT:-0}" = "1" ]; then exit 0; fi
                        exit 1;;   # gone (the poll loop ends)
                    *) exit 1;;    # gone by default
                esac;;
            "resource delete"*) exit 0;;
            "acr login"*) exit 0;;
            "acr show"*)
                if [ "${STUB_ACR:-1}" = "0" ]; then exit 1; fi
                printf '%s\n' "credproxm46reg.azurecr.io"; exit 0;;
            "acr repository show"*)
                if [ "${STUB_DIGEST:-1}" = "0" ]; then exit 0; fi   # empty digest = not landed
                case "$all" in
                    *credprox-m46-aca:latest*)
                        printf '%s\n' "sha256:aaaaaaaaaaaa1111111111111111111111111111111111111111111111111111";;
                    *credprox-m46-stub:latest*)
                        printf '%s\n' "sha256:bbbbbbbbbbbb2222222222222222222222222222222222222222222222222222";;
                    *credprox-m46-harness:latest*)
                        printf '%s\n' "sha256:cccccccccccc3333333333333333333333333333333333333333333333333333";;
                    *) echo "stub az: repository show for unknown image" >&2; exit 3;;
                esac
                exit 0;;
            "acr delete"*) exit 0;;
            "identity show"*)
                case "$all" in
                    *principalId*)
                        # STUB_PRIN=0: both identities already gone, principal query
                        # answers empty; STUB_PRIN=half: only the kubelet identity is
                        # gone (the half-pair shape - partial cleanup of one identity)
                        if [ "${STUB_PRIN:-1}" = "0" ]; then printf '%s\n' ""; exit 0; fi
                        if [ "${STUB_PRIN:-1}" = "half" ]; then
                            case "$all" in
                                *credprox-m46-kubelet*) printf '%s\n' ""; exit 0;;
                            esac
                        fi
                        case "$all" in
                            *credprox-m46-kubelet*) printf '%s\n' "66666666-6666-6666-6666-666666666666";;
                            *)                      printf '%s\n' "55555555-5555-5555-5555-555555555555";;
                        esac;;
                    *clientId*) printf '%s\n' "77777777-0000-0000-0000-000000000001";;
                    *)
                        case "$all" in
                            *credprox-m46-kubelet*)
                                printf '%s\n' "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/credprox-m46-aca/providers/Microsoft.ManagedIdentity/userAssignedIdentities/credprox-m46-kubelet";;
                            *)
                                printf '%s\n' "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/credprox-m46-aca/providers/Microsoft.ManagedIdentity/userAssignedIdentities/credprox-m46-uai";;
                        esac;;
                esac
                exit 0;;
            "identity delete"*) exit 0;;
            "identity list"*) printf '%s\n' "${STUB_ID_LEFT:-0}"; exit 0;;
            "role assignment list"*) printf '%s\n' "${STUB_ROLE_LEFT:-0}"; exit 0;;
            "containerapp job start"*)
                case "${STUB_START:-ok}" in
                    fail) exit 1;;
                    empty) echo ""; exit 0;;
                    *) printf '%s\n' "stub-exec-1"; exit 0;;
                esac;;
            "containerapp job execution list"*) printf '%s\n' "stub-exec-1"; exit 0;;
            "containerapp job execution show"*) printf '%s\n' "${STUB_STATUS:-Succeeded}"; exit 0;;
            "containerapp job logs show"*)
                printf '%s\n' "2026-11-22T00:00:00Z stdout F acacheck UTC 2026-11-22T00:00:00Z build aaaaaaaaaaaa"
                printf '%s\n' "2026-11-22T00:00:01Z stdout F C1 PASS health unauthenticated"
                if [ "${STUB_LOGS:-ok}" = "fail" ]; then
                    printf '%s\n' "2026-11-22T00:00:02Z stdout F C2 FAIL caller-key call reaches the vendor, scrubbed for the caller status=401 body=[redacted-shape]"
                else
                    printf '%s\n' "2026-11-22T00:00:02Z stdout F C2 PASS caller-key call reaches the vendor, scrubbed for the caller"
                fi
                printf '%s\n' "2026-11-22T00:00:03Z stdout F C3 PASS no caller key refused 401"
                if [ "${STUB_LOGS:-ok}" = "fail" ]; then
                    printf '%s\n' "2026-11-22T00:00:04Z stdout F ACACHECK FAILED"
                else
                    printf '%s\n' "2026-11-22T00:00:04Z stdout F ACACHECK OK"
                fi
                exit 0;;
            "containerapp job show"*)
                case "$all" in
                    *identity.type*) printf '%s\n' "UserAssigned";;
                    *ends_with*) printf '%s\n' "${STUB_KUBELET:-true}";;
                    *length*) printf '%s\n' "${STUB_ID_COUNT:-2}";;
                    *) [ "${STUB_JOB_EXISTS:-0}" = "1" ] && exit 0 || exit 1;;
                esac
                exit 0;;
            "containerapp job create"*) exit 0;;
            "containerapp job update"*) exit 0;;
            "containerapp job identity assign"*) exit 0;;
            "containerapp show"*)
                case "$all" in
                    *provisioningState*) printf '%s\n' "Succeeded";;
                    *identity.type*) printf '%s\n' "UserAssigned";;
                    *ends_with*) printf '%s\n' "${STUB_KUBELET:-true}";;
                    *length*) printf '%s\n' "${STUB_ID_COUNT:-2}";;
                    *DEPLOY_IMAGE_DIGEST*) printf '%s\n' "${STUB_STAMP:-aaaaaaaaaaaa}";;
                    *ingress.fqdn*) printf '%s\n' "https://credprox-m46-app.internal.eastus.azurecontainerapps.io";;
                    *) { [ "${STUB_APP_EXISTS:-0}" = "1" ] || [ -e "$STUB_AZ_LOG.app" ]; } && exit 0 || exit 1;;
                esac
                exit 0;;
            "containerapp create"*)
                # live finding 2026-11-22: a refused spec creates nothing, so
                # the app exists only after a create that succeeded
                [ "${STUB_CREATE_REFUSED:-0}" = "1" ] && { echo "ERROR: Invalid YAML provided." >&2; exit 1; }
                : > "$STUB_AZ_LOG.app"; exit 0;;
            "containerapp update"*) exit 0;;
            "containerapp identity assign"*) exit 0;;
            "containerapp revision list"*)
                case "$all" in
                    *healthState*) printf '%s\t%s\t%s\t%s\n' "credprox-m46-app--g1" "Unhealthy" "Failed" "0";;
                    *) printf '%s\n' "credprox-m46-app--g1";;
                esac
                exit 0;;
            "containerapp logs show"*)
                case "$all" in
                    *"--type console"*) printf '%s\n' "stub proxy console: startup failed";;
                    *"--type system"*) printf '%s\n' "stub system event: container crashing";;
                esac
                exit 0;;
            *) echo "stub az: unmatched invocation: $all" >&2; exit 3;;
        esac
        """;

    // Stub docker: logs the call (through the SAME log file, so a cell can
    // count builds and pushes) and succeeds. No image is ever built offline.
    internal const string StubDocker = """
        #!/usr/bin/env bash
        if [ -n "${STUB_AZ_LOG:-}" ]; then printf 'docker %s\n' "$*" >> "$STUB_AZ_LOG"; fi
        exit 0
        """;
}
