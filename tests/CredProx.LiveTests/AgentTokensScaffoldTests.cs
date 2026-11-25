using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using Xunit;

namespace CredProx.LiveTests;

// The AgentTokens vendor's machine-local contract, proven offline against
// planted files in the temp directory (same shape as the graph contract cells).
[Trait("Layer", "Offline")]
public sealed class AgentTokensEnvContractTests : IDisposable
{
    private readonly string _tempPath = Path.Combine(
        Path.GetTempPath(),
        $"credprox-live-agenttokens-{Guid.NewGuid():N}.env");

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
        var absent = LiveEnv.Probe(AgentTokensEnv.Vendor, AgentTokensEnv.RequiredKeys, _tempPath + ".absent");
        Assert.False(absent.Available);
        Assert.Contains("~/.config/credprox-live/live.env", absent.SkipReason, StringComparison.Ordinal);
        Assert.Contains("TENANT_ID", absent.SkipReason, StringComparison.Ordinal);

        File.WriteAllLines(_tempPath, new[] { "TENANT_ID=00000000-0000-0000-0000-000000000000" });
        File.SetUnixFileMode(
            _tempPath,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead); // 644
        var loose = LiveEnv.Probe(AgentTokensEnv.Vendor, AgentTokensEnv.RequiredKeys, _tempPath);
        Assert.False(loose.Available);
        Assert.Contains("mode 644, must be exactly 600", string.Join("; ", loose.Problems), StringComparison.Ordinal);

        File.SetUnixFileMode(_tempPath, UnixFileMode.UserRead | UnixFileMode.UserWrite); // 600
        var probe = LiveEnv.Probe(AgentTokensEnv.Vendor, AgentTokensEnv.RequiredKeys, _tempPath);
        Assert.True(probe.Available, string.Join("; ", probe.Problems));
        Assert.Equal("00000000-0000-0000-0000-000000000000", probe.Values["TENANT_ID"]);
    }

    [Fact]
    public void ValueProblems_NameBadShapesWithoutEchoingValues()
    {
        var domain = AgentTokensEnv.ValueProblems(new Dictionary<string, string>
        {
            ["TENANT_ID"] = "contoso.onmicrosoft.com",
        });
        Assert.Single(domain);
        Assert.Contains("TENANT_ID", domain[0], StringComparison.Ordinal);
        Assert.DoesNotContain("contoso", domain[0], StringComparison.Ordinal);

        var good = AgentTokensEnv.ValueProblems(new Dictionary<string, string>
        {
            ["TENANT_ID"] = "00000000-0000-0000-0000-000000000000",
        });
        Assert.Empty(good);
    }
}

// The offline contract for scripts/live-agenttokens-app.sh, run against a stub
// az shadowed at the front of PATH — nothing here can touch a tenant. The claims
// proven: the destroy read-back over ALL THREE display names decides the exit
// code on both leftover shapes; create writes exactly the five scratch handoff
// files at mode 600 and never echoes either minted secret; the create-side
// read-backs (identifier EXACTLY api://<its own appId>, role values EXACTLY the
// sorted SET docs-read + model-call in any order, both assignments present) fail
// loudly when the canned API output says otherwise —
// including the exact-audience shape the tenant policy made load-bearing; and
// both sign-in gates die before any write verb.
[Trait("Layer", "Offline")]
public sealed class AgentTokensScriptTests : IDisposable
{
    private const string CanariedMappedSecret = "canary-secret-mapped-do-not-echo";
    private const string CanariedUnmappedSecret = "canary-secret-unmapped-do-not-echo";
    private const string StubAppId1 = "aaaaaaaa-0000-0000-0000-000000000001";
    private const string StubAppId2 = "aaaaaaaa-0000-0000-0000-000000000002";
    private const string StubAppId3 = "aaaaaaaa-0000-0000-0000-000000000003";

    private static readonly string ScriptPath = LocateScript();
    private readonly string _stubBin;
    private readonly string _scratch;

    public AgentTokensScriptTests()
    {
        _stubBin = Path.Combine(Path.GetTempPath(), $"credprox-m46-at-stubbin-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_stubBin);
        var azStub = Path.Combine(_stubBin, "az");
        File.WriteAllText(azStub, StubAz);
        File.SetUnixFileMode(
            azStub,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
            | UnixFileMode.GroupRead | UnixFileMode.GroupExecute
            | UnixFileMode.OtherRead | UnixFileMode.OtherExecute); // 755
        _scratch = Path.Combine(Path.GetTempPath(), $"credprox-m46-at-scratch-{Guid.NewGuid():N}");
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
        Assert.Contains("OK live-agenttokens-app destroy", run.Out, StringComparison.Ordinal);
    }

    [Fact]
    public void Destroy_AppStillListed_ExitsOneAndNamesTheReadback()
    {
        var run = Run("destroy", new() { ["STUB_APP_LEFT"] = "1" });
        Assert.Equal(1, run.Exit);
        Assert.Contains("DESTROY-READBACK FAILED: apps left=3", run.Err, StringComparison.Ordinal);
        Assert.DoesNotContain("OK live-agenttokens-app destroy", run.Out, StringComparison.Ordinal);
    }

    [Fact]
    public void Destroy_ServicePrincipalLeft_ExitsOne()
    {
        // apps are gone (deletes "succeeded") but every name still shows an SP:
        var run = Run("destroy", new() { ["STUB_SP_LEFT"] = "1" });
        Assert.Equal(1, run.Exit);
        Assert.Contains("service-principals left=3", run.Err, StringComparison.Ordinal);
    }

    [Fact]
    public void Destroy_RoleValueLeft_ExitsOne()
    {
        // a half-deleted registration still surfaces its app-role values; the
        // destroy read-back now covers them per name, so one leftover role per
        // name lands as three and fails the run:
        var run = Run("destroy", new() { ["STUB_ROLE_LEFT"] = "1" });
        Assert.Equal(1, run.Exit);
        Assert.Contains("app-role values left=3", run.Err, StringComparison.Ordinal);
        Assert.DoesNotContain("OK live-agenttokens-app destroy", run.Out, StringComparison.Ordinal);
    }

    [Fact]
    public void Create_HappyPath_WritesFiveHandoffFilesAndNeverEchoesSecrets()
    {
        var run = Run("create");
        Assert.True(run.Exit == 0, $"create must exit 0: exit={run.Exit} err={run.Err}");
        Assert.Contains("OK live-agenttokens-app create", run.Out, StringComparison.Ordinal);
        Assert.DoesNotContain(CanariedMappedSecret, run.Out + run.Err + run.Log, StringComparison.Ordinal);
        Assert.DoesNotContain(CanariedUnmappedSecret, run.Out + run.Err + run.Log, StringComparison.Ordinal);

        var expected = new Dictionary<string, string>
        {
            ["app2-id.txt"] = StubAppId2,
            ["app2-secret.txt"] = CanariedMappedSecret,
            ["app3-id.txt"] = StubAppId3,
            ["app3-secret.txt"] = CanariedUnmappedSecret,
            // the audience the live cell must use, handed over like the secrets:
            ["resource-audience.txt"] = StubAppId1,
        };
        foreach (var (name, value) in expected)
        {
            var path = Path.Combine(_scratch, name);
            Assert.Equal(value, File.ReadAllText(path).Trim());
            Assert.Equal(Convert.ToInt32("600", 8), (int)File.GetUnixFileMode(path));
        }

        Assert.Equal(Convert.ToInt32("700", 8), (int)File.GetUnixFileMode(_scratch));

        // The three apps stayed three distinct principals end to end: the role
        // PATCH and both assignments reference the RESOURCE app/service principal
        // (the first canned ids), never a client's — a collapsed id would mean
        // the script is granting the role against the wrong resource.
        Assert.Contains("applications/bbbbbbbb-0000-0000-0000-000000000001", run.Log, StringComparison.Ordinal);
        Assert.Contains("ad sp create --id aaaaaaaa-0000-0000-0000-000000000001", run.Log, StringComparison.Ordinal);
        Assert.Contains("\"resourceId\":\"cccccccc-0000-0000-0000-000000000001\"", run.Log, StringComparison.Ordinal);
        Assert.DoesNotContain("applications/bbbbbbbb-0000-0000-0000-000000000002", run.Log, StringComparison.Ordinal);
        Assert.DoesNotContain("applications/bbbbbbbb-0000-0000-0000-000000000003", run.Log, StringComparison.Ordinal);

        // the fixture handoff reads exactly these five:
        var apps = AgentTokensFixture.ReadScratchApps(_scratch);
        Assert.Equal(StubAppId2, apps.MappedId);
        Assert.Equal(StubAppId3, apps.UnmappedId);
        // and the live cell's audience comes from the handoff: the API's client id,
        // because v2 access tokens carry the client id as aud:
        Assert.Equal(StubAppId1, AgentTokensFixture.ReadScratchAudience(_scratch));
        // the resource create never passed a fixed identifier, and the PATCH
        // that set the audience carried the resource app's own appId:
        Assert.DoesNotContain("--identifier-uris", run.Log, StringComparison.Ordinal);
        Assert.Contains($"api://{StubAppId1}", run.Log, StringComparison.Ordinal);
    }

    [Fact]
    public void Create_IdentifierReadBackFails_ExitsOne()
    {
        // the PATCH "succeeded" but the canned app shows no api:// identifier —
        // the half-created state the create-side read-back exists to catch:
        var run = Run("create", new() { ["STUB_URI"] = "0" });
        Assert.Equal(1, run.Exit);
        Assert.Contains("expected the api:// identifier", run.Err, StringComparison.Ordinal);
    }

    [Fact]
    public void Create_AudienceIsNotOwnAppId_ExitsOne()
    {
        // one identifier present but NOT api://<its own appId> — the exact-value
        // read-back is what catches a leftover fixed-name audience that the
        // count check alone would wave through:
        var run = Run("create", new() { ["STUB_AUD"] = "api://some-fixed-name" });
        Assert.Equal(1, run.Exit);
        Assert.Contains("not its own api://<appId>", run.Err, StringComparison.Ordinal);
        // a run that failed the audience read-back must not hand over an audience:
        Assert.False(
            File.Exists(Path.Combine(_scratch, "resource-audience.txt")),
            "the audience handoff is written only after the read-backs pass");
    }

    [Fact]
    public void Create_HandoffAlreadyPresent_RefusesBeforeMintingAnything()
    {
        // The shared scratch carries one az-vendor leg's handoff at a time. A
        // handoff already here means another leg created (or is mid-create of)
        // the same three apps, so create must refuse naming the scratch, mint
        // nothing, leave the planted handoff untouched and never echo what is
        // inside it. The handoff is planted whole - the same shape a successful
        // create leaves - so no app is minted for the arm to be reachable.
        Directory.CreateDirectory(_scratch);
        var audience = Path.Combine(_scratch, "resource-audience.txt");
        var sentinel = "sentinel-handoff-content-00000000-0000-0000-0000-000000000000";
        File.WriteAllText(audience, sentinel);
        var run = Run("create");
        Assert.Equal(1, run.Exit);
        Assert.Contains("a run-created handoff already exists", run.Err, StringComparison.Ordinal);
        Assert.Contains(_scratch, run.Err, StringComparison.Ordinal);
        // the refusal names the scratch, never the handoff contents:
        Assert.DoesNotContain(sentinel, run.Out + run.Err + run.Log, StringComparison.Ordinal);
        Assert.Equal(sentinel, File.ReadAllText(audience));
        // and it dies before minting: no app was created against the canned tenant:
        Assert.DoesNotContain("ad app create", run.Log, StringComparison.Ordinal);
    }

    [Fact]
    public void Create_HappyPath_IdentifierPatchCarriesV2RequestedVersion()
    {
        // the audience PATCH must request v2 tokens in the same body that sets
        // api://<appId>: left unset, Entra keeps minting v1 tokens and the
        // sample's v2 authority refuses them (the first live run died here).
        // The canned az refuses that shape exactly as Entra did; this cell
        // proves the script sends the right body rather than tripping the arm:
        var run = Run("create");
        Assert.True(run.Exit == 0, $"create must exit 0: exit={run.Exit} err={run.Err}");
        var patch = Array.FindAll(
            run.Log.Split('\n'),
            l => l.Contains("--method PATCH", StringComparison.Ordinal)
                 && l.Contains("identifierUris", StringComparison.Ordinal));
        Assert.Single(patch);
        Assert.Contains($"api://{StubAppId1}", patch[0], StringComparison.Ordinal);
        Assert.Contains("\"api\":{\"requestedAccessTokenVersion\":2}", patch[0], StringComparison.Ordinal);
    }

    [Fact]
    public void Create_HappyPath_AppRolesPatchCarriesDescription()
    {
        // Entra requires a non-empty description on every app role (measured
        // live 2026-11-22); the canned az refuses the shapeless role body, so
        // a green create plus this log pin together prove the script sends it:
        var run = Run("create");
        Assert.True(run.Exit == 0, $"create must exit 0: exit={run.Exit} err={run.Err}");
        var patch = Array.FindAll(
            run.Log.Split('\n'),
            l => l.Contains("--method PATCH", StringComparison.Ordinal)
                 && l.Contains("appRoles", StringComparison.Ordinal));
        Assert.Single(patch);
        Assert.Contains("\"description\":\"Read docs", patch[0], StringComparison.Ordinal);
    }

    [Fact]
    public void StubAz_RefusesTheShapesEntraRefused()
    {
        // the three new refuse arms must actually be reachable and must still
        // accept the good bodies — an arm that refuses everything, or one a
        // pattern typo made dead, would make the happy-path pins above hollow:
        var az = Path.Combine(_stubBin, "az");
        var goodIdentifier =
            $"{{\"identifierUris\":[\"api://{StubAppId1}\"],\"api\":{{\"requestedAccessTokenVersion\":2}}}}";
        var noVersion = $"{{\"identifierUris\":[\"api://{StubAppId1}\"]}}";
        var wrongAudience = "{\"identifierUris\":[\"api://some-fixed-name\"]}";
        var goodRoles = "{\"appRoles\":[{\"description\":\"Read docs through the CredProx live test\",\"value\":\"docs-read\"}]}";
        var noDescription = "{\"appRoles\":[{\"value\":\"docs-read\"}]}";
        var emptyDescription = "{\"appRoles\":[{\"description\":\"\",\"value\":\"docs-read\"}]}";

        Assert.Equal(0, RunAzStub(az, "rest", "--method", "PATCH", "--body", goodIdentifier).Exit);
        var missingVersion = RunAzStub(az, "rest", "--method", "PATCH", "--body", noVersion);
        Assert.Equal(3, missingVersion.Exit);
        Assert.Contains("without requestedAccessTokenVersion 2", missingVersion.Err, StringComparison.Ordinal);
        var fixedName = RunAzStub(az, "rest", "--method", "PATCH", "--body", wrongAudience);
        Assert.Equal(3, fixedName.Exit);
        Assert.Contains("without api://", fixedName.Err, StringComparison.Ordinal);
        Assert.Equal(0, RunAzStub(az, "rest", "--method", "PATCH", "--body", goodRoles).Exit);
        var missingDescription = RunAzStub(az, "rest", "--method", "PATCH", "--body", noDescription);
        Assert.Equal(3, missingDescription.Exit);
        Assert.Contains("without a description", missingDescription.Err, StringComparison.Ordinal);
        var emptyDescr = RunAzStub(az, "rest", "--method", "PATCH", "--body", emptyDescription);
        Assert.Equal(3, emptyDescr.Exit);
        Assert.Contains("empty description", emptyDescr.Err, StringComparison.Ordinal);
    }

    [Fact]
    public void Create_AssignmentReadBackFails_ExitsOne()
    {
        var run = Run("create", new() { ["STUB_ASSIGN"] = "0" });
        Assert.Equal(1, run.Exit);
        Assert.Contains("has no role assignment", run.Err, StringComparison.Ordinal);
    }

    [Fact]
    public void Create_UnmappedRoleReadBackFails_ExitsOne()
    {
        // asymmetric failure: the mapped SP carries both roles, the unmapped
        // one only one — both SPs must be pinned to the identical role set, or
        // the unmapped 401 stops being a pure caller-mapping proof:
        var run = Run("create", new() { ["STUB_ASSIGN_3"] = "1" });
        Assert.Equal(1, run.Exit);
        Assert.Contains("unmapped client SP has no role assignment for both roles", run.Err, StringComparison.Ordinal);
    }

    [Fact]
    public void Create_HappyPath_AppRolesPatchCarriesBothRoles()
    {
        // live run 2 died because the Entra app had only docs-read: the sample's
        // model route names model-call and refused the token with 403. One PATCH
        // must land BOTH roles, each with its own non-empty description:
        var run = Run("create");
        Assert.True(run.Exit == 0, $"create must exit 0: exit={run.Exit} err={run.Err}");
        var patch = Array.FindAll(
            run.Log.Split('\n'),
            l => l.Contains("--method PATCH", StringComparison.Ordinal)
                 && l.Contains("appRoles", StringComparison.Ordinal));
        Assert.Single(patch);
        Assert.Contains("\"value\":\"docs-read\"", patch[0], StringComparison.Ordinal);
        Assert.Contains("\"value\":\"model-call\"", patch[0], StringComparison.Ordinal);
        Assert.Contains("\"description\":\"Call the model through the CredProx live test\"", patch[0], StringComparison.Ordinal);
    }

    [Fact]
    public void Create_HappyPath_AssignsBothRolesToBothClientSPs()
    {
        // identical role sets on both client SPs (lead ruling): exactly two
        // assignment POSTs per client service principal, never a third; the
        // POST log lines name the client SP in the uri:
        var run = Run("create");
        Assert.True(run.Exit == 0, $"create must exit 0: exit={run.Exit} err={run.Err}");
        var lines = run.Log.Split('\n');
        var mapped = Array.FindAll(
            lines, l => l.Contains("--method POST", StringComparison.Ordinal)
                        && l.Contains("servicePrincipals/cccccccc-0000-0000-0000-000000000002/appRoleAssignments", StringComparison.Ordinal));
        var unmapped = Array.FindAll(
            lines, l => l.Contains("--method POST", StringComparison.Ordinal)
                        && l.Contains("servicePrincipals/cccccccc-0000-0000-0000-000000000003/appRoleAssignments", StringComparison.Ordinal));
        Assert.Equal(2, mapped.Length);
        Assert.Equal(2, unmapped.Length);
    }

    [Fact]
    public void Create_RoleValuesMissingModelCall_ExitsOne()
    {
        // the count read-back alone would wave through a swapped role value; the
        // exact-values check must name the role that is missing:
        var run = Run("create", new() { ["STUB_ROLE_VALUES"] = "docs-read" });
        Assert.Equal(1, run.Exit);
        Assert.Contains("not exactly docs-read model-call", run.Err, StringComparison.Ordinal);
        Assert.Contains("model-call", run.Err, StringComparison.Ordinal);
    }

    [Fact]
    public void Create_RoleValuesReversedOrder_Passes()
    {
        // live run 3 died in create because Graph returned the joined role values
        // reversed; the sorted set-compare must wave the same valid set through:
        var run = Run("create", new() { ["STUB_ROLE_VALUES"] = "model-call docs-read" });
        Assert.Equal(0, run.Exit);
    }

    [Fact]
    public void Create_RoleValuesDuplicate_ExitsOne()
    {
        // set-exactness, not membership: a doubled value must still be refused,
        // and the die line names what was actually found, order as Graph sent it:
        var run = Run("create", new() { ["STUB_ROLE_VALUES"] = "docs-read docs-read" });
        Assert.Equal(1, run.Exit);
        Assert.Contains("not exactly docs-read model-call", run.Err, StringComparison.Ordinal);
        Assert.Contains("found: docs-read docs-read", run.Err, StringComparison.Ordinal);
    }

    [Fact]
    public void Create_RoleValuesWrongValue_ExitsOne()
    {
        // the count stays 2 when only a value is wrong — the exact set is the
        // only read-back that catches it:
        var run = Run("create", new() { ["STUB_ROLE_VALUES"] = "docs-read model-cal" });
        Assert.Equal(1, run.Exit);
        Assert.Contains("not exactly docs-read model-call", run.Err, StringComparison.Ordinal);
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
    public void DryRun_PlanOnlyAndTouchesNothing()
    {
        var run = Run("--dry-run");
        Assert.True(run.Exit == 0, $"--dry-run must exit 0: exit={run.Exit} err={run.Err}");
        Assert.Contains("DRY-RUN", run.Out, StringComparison.Ordinal);
        Assert.DoesNotContain("ad app create", run.Log, StringComparison.Ordinal);
        Assert.DoesNotContain("ad app delete", run.Log, StringComparison.Ordinal);
        Assert.DoesNotContain("credential reset", run.Log, StringComparison.Ordinal);
        Assert.DoesNotContain("appRoleAssignments", run.Log, StringComparison.Ordinal);
        Assert.False(Directory.Exists(_scratch), "--dry-run must not create the scratch dir");
    }

    [Fact]
    public void UnknownVerb_PrintsUsageAndExitsTwo()
    {
        var run = Run("obliterate");
        Assert.Equal(2, run.Exit);
        Assert.Contains("usage: live-agenttokens-app.sh create|destroy|--dry-run", run.Err, StringComparison.Ordinal);
    }

    private sealed record ScriptRun(int Exit, string Out, string Err, string Log);

    private ScriptRun Run(string verb, Dictionary<string, string>? stubEnv = null, bool withAz = true)
    {
        var logPath = Path.Combine(Path.GetTempPath(), $"credprox-m46-at-azlog-{Guid.NewGuid():N}.log");
        var psi = new ProcessStartInfo
        {
            FileName = "/bin/bash",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add(ScriptPath);
        psi.ArgumentList.Add(verb);
        // withAz: the stub leads so it shadows the machine's real az; the system
        // dirs stay behind it for date and the stub's own env-bash shebang.
        psi.Environment["PATH"] = withAz ? _stubBin + ":/usr/bin:/bin" : "/credprox-m46-no-az-here";
        psi.Environment["CREDPROX_M46_SCRATCH"] = _scratch;
        psi.Environment["STUB_AZ_LOG"] = logPath;
        psi.Environment["STUB_AZ_SIGNED_IN"] = "1";
        psi.Environment["STUB_URI"] = "1";
        psi.Environment["STUB_AUD"] = $"api://{StubAppId1}";
        psi.Environment["STUB_ROLE"] = "2";
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

    // Drives the canned az directly (not through the script) so a refuse arm can
    // be shown reachable with a body the script itself never sends.
    private static (int Exit, string Err) RunAzStub(string azPath, params string[] args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = azPath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var arg in args)
        {
            psi.ArgumentList.Add(arg);
        }

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("the canned az did not start");
        var err = process.StandardError.ReadToEndAsync();
        Assert.True(process.WaitForExit(30_000), "the canned az did not exit within 30 s");
        return (process.ExitCode, err.Result);
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
        var script = Path.Combine(repoRoot, "scripts", "live-agenttokens-app.sh");
        if (!File.Exists(script))
        {
            throw new InvalidOperationException($"the lifecycle script is not where the test expects it: {script}");
        }

        return script;
    }

    // Canned az answers keyed off the verb line and the display names; env
    // switches drive the failure arms. The minted app-role ids are generated by
    // the script at run time, so the assignment read-back is canned as a COUNT
    // per service principal (STUB_ASSIGN_2 for the mapped SP, STUB_ASSIGN_3 for
    // the unmapped one; STUB_ASSIGN sets both), never as an id match. The happy
    // default is TWO assignments per SP — both client SPs carry both roles.
    // INTERNAL (not private): SecretPropagationClientTests in
    // SecretPropagationTests.cs execs live-run.sh against this exact stub
    // rather than carrying a second copy that could drift from the verbs'
    // shapes (same discipline as GraphAppScriptTests.StubAz).
    internal const string StubAz = """
        #!/usr/bin/env bash
        if [ -n "${STUB_AZ_LOG:-}" ]; then printf '%s\n' "$*" >> "$STUB_AZ_LOG"; fi
        RESID=aaaaaaaa-0000-0000-0000-000000000001
        ID2=aaaaaaaa-0000-0000-0000-000000000002
        ID3=aaaaaaaa-0000-0000-0000-000000000003
        all="$*"
        case "$all" in
            "account get-access-token"*)
                if [ "${STUB_AZ_SIGNED_IN:-1}" = "0" ]; then echo "Please run 'az login'" >&2; exit 1; fi
                echo '{"accessToken":"stub-token"}'; exit 0;;
            "ad app create"*"--identifier-uris"*)
                # Mirrors the tenant default protection policy measured live
                # 2026-11-22: newly added identifier URIs must contain a verified
                # domain, the tenant id, or the app id — a fixed api:// name dies.
                echo "stub az: tenant policy refuses the fixed identifier URI" >&2; exit 3;;
            "ad app create"*"agents-api"*)
                printf '%s\n%s\n' "$RESID" "bbbbbbbb-0000-0000-0000-000000000001"; exit 0;;
            "ad app create"*)
                case "$all" in
                    # "-mapped" with the hyphen: "unmapped" would also contain "mapped"
                    *"-mapped"*) printf '%s\n%s\n' "$ID2" "bbbbbbbb-0000-0000-0000-000000000002";;
                    *)           printf '%s\n%s\n' "$ID3" "bbbbbbbb-0000-0000-0000-000000000003";;
                esac
                exit 0;;
            "ad sp create"*"--query"*)
                case "$all" in
                    *"$RESID"*) printf '%s\n' "cccccccc-0000-0000-0000-000000000001";;
                    *"$ID2"*)   printf '%s\n' "cccccccc-0000-0000-0000-000000000002";;
                    *"$ID3"*)   printf '%s\n' "cccccccc-0000-0000-0000-000000000003";;
                    *) echo "stub az: sp create query for unknown app" >&2; exit 3;;
                esac
                exit 0;;
            "ad sp create"*) echo '{}'; exit 0;;
            "ad sp list"*"--display-name"*)
                printf '%s\n' "${STUB_SP_LEFT:-0}"; exit 0;;
            "ad sp list"*)
                case "$all" in
                    *"$ID2"*) printf '%s\n' "cccccccc-0000-0000-0000-000000000002";;
                    *"$ID3"*) printf '%s\n' "cccccccc-0000-0000-0000-000000000003";;
                    *) echo "stub az: sp list filter for unknown app" >&2; exit 3;;
                esac
                exit 0;;
            "rest --method PATCH"*identifierUris*api://$RESID*'"requestedAccessTokenVersion":2'*)
                # the audience PATCH must carry BOTH shapes Entra proved on the wire
                # 2026-11-22: api://<the resource appId> (tenant policy) AND
                # api.requestedAccessTokenVersion 2 — with the version unset Entra
                # keeps minting v1 tokens and the sample's v2 authority refuses
                # them, which is what killed the first live run:
                echo '{}'; exit 0;;
            "rest --method PATCH"*identifierUris*api://$RESID*)
                echo "stub az: identifierUris PATCH without requestedAccessTokenVersion 2" >&2; exit 3;;
            "rest --method PATCH"*identifierUris*)
                echo "stub az: identifierUris PATCH without api://\$RESID" >&2; exit 3;;
            "rest --method PATCH"*appRoles*'"description":""'*)
                # Entra requires a non-empty description on every app role
                # (measured live 2026-11-22: the role PATCH died without one) —
                # empty-value arm FIRST: it is also a substring of the presence
                # arm below:
                echo "stub az: appRoles PATCH with an empty description" >&2; exit 3;;
            "rest --method PATCH"*appRoles*'"description"'*)
                echo '{}'; exit 0;;
            "rest --method PATCH"*appRoles*)
                echo "stub az: appRoles PATCH without a description" >&2; exit 3;;
            "rest --method PATCH"*) echo '{}'; exit 0;;
            "rest --method POST"*) echo '{}'; exit 0;;
            "rest --method GET"*)
                case "$all" in
                    # per-SP assignment counts: both client SPs hold BOTH roles
                    # by default; STUB_ASSIGN still drives both for compat
                    *"cccccccc-0000-0000-0000-000000000002"*) printf '%s\n' "${STUB_ASSIGN_2:-${STUB_ASSIGN:-2}}";;
                    *"cccccccc-0000-0000-0000-000000000003"*) printf '%s\n' "${STUB_ASSIGN_3:-${STUB_ASSIGN:-2}}";;
                    *) printf '%s\n' "${STUB_ASSIGN:-2}";;
                esac
                exit 0;;
            "ad app credential reset"*)
                case "$all" in
                    *"$ID2"*) printf '%s\n' "canary-secret-mapped-do-not-echo";;
                    *"$ID3"*) printf '%s\n' "canary-secret-unmapped-do-not-echo";;
                    *) echo "stub az: credential reset for unknown app" >&2; exit 3;;
                esac
                exit 0;;
            "ad app show"*)
                case "$all" in
                    # join-arm FIRST: the join query also contains the word
                    # identifierUris, and the length arm below would swallow it;
                    # the "(" must stay quoted — bare ( in a case pattern is a
                    # bash syntax error (measured 2026-11-22)
                    *"join("*identifierUris*) printf '%s\n' "${STUB_AUD:-api://$RESID}"; exit 0;;
                    # join-arm for roles BEFORE the appRoles-count arm: the join
                    # query also contains the word appRoles, and the count arm
                    # would swallow it (same ordering rule as the identifier one)
                    # default is the REVERSED order (live run 3 proved Graph may
                    # return either) so the fixture and the assertion can never
                    # agree by construction:
                    *"join("*appRoles*) printf '%s\n' "${STUB_ROLE_VALUES:-model-call docs-read}"; exit 0;;
                    *identifierUris*) printf '%s\n' "${STUB_URI:-1}"; exit 0;;
                    *appRoles*) printf '%s\n' "${STUB_ROLE:-2}"; exit 0;;
                esac
                echo "stub az: unmatched app show query: $all" >&2; exit 3;;
            "ad app list"*)
                case "$all" in
                    # the destroy role-value read-back FIRST: its query contains
                    # both appRoles and length, and the count arm would swallow it
                    *"appRoles"*) printf '%s\n' "${STUB_ROLE_LEFT:-0}"; exit 0;;
                    *length*) printf '%s\n' "${STUB_APP_LEFT:-0}"; exit 0;;
                    *)
                        # the destroy phase's pre-delete list: live-agenttokens-app.sh
                        # captures only its stdout in the command substitution, so a
                        # plant on stderr passes through into the destroy's tee'd
                        # output and lands in the runner log AFTER the run's leg has
                        # already passed — only a scan that runs after the destroys
                        # sees it (the same door the graph stub carries):
                        if [ -n "${STUB_DESTROY_PLANT:-}" ]; then echo "$STUB_DESTROY_PLANT" >&2; fi
                        printf '%s\n' ""; exit 0;;
                esac;;
            "ad app delete"*) echo '{}'; exit 0;;
            *) echo "stub az: unmatched invocation: $all" >&2; exit 3;;
        esac
        """;
}

// The build graph the live leg depends on: the fixture execs the Agent dll as its
// own process, so the LiveTests project must BUILD it (live run 1 at 7dc7d0b died in
// the fixture ctor on a fresh worktree that had built LiveTests only).
[Trait("Layer", "Offline")]
public sealed class AgentTokensBuildGraphTests
{
    [Fact]
    public void LiveTestsProject_BuildsTheAgent_AsBuildOnlyReference()
    {
        // same bin-index discipline as LiveHosts.LocateBin / LocateScript: this
        // assembly's own path gives the repo root without depending on the test's
        // working directory (strip bin/<configuration>/<tfm>, then the project
        // and its folder).
        var parts = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar)
            .Split(Path.DirectorySeparatorChar);
        var binIndex = Array.IndexOf(parts, "bin");
        Assert.True(binIndex >= 3, $"unexpected test assembly location '{AppContext.BaseDirectory}'");
        var repoRoot = string.Join(Path.DirectorySeparatorChar, parts[..(binIndex - 2)]);
        var csproj = Path.Combine(repoRoot, "tests", "CredProx.LiveTests", "CredProx.LiveTests.csproj");
        var line = File.ReadLines(csproj)
            .Select(l => l.Trim().Replace('\\', '/'))
            .FirstOrDefault(l => l.Contains("samples/AgentTokens/Agent/Agent.csproj"));
        Assert.True(
            line is not null && line.Contains("ReferenceOutputAssembly=\"false\""),
            "building LiveTests must build the Agent or the live leg dies at the fixture in a fresh worktree");
    }

    // ---- Guard 1, self-witness plants (widened on the post-merge forward row; the skip
    // arms are proven by THIS file being in its own scan set). These lines carry the REAL
    // banned byte shape inside comment text and must stay GREEN: the first two are trimmed-
    // start // lines, the block body line below starts with *. If the skip rule ever breaks,
    // the tree scan names this very file and the pin goes red on its own explanation.
    // var bannedPlant = new AgentTokensFixture();
    // var bannedPlantToo = new AgentTokensFixture { };
    /*
     * var bannedPlantAlso = new AgentTokensFixture(); <- this block-body line starts with
     * * and is skipped by the same rule; deleting the filter turns it into the offender.
     */
    private static readonly Regex Guard1BannedConstruction =
        new(@"new\s+([A-Za-z][A-Za-z0-9_]*Fixture)\s*[(\{]", RegexOptions.None);

    // Anchored to the declaration position (line start after optional modifiers),
    // post-release item 8: the old word-boundary reading let `foreach (var record
    // in records)` capture "in" and a string containing `class FakeFixture` mint
    // a fake declared type — after which `new FakeFixture();` in that file was
    // exempt (measured in the Guard 1 verdict's extractor-precision leg).
    private static readonly Regex Guard1DeclaredType =
        new(@"^\s*(?:(?:public|private|internal|protected|static|sealed|abstract|partial)\s+)*(?:class|record)\s+([A-Za-z][A-Za-z0-9_]*)", RegexOptions.None);
    // Line-aligned structural view of one raw line for scope tracking: comment bytes
    // dropped (block state crosses lines; exact-three-quote raw bodies skipped under
    // the same rule the build-proof strip uses), string and char CONTENT blanked, so
    // only structure survives and no brace inside content can fake a scope. This is
    // deliberately NOT the strip — the strip KEEPS literal content because the launch
    // scans read it as data; here content is noise. MEASURED LIMIT, recorded not
    // chased: a multi-line verbatim @"" continuation line opens outside a string, so a
    // lone quote there would miscount scope — no scanned file carries that shape today.
    private static string Guard1Structural(string rawLine, ref bool inBlock, ref bool inRaw)
    {
        var code = new StringBuilder(rawLine.Length);
        var inString = false;
        for (var i = 0; i < rawLine.Length; i++)
        {
            var c = rawLine[i];
            if (inBlock)
            {
                if (c == '*' && i + 1 < rawLine.Length && rawLine[i + 1] == '/')
                {
                    inBlock = false;
                    i++;
                }

                continue;
            }

            if (!inString && c == '"' && i + 2 < rawLine.Length
                && rawLine[i + 1] == '"' && rawLine[i + 2] == '"'
                && !(i + 3 < rawLine.Length && rawLine[i + 3] == '"'))
            {
                inRaw = !inRaw;
                i += 2;
                continue;
            }

            if (inRaw)
            {
                continue;
            }

            if (c == '"')
            {
                inString = !inString;
                continue;
            }

            if (inString)
            {
                if (c == '\\')
                {
                    i++;
                }

                continue;
            }

            if (c == '\'')
            {
                i++;
                if (i < rawLine.Length && rawLine[i] == '\\')
                {
                    i++;
                }

                continue;
            }

            if (c == '/' && i + 1 < rawLine.Length)
            {
                if (rawLine[i + 1] == '/')
                {
                    break;
                }

                if (rawLine[i + 1] == '*')
                {
                    inBlock = true;
                    i++;
                    continue;
                }
            }

            code.Append(c);
        }

        return code.ToString();
    }

    // Skip rule, exactly the lead's ruling: a comment-LINE filter, not a comment STRIPPER.
    // Only lines whose trimmed-start text begins with // or * are skipped. A trailing
    // comment after code is still code, and a one-line /* */ mention starts with /* —
    // neither is skipped, so both shapes stay in the offender set by design.
    private static bool Guard1IsSkipped(string rawLine)
    {
        var t = rawLine.TrimStart();
        return t.StartsWith("//", StringComparison.Ordinal)
            || t.StartsWith("*", StringComparison.Ordinal);
    }

    // The fixture type a line constructs, or null. Comments are not stripped, only skipped.
    private static string? Guard1BannedType(string rawLine)
    {
        if (Guard1IsSkipped(rawLine))
        {
            return null;
        }

        var m = Guard1BannedConstruction.Match(rawLine);
        return m.Success ? m.Groups[1].Value : null;
    }

    // A construction is exempt ONLY inside the declaration of the type it constructs
    // — CLASS-granular since post-release item 8: the file-granular exemption left the
    // guard's own hazard untouched (a holder class cohabiting the fixture's file could
    // bind the port twice; measured in the Guard 1 verdict's cohabit leg). Never
    // file-name convention, so a holder in some other *Fixture.cs is still an offender.
    private static bool Guard1IsOffense(string rawLine, string? enclosingType)
    {
        var banned = Guard1BannedType(rawLine);
        return banned is not null && enclosingType != banned;
    }

    // A banned shape assembled at runtime, never written whole on any line of this file:
    // a contiguous literal here would match the scanner's own needle (self-match family —
    // see the LOW-2 pin's concatenation rule below for the same cure).
    private static string Guard1Sample(string ctorTail) => "var holder = new AgentTokens" + ctorTail;

    // The enclosing type a construction line sits in, for the exemption arms: a
    // holder class that is NOT the fixture, versus the fixture's own declaration.
    private const string? Guard1DeclaredElsewhere = "ZZScratchSecondHolder";

    private const string? Guard1DeclaredSelf = "AgentTokensFixture";

    [Fact]
    public void LiveTestsSource_OnlyFixtureFilesConstructAPortOwningFixture()
    {
        // Structural pin (reviewer Guard 1, live run 5 class, widened per the post-merge
        // forward row): a *Fixture that owns a fixed stand-in port may only be CONSTRUCTED
        // inside the TYPE that DECLARES it — xUnit's collection machinery holds exactly
        // one instance per collection. The one construction site outside that rule bound
        // the port a second time only in the LIVE leg (offline never double-binds), after
        // the billable call was already paid for. The pin reads the source tree, so it
        // cannot drift with class order — it pins the rule, not the symptom.
        // Widened arms (reviewer fold2 verdict + lead ruling): the matcher accepts the
        // paren AND brace forms; the exemption is the declaring type, not any file named
        // *Fixture.cs, and — since post-release item 8 — not merely a file that declares
        // it either (the file-granular exemption let a holder class cohabiting the
        // fixture's file bind the port twice; measured in the Guard 1 verdict's cohabit
        // leg). Only trim-start // and * lines are skipped. Every arm is a committed
        // cell; the plants above self-witness the two GREEN skip arms in the scan itself.
        var parts = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar)
            .Split(Path.DirectorySeparatorChar);
        var binIndex = Array.IndexOf(parts, "bin");
        Assert.True(binIndex >= 3, $"unexpected test assembly location '{AppContext.BaseDirectory}'");
        var repoRoot = string.Join(Path.DirectorySeparatorChar, parts[..(binIndex - 2)]);
        var srcDir = Path.Combine(repoRoot, "tests", "CredProx.LiveTests");
        var sep = Path.DirectorySeparatorChar;
        var files = Directory
            .EnumerateFiles(srcDir, "*.cs", SearchOption.AllDirectories)
            .Where(f => f.Contains($"{sep}bin{sep}") is false && f.Contains($"{sep}obj{sep}") is false)
            .ToList();
        // Tree-readability anchor (reviewer's anti-vacuity leg): a locator that landed on
        // the wrong directory, or a scan that enumerated zero files, must not report a
        // clean guard — the scan set has to contain this very file before emptiness of
        // the offender list means anything.
        Assert.Contains(files, f => Path.GetFileName(f) == "AgentTokensScaffoldTests.cs");
        var offenders = files
            .SelectMany(f =>
            {
                var lines = File.ReadAllLines(f);
                // Scope walk: depth and the enclosing-type stack come from the
                // structural view (comments gone, string and char content blanked),
                // so no content brace fakes a scope and a positional record line
                // (no body, ends with ;) never captures the scope of what follows.
                // The offense rule itself stays the lead's: raw line plus the
                // comment-LINE skip filter, never a comment stripper.
                var scope = new List<(string Name, int Depth)>();
                var depth = 0;
                var inBlock = false;
                var inRaw = false;
                var found = new List<string>();
                for (var i = 0; i < lines.Length; i++)
                {
                    var structural = Guard1Structural(lines[i], ref inBlock, ref inRaw);
                    var declared = structural.TrimEnd().EndsWith(";", StringComparison.Ordinal)
                        ? Match.Empty
                        : Guard1DeclaredType.Match(structural);
                    if (declared.Success)
                    {
                        scope.Add((declared.Groups[1].Value, depth));
                    }

                    if (Guard1IsOffense(
                            lines[i],
                            scope.Count > 0 ? scope[^1].Name : null))
                    {
                        found.Add($"{Path.GetFileName(f)}:{i + 1}: {lines[i].Trim()}");
                    }

                    foreach (var c in structural)
                    {
                        if (c == '{')
                        {
                            depth++;
                        }
                        else if (c == '}')
                        {
                            depth--;
                            while (scope.Count > 0 && depth <= scope[^1].Depth)
                            {
                                scope.RemoveAt(scope.Count - 1);
                            }
                        }
                    }
                }

                return found;
            })
            .ToList();
        Assert.Empty(offenders);
    }

    [Fact]
    public void Guard1_ParenConstruction_IsAnOffender()
    {
        // Regression arm: the original fold shape (re-add witness, m53-c9-guard-revert.log)
        // still offends under the widened matcher.
        Assert.True(Guard1IsOffense(Guard1Sample("Fixture();"), Guard1DeclaredElsewhere));
    }

    [Fact]
    public void Guard1_BraceConstruction_IsAnOffender()
    {
        // The fold2 gap: brace-init was GREEN under the paren-only matcher; the shape is
        // precedented at tests/CredProx.SampleSmokes/TokenExchangeTeardownTests.cs:47 —
        // that file sits OUTSIDE this scan's root: it is the precedent for the shape,
        // never an offender this guard reads.
        Assert.True(Guard1IsOffense(Guard1Sample("Fixture { StandIn = true };"), Guard1DeclaredElsewhere));
    }

    [Fact]
    public void Guard1_DeclaringTypeConstruction_IsExempt()
    {
        // The exemption arm: the SAME line is legal inside the declaration of the
        // type it constructs — content and scope decide, not the file-name
        // convention.
        Assert.False(Guard1IsOffense(Guard1Sample("Fixture();"), Guard1DeclaredSelf));
    }
    [Fact]
    public void Guard1_CohabitHolderConstruction_IsAnOffender()
    {
        // Post-release item 8 (class-granular exemption): the construction the
        // declaring-type arm exempts offends when it sits in a holder class that
        // merely COHABITS the fixture's file — the old file-granular rule exempted
        // exactly that double-bind the guard exists to prevent (Guard 1 verdict
        // cohabit leg).
        Assert.True(Guard1IsOffense(Guard1Sample("Fixture();"), "ReviewerCohabitProbe"));
    }
    [Fact]
    public void Guard1_DeclaredTypeExtractor_IsAnchored()
    {
        // Post-release item 8: only a declaration at the line start (after optional
        // modifiers) declares a type. The old word-boundary reading captured "in"
        // from `foreach (var record in records)` and minted FakeFixture from a
        // string that merely names it — either token could then exempt a real
        // construction in the same file (Guard 1 verdict extractor leg).
        Assert.DoesNotMatch(Guard1DeclaredType, "foreach (var record in records)");
        Assert.DoesNotMatch(Guard1DeclaredType, "        var s = \"class FakeFixture\";");
        Assert.Matches(Guard1DeclaredType, "public sealed class FakeFixture : IDisposable");
        Assert.Matches(Guard1DeclaredType, "    private sealed record RunnerRun(int Exit, string Out, string Err)");
    }

    [Fact]
    public void Guard1_DoubleSlashMention_IsSkipped()
    {
        // INFO-2 arm: a comment-line mention is not code. Non-vacuity: the bare shape
        // without the comment prefix DOES offend, so the skip is doing the work here.
        var line = "// " + Guard1Sample("Fixture();");
        Assert.True(Guard1IsSkipped(line));
        Assert.True(Guard1IsOffense(Guard1Sample("Fixture();"), Guard1DeclaredElsewhere));
    }

    [Fact]
    public void Guard1_BlockBodyMention_IsSkipped()
    {
        // The leading-* half of INFO-2, measured: the checker's fmut leg used a // line,
        // so this body-line shape ships with this cell as its witness (plus the plant).
        var line = " * " + Guard1Sample("Fixture();");
        Assert.True(Guard1IsSkipped(line));
        Assert.True(Guard1IsOffense(Guard1Sample("Fixture();"), Guard1DeclaredElsewhere));
    }

    [Fact]
    public void Guard1_OneLineBlockCommentMention_IsAnOffender()
    {
        // RED by design (lead ruling): trimmed-start is /*, neither skip prefix. The pin
        // refuses even quoted-in-a-one-liner mentions; widening the filter is the change
        // this cell stops.
        Assert.True(Guard1IsOffense("/* " + Guard1Sample("Fixture();") + " */", Guard1DeclaredElsewhere));
    }

    [Fact]
    public void Guard1_TrailingMentionAfterCode_IsAnOffender()
    {
        // RED by design (lead ruling): the filter is a comment-LINE filter, not a
        // comment STRIPPER — code plus a trailing comment is still code.
        Assert.True(Guard1IsOffense(
            Guard1Sample("Fixture(); // reviewed exception does not exempt"), Guard1DeclaredElsewhere));
    }

    [Fact]
    public void StubAzDefaultRoleJoin_KeepsTheReversedPair()
    {
        // Text pin for the anti-self-fulfillment default (reviewer LOW-2): the
        // canned role join must DEFAULT to the reversed pair, so the sorted
        // read-back can never agree with the fixture by construction (live run 3:
        // Graph returns appRoles in an order of its own choosing). Flipping the
        // default back to the ordered pair keeps every script cell green while
        // proving nothing — which is why the byte string itself is pinned here.
        var parts = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar)
            .Split(Path.DirectorySeparatorChar);
        var binIndex = Array.IndexOf(parts, "bin");
        Assert.True(binIndex >= 3, $"unexpected test assembly location '{AppContext.BaseDirectory}'");
        var repoRoot = string.Join(Path.DirectorySeparatorChar, parts[..(binIndex - 2)]);
        var src = File.ReadAllText(Path.Combine(
            repoRoot, "tests", "CredProx.LiveTests", "AgentTokensScaffoldTests.cs"));
        // Assembled, never written whole into this file: if the needle sat here as
        // one literal, the pin would match its own source and could never fail
        // (the self-match family — a grep that counts its own line). Whole only in
        // the StubAz arm, which is the byte string under guard.
        var needle = "${STUB_ROLE_VALUES:-" + "model-call docs-read" + "}";
        Assert.Contains(needle, src, StringComparison.Ordinal);
    }
}
