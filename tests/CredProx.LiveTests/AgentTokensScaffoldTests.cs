using System.Diagnostics;
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
// read-backs (identifier EXACTLY api://<its own appId>, role present, both
// assignments present) fail loudly when the canned API output says otherwise —
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
        psi.Environment["STUB_ROLE"] = "1";
        psi.Environment["STUB_ASSIGN"] = "1";
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
    // switches drive the failure arms. The minted app-role id is generated by
    // the script at run time, so the assignment read-back is canned as a COUNT
    // (STUB_ASSIGN), never as an id match.
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
            "rest --method GET"*) printf '%s\n' "${STUB_ASSIGN:-1}"; exit 0;;
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
                    *identifierUris*) printf '%s\n' "${STUB_URI:-1}"; exit 0;;
                    *appRoles*) printf '%s\n' "${STUB_ROLE:-1}"; exit 0;;
                esac
                echo "stub az: unmatched app show query: $all" >&2; exit 3;;
            "ad app list"*)
                case "$all" in
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
