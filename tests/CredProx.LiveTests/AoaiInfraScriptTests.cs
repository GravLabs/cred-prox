using System.Diagnostics;
using Xunit;

namespace CredProx.LiveTests;

// Witness for scripts/live-m52-aoai.sh ITSELF: these cells exec the real helper
// directly under the same canned az the runner-witness class plays
// (AoaiRunnerWitnessTests.StubAoaiAz - shared deliberately, so the stub answers
// the helper's exact queries and one stub fix can never drift from the other
// class's copy). What lives here is everything the runner-level cells cannot
// see: the create-step ORDER and the names-only 600 handoff (including the
// endpoint's trailing-slash strip), the refusal guard that a pre-existing
// handoff must stop BEFORE any az write, the existing-group rule (a group this
// run did not record making is never created over and never deleted), the
// partial-create case where destroy
// must still sweep a half-built run, every create read-back that must DIE
// (provisioningState Failed, local auth still on, zero role assignments), both
// destroy zero-shapes (a list that says 0 and a list that ERRORS - the
// deleted-scope shape the docs leave UNVERIFIED), a still-assigned role after
// delete that must FAIL the read-back, an already-gone group that must not be
// re-deleted, and an unresolvable scope that must print SKIPPED and NOT a
// confirmed zero rather than claim a zero it never measured. The identity
// material (the planted principal GUID, the canned resource scope) is asserted
// absent from the streams the RUNNER tees - the runner-level full-lifecycle
// cell covers create and destroy output there; the helper's own stdout/stderr
// here carries names only by construction, and the handoff contents pinned
// below prove it. No real az, no network. The class name deliberately carries
// no live-run.sh filter token ("Aoai", never "AzureOpenAI"): this class execs
// the helper script, not the runner, and must stay out of every vendor leg's
// filter; the marker/guard pair in RunnerRunCreatedScanTests binds the runner
// specifically, and this file resolves the helper from the test-assembly
// location precisely so it never calls the runner locator (whose name must not
// even be quoted here: the marker guard greps every test file for it, comments
// included - a comment describing the absence trips the very cell it describes).
[Trait("Layer", "Offline")]
public sealed class AoaiInfraScriptTests : IDisposable
{
    // the five creation names the helper refuses to run without (fake witness
    // values; a location string, a model name, a version, an account SKU, a
    // deployment SKU tier):
    private const string Loc = "credprox-witness-location";
    private const string Model = "credprox-witness-model";
    private const string ModelVersion = "1.0";
    private const string Sku = "s0";
    private const string DeploymentSku = "Standard";

    // the values the shared canned az plants by default - obviously fake by
    // construction, and the leak arms here assert they reach no helper stream:
    private const string PlantedPrincipal = "11112222-3333-4444-5555-666677778888";
    private const string CannedScope =
        "/subscriptions/aaaaaaaa-0000-0000-0000-000000000000/resourceGroups/credprox-m52"
        + "/providers/Microsoft.CognitiveServices/accounts/canned-account";
    private const string CannedEndpoint = "https://canned-host.openai.azure.com";

    private readonly string _stubBin;
    private readonly string _script;

    public AoaiInfraScriptTests()
    {
        _stubBin = Path.Combine(Path.GetTempPath(), $"credprox-m52-infra-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_stubBin);
        SecretPropagationStubs.WriteExec(_stubBin, "az", AoaiRunnerWitnessTests.StubAoaiAz);
        // the helper sits beside the runner in scripts/ - derived from the
        // assembly's own location, NOT via the runner locator, whose textual
        // guard arm in RunnerRunCreatedScanTests binds it to the marker:
        var root = RepoRoot();
        _script = Path.Combine(root, "scripts", "live-m52-aoai.sh");
        Assert.True(File.Exists(_script), $"the lifecycle helper is not where this witness expects it: {_script}");
    }

    [Fact]
    public void Create_RunsEveryStepInOrder_WritesNamesOnlyHandoff()
    {
        // trailing slash on purpose: the handoff must carry the endpoint
        // stripped, because everything downstream concatenates paths onto it.
        var s = NewSet();
        var run = Exec("create", s, new() { ["STUB_AOAI_ENDPOINT"] = CannedEndpoint + "/" });
        Assert.True(run.Exit == 0, $"the happy create must pass: exit={run.Exit} out={run.Out} err={run.Err}");
        Assert.Contains("OK live-m52-aoai create:", run.Out, StringComparison.Ordinal);
        var at = new Dictionary<string, int>();
        foreach (var verb in new[] { "az group create", "az account create", "az resource update", "az deployment create", "az role assignment create" })
        {
            var i = run.Log.IndexOf(verb, StringComparison.Ordinal);
            Assert.True(i >= 0, $"the canned az never saw '{verb}':\n{run.Log}");
            at[verb] = i;
        }

        Assert.True(
            at["az group create"] < at["az account create"]
            && at["az account create"] < at["az resource update"]
            && at["az resource update"] < at["az deployment create"]
            && at["az deployment create"] < at["az role assignment create"],
            $"wrong create verb order:\n{run.Log}");
        // the account resource id is read ONCE after provisioning and reused for
        // both the local-auth set verb and the role scope - the log carries
        // exactly one id read for the whole create:
        Assert.Equal(1, run.Log.Split("az account show id", StringSplitOptions.None).Length - 1);
        // the handoff: names only, exactly 600, endpoint last and stripped -
        // the runner exports AZURE_OPENAI_ENDPOINT from precisely this file:
        Assert.Equal("credprox-m52", File.ReadAllText(Path.Combine(s.Scratch, "rg.txt")).Trim());
        Assert.Matches(@"^credprox-m52-[0-9a-f]{6}$", File.ReadAllText(Path.Combine(s.Scratch, "account.txt")).Trim());
        // location.txt rides the group create success: the recorded location is
        // what destroy scopes the purge with, so it is handoff - names only, 600.
        var locationFile = Path.Combine(s.Scratch, "location.txt");
        Assert.Equal(Loc, File.ReadAllText(locationFile).Trim());
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(locationFile));
        Assert.Equal("credprox-m52", File.ReadAllText(Path.Combine(s.Scratch, "deployment.txt")).Trim());
        var endpointFile = Path.Combine(s.Scratch, "endpoint.txt");
        Assert.Equal(CannedEndpoint, File.ReadAllText(endpointFile).Trim());
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(endpointFile));
        // nothing of the owner's identity or the resource id may sit in a
        // printed stream or in the handoff:
        var handoff = string.Concat(Directory.EnumerateFiles(s.Scratch).Select(File.ReadAllText));
        foreach (var secret in new[] { PlantedPrincipal, CannedScope })
        {
            Assert.DoesNotContain(secret, run.Out + run.Err + handoff, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Create_LocalAuthSetFails_StopsBeforeDeployment()
    {
        // the local-auth set verb is the last gate before anything billable:
        // when it fails the run must die naming the verb, must NOT reach the
        // deployment create, and must keep the recorded names so the destroy
        // leg can still sweep what exists.
        var s = NewSet();
        var run = Exec("create", s, new() { ["STUB_AOAI_FAIL"] = "resource" });
        Assert.True(run.Exit != 0, $"a failed local-auth set must die: exit={run.Exit} out={run.Out}");
        Assert.Contains("local-auth disable failed", run.Out + run.Err, StringComparison.Ordinal);
        Assert.DoesNotContain("az deployment create", run.Log, StringComparison.Ordinal);
        Assert.True(File.Exists(Path.Combine(s.Scratch, "rg.txt")), "the recorded group must survive for the destroy leg");
        Assert.True(File.Exists(Path.Combine(s.Scratch, "account.txt")), "the recorded account must survive for the destroy leg");
    }

    [Fact]
    public void Create_AccountCreateFails_PrintsErrorCodeNotBody()
    {
        // live run 2 died blind: the write's stderr was thrown away whole. A
        // failure from now on carries az's error CODE and nothing else - the
        // message body can carry the principal and the scope, so every id and
        // body phrase planted in the canned stderr must stay inside the stub.
        var s = NewSet();
        var run = Exec("create", s, new() { ["STUB_AOAI_FAIL"] = "account" });
        Assert.True(run.Exit == 1, $"a failed account create must die: exit={run.Exit} out={run.Out}");
        Assert.Contains("account create failed (az error code: ServiceQuotaExceeded)", run.Out + run.Err, StringComparison.Ordinal);
        foreach (var secret in new[] { PlantedPrincipal, CannedScope, "Message body that must never be printed" })
        {
            Assert.DoesNotContain(secret, run.Out + run.Err, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Create_DeprecatingOrDeprecatedModel_RefusesBeforeAnyWrite()
    {
        // Live run 3's cause, guarded: the catalog read is read-only and needs
        // no account, so it must run BEFORE any write - a refused pick leaves
        // no group, no account and no scratch handoff, and the only az lines
        // the canned helper saw are the sign-in probe and the catalog read.
        foreach (var status in new[] { "Deprecating", "Deprecated" })
        {
            var s = NewSet();
            var run = Exec("create", s, new() { ["STUB_AOAI_MODEL_LIFECYCLE"] = status });
            Assert.True(run.Exit != 0, $"a {status} model version must refuse the run: exit={run.Exit} out={run.Out}");
            Assert.Contains($"catalogued as '{status}'", run.Out + run.Err, StringComparison.Ordinal);
            Assert.Contains("az cognitiveservices model list", run.Log, StringComparison.Ordinal);
            foreach (var verb in new[] { "az group exists", "az group create", "az account create", "az deployment create" })
            {
                Assert.DoesNotContain(verb, run.Log, StringComparison.Ordinal);
            }

            Assert.False(File.Exists(Path.Combine(s.Scratch, "rg.txt")), $"a refused {status} run must write no handoff");
        }
    }

    [Fact]
    public void Create_CatalogAnswersPreviewOrEmpty_NotRefused()
    {
        // Only Deprecating/Deprecated refuse. A Preview pick and a name+version
        // the catalog does not list (the read answers empty) both proceed to
        // the writes - Azure stays the decider for everything the guard cannot
        // see, and the guard must not add a new way to lose a healthy run.
        foreach (var answer in new[] { "Preview", "" })
        {
            var s = NewSet();
            var run = Exec("create", s, new() { ["STUB_AOAI_MODEL_LIFECYCLE"] = answer });
            Assert.True(run.Exit == 0, $"a '{answer}' catalog answer must not refuse: exit={run.Exit} out={run.Out} err={run.Err}");
            Assert.Contains("az cognitiveservices model list", run.Log, StringComparison.Ordinal);
            Assert.Contains("az group create", run.Log, StringComparison.Ordinal);
            Assert.True(File.Exists(Path.Combine(s.Scratch, "endpoint.txt")), "the create must finish and write the handoff");
        }
    }

    [Fact]
    public void Create_FailureShapes_FallbackToParenCodeOrFullSuppression()
    {
        // two more canned shapes: no Code: token but a (Word) marker - the
        // fallback prints just that word; neither shape at all - the run says
        // so and echoes NO bytes of the body.
        var s = NewSet();
        var role = Exec("create", s, new() { ["STUB_AOAI_FAIL"] = "role" });
        Assert.True(role.Exit == 1, $"a failed role assignment must die: exit={role.Exit}");
        Assert.Contains("role assignment create failed (az error code: Forbidden)", role.Out + role.Err, StringComparison.Ordinal);
        Assert.DoesNotContain(PlantedPrincipal, role.Out + role.Err, StringComparison.Ordinal);
        var s2 = NewSet();
        var dep = Exec("create", s2, new() { ["STUB_AOAI_FAIL"] = "deployment" });
        Assert.True(dep.Exit == 1, $"a failed deployment create must die: exit={dep.Exit}");
        Assert.Contains("deployment create failed (az error code: unrecognized, details suppressed)", dep.Out + dep.Err, StringComparison.Ordinal);
        foreach (var secret in new[] { PlantedPrincipal, CannedScope, "message body that must never be printed" })
        {
            Assert.DoesNotContain(secret, dep.Out + dep.Err, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void RefusalGuard_ExistingHandoff_RefusesBeforeAnyAzWrite()
    {
        // the one-leg-at-a-time rule: a handoff already under the scratch means
        // a create is or was in flight; overwriting it would orphan that run's
        // resources. The sign-in gate legitimately calls az READS first (that
        // is why this asserts the absence of WRITE verbs, not of the log).
        var s = NewSet();
        Directory.CreateDirectory(s.Scratch);
        File.WriteAllText(Path.Combine(s.Scratch, "endpoint.txt"), "https://other-run.openai.azure.com\n");
        var run = Exec("create", s);
        Assert.True(run.Exit != 0, $"the refusal guard must fail the create: exit={run.Exit} out={run.Out}");
        Assert.Contains("a run-created handoff already exists", run.Out + run.Err, StringComparison.Ordinal);
        foreach (var write in new[] { "az group create", "az account create", "az deployment create", "az role assignment create" })
        {
            Assert.DoesNotContain(write, run.Log, StringComparison.Ordinal);
        }

        // the refusal is BEFORE any scratch write too - no account.txt of this
        // attempt may exist beside the other run's handoff:
        Assert.False(File.Exists(Path.Combine(s.Scratch, "account.txt")), "the guard must fire before the scratch is written");
    }

    [Fact]
    public void RefusalGuard_PartialHandoffFile_RefusesBeforeAnyAzWrite()
    {
        // The guard covers EVERY handoff file, not just the last one written:
        // a create interrupted between writes leaves some of the five and not
        // others, and any single leftover is another run's recorded name.
        // Each leftover here is exactly the file the old single-file guard
        // could not see - the endpoint it watched was the one missing.
        foreach (var leftover in new[] { "rg.txt", "account.txt", "location.txt", "deployment.txt" })
        {
            var s = NewSet();
            Directory.CreateDirectory(s.Scratch);
            File.WriteAllText(Path.Combine(s.Scratch, leftover), "credprox-m52\n");
            var run = Exec("create", s);
            Assert.True(run.Exit != 0, $"the {leftover} handoff guard must fire: exit={run.Exit} out={run.Out}");
            Assert.Contains($"scratch has {leftover}", run.Out + run.Err, StringComparison.Ordinal);
            foreach (var write in new[] { "az group create", "az account create", "az deployment create", "az role assignment create" })
            {
                Assert.DoesNotContain(write, run.Log, StringComparison.Ordinal);
            }
        }
    }

    [Fact]
    public void Create_ExistingGroup_RefusesBeforeAnyWrite()
    {
        // the owner-safety rule: a group of the fixed name that this run did
        // not create is not this run's to touch. The refusal fires before the
        // scratch exists and before a single az WRITE; the message names the
        // group and says how a person clears a leftover by hand.
        var s = NewSet();
        var run = Exec("create", s, new() { ["STUB_AOAI_EXISTS_SEQ"] = "true" });
        Assert.True(run.Exit != 0, $"an existing group must refuse the create: exit={run.Exit} out={run.Out}");
        Assert.Contains("already exists", run.Out + run.Err, StringComparison.Ordinal);
        foreach (var write in new[] { "az group create", "az account create", "az deployment create", "az role assignment create" })
        {
            Assert.DoesNotContain(write, run.Log, StringComparison.Ordinal);
        }

        Assert.False(Directory.Exists(s.Scratch), "the refusal must fire before the scratch is even created");
    }

    [Fact]
    public void Create_GroupCreateFails_RecordsNoGroup()
    {
        // rg.txt rides a group create that SUCCEEDED on a name just seen free:
        // when the create dies there is no recorded group, so a later destroy
        // will refuse to delete one (the account name is recorded earlier
        // precisely so a half-run stays nameable).
        var s = NewSet();
        var run = Exec("create", s, new() { ["STUB_AOAI_FAIL"] = "group" });
        Assert.True(run.Exit == 1, $"a failed group create must die: exit={run.Exit} out={run.Out}");
        Assert.Contains("resource group create failed", run.Out + run.Err, StringComparison.Ordinal);
        Assert.False(File.Exists(Path.Combine(s.Scratch, "rg.txt")), "rg.txt must only ride a group create that succeeded");
        Assert.True(File.Exists(Path.Combine(s.Scratch, "account.txt")), "the account name is recorded before the group create, so destroy can still name the account");
    }

    [Fact]
    public void Create_MissingDeploymentSku_RefusesBeforeAnyWrite()
    {
        // the deployment SKU is the fifth creation name: the tier is the owner's
        // choice from live.env, never a remembered constant - so a run without
        // it must refuse at the name gate, not limp into the deployment create
        // with an empty flag.
        var s = NewSet();
        var run = Exec("create", s, new() { ["AZURE_OPENAI_DEPLOYMENT_SKU"] = "" });
        Assert.True(run.Exit != 0, $"a missing deployment SKU must refuse the create: exit={run.Exit} out={run.Out}");
        Assert.Contains("AZURE_OPENAI_DEPLOYMENT_SKU is not set", run.Out + run.Err, StringComparison.Ordinal);
        foreach (var write in new[] { "az group create", "az account create", "az deployment create", "az role assignment create" })
        {
            Assert.DoesNotContain(write, run.Log, StringComparison.Ordinal);
        }

        Assert.False(Directory.Exists(s.Scratch), "the name gate must fire before the scratch is created");
    }

    [Fact]
    public void DeploymentCreateLine_UsesTheEnvNamedSku()
    {
        // the stub never logs flags, so the flag wiring itself is pinned on the
        // script text: the deployment create must carry the env-named tier, not
        // a hard-coded one (a hard-coded Standard would silently ignore the
        // fifth required name the run just validated).
        var script = File.ReadAllText(_script);
        Assert.Contains("--sku-name \"$AZURE_OPENAI_DEPLOYMENT_SKU\"", script, StringComparison.Ordinal);
    }

    [Fact]
    public void ScriptText_LocalAuthRidesTheRealPropertyPath()
    {
        // keyless is this vendor's whole point. Live run 1 falsified the old
        // create-flag composition (it lands on properties.apiProperties), so
        // the property is set by the ARM PATCH. The canned stub's reality
        // marker is set ONLY by the literal --set properties.disableLocalAuth=
        // true, so a PATCH of any other path now also burns the behavioral
        // read-back cells - and this pin still binds the path in the script
        // text (needles carry the quoted variable names so the dry-run's
        // echoes cannot satisfy them).
        var script = File.ReadAllText(_script);
        Assert.Contains("--ids \"$ACCT_ID\" --set properties.disableLocalAuth=true", script, StringComparison.Ordinal);
        Assert.Contains("--custom-domain \"$ACCT\" --yes", script, StringComparison.Ordinal);
        // the falsified flag must be GONE from the create statement (it spans
        // continuation lines, so bound the whole statement, not one line -
        // bounded by its own final flag, since the failure text now PRECEDES
        // the statement as the az_write prefix):
        var start = script.IndexOf("az cognitiveservices account create --name \"$ACCT\"", StringComparison.Ordinal);
        Assert.True(start >= 0, "the account create statement is not where this pin expects it");
        var endMarker = "--custom-domain \"$ACCT\" --yes";
        var end = script.IndexOf(endMarker, start, StringComparison.Ordinal);
        Assert.True(end >= 0, "the account create statement does not end where this pin expects it");
        var stmt = script[start..(end + endMarker.Length)];
        Assert.DoesNotContain("api-properties", stmt, StringComparison.Ordinal);
        Assert.DoesNotContain("disableLocalAuth", stmt, StringComparison.Ordinal);
    }

    [Fact]
    public void ScriptText_HandoffLineNamesAllFiveCarriedValues()
    {
        // The handoff file is the only channel from create to the live cell,
        // and the dry-run's own line is what states its contract: five carried
        // values, mode 600. Pinned as ONE line carrying all five names in
        // order, so dropping any one of them - or the mode - burns this cell;
        // before it existed, no mutant of the handoff line burned anything.
        var script = File.ReadAllText(_script);
        Assert.Contains(
            "handoff: rg/account/location/endpoint/deployment names into $SCRATCH at mode 600",
            script, StringComparison.Ordinal);
    }

    [Fact]
    public void ScriptText_ListDeletedReadBackCarriesNoScopeFlag()
    {
        // live run 2: the real CLI refuses ANY scope argument on list-deleted
        // (rc 2 "unrecognized arguments" for --location, verified this host with
        // az <verb> --help) - but the canned az used to accept everything, so a
        // purge read-back that could never return clean ran green offline. The
        // stub logs verb lines only, so the call site is pinned on script text:
        // no scope flags on the list-deleted statement, and the exactness of the
        // verdict rides the name filter inside --query (the account name is the
        // global namespace the reservation lives in).
        var script = File.ReadAllText(_script);
        var start = script.IndexOf("az cognitiveservices account list-deleted \\", StringComparison.Ordinal);
        Assert.True(start >= 0, "the list-deleted read-back statement is not where this pin expects it");
        var stmt = script[start..script.IndexOf("-o tsv", start, StringComparison.Ordinal)];
        Assert.DoesNotContain("--location", stmt, StringComparison.Ordinal);
        Assert.DoesNotContain("--resource-group", stmt, StringComparison.Ordinal);
        Assert.Contains("[?name=='$ACCT_LEFT'] | length(@)", stmt, StringComparison.Ordinal);
    }

    [Fact]
    public void StubRefusesLocationOnListDeleted_LikeTheRealCli()
    {
        // the behavioral half of live run 2 finding 1: the real list-deleted
        // takes NO scope flag (rc 2, unrecognized arguments) - so the canned
        // az takes none either, and any script that adds --location is
        // refused here, not silently accepted.
        var bad = ExecStub(
            "cognitiveservices", "account", "list-deleted", "--location", "eastus2",
            "--query", "[?name=='credprox-m52-abcdef'] | length(@)", "-o", "tsv");
        Assert.Equal(2, bad.Exit);
        Assert.Contains("unrecognized arguments: --location", bad.Err, StringComparison.Ordinal);
    }

    [Fact]
    public void StubAcceptsTheExactListDeletedCall()
    {
        // the refusal must not eat the legitimate call the script makes - the
        // exact shape from the purge read-back passes and answers the scripted
        // settle sequence (default 0 = absent).
        var ok = ExecStub(
            "cognitiveservices", "account", "list-deleted",
            "--query", "[?name=='credprox-m52-abcdef'] | length(@)", "-o", "tsv");
        Assert.True(ok.Exit == 0, $"the read-back's exact call must pass: exit={ok.Exit} err={ok.Err}");
        Assert.Equal("0", ok.Out.Trim());
    }

    [Fact]
    public void StubRefusesFlagsTheVerbDoesNotTake_OnBothReadAndWrite()
    {
        // allow-lists are per-verb, not decorative: --location is real on
        // group create but refused on group delete, and --sku is real on
        // account create but refused on group create.
        var bad = ExecStub("group", "delete", "--name", "credprox-m52", "--yes", "--no-wait", "--location", "eastus2");
        Assert.Equal(2, bad.Exit);
        Assert.Contains("unrecognized arguments: --location", bad.Err, StringComparison.Ordinal);
        var bad2 = ExecStub("group", "create", "--name", "credprox-m52", "--location", "eastus2", "--sku", "S0");
        Assert.Equal(2, bad2.Exit);
        Assert.Contains("unrecognized arguments: --sku", bad2.Err, StringComparison.Ordinal);
    }

    [Fact]
    public void ScriptText_EndpointHandoffIsWrittenLast()
    {
        // endpoint.txt is the in-flight refusal guard AND the runner's export
        // source: it must ride after the deployment write, so a half-built
        // scratch never advertises a dialable endpoint. Pinned on the write
        // redirections (a read of the file appears earlier, as the guard).
        var script = File.ReadAllText(_script);
        var deploymentWrite = script.IndexOf("> \"$SCRATCH/deployment.txt\"", StringComparison.Ordinal);
        var endpointWrite = script.IndexOf("> \"$SCRATCH/endpoint.txt\"", StringComparison.Ordinal);
        Assert.True(deploymentWrite >= 0 && endpointWrite > deploymentWrite,
            "endpoint.txt must be written after deployment.txt - its existence is the refusal guard");
    }

    [Fact]
    public void PartialCreate_AccountFail_DestroyStillSweepsClean()
    {
        // the group is up, the account is not: the recorded names make the
        // half-run sweepable, and destroy must report the plain clean line.
        var s = NewSet();
        var create = Exec("create", s, new() { ["STUB_AOAI_FAIL"] = "account" });
        Assert.True(create.Exit == 1, $"a failed account create must die: exit={create.Exit} out={create.Out}");
        Assert.Contains("ERROR: account create failed", create.Err, StringComparison.Ordinal);
        Assert.True(File.Exists(Path.Combine(s.Scratch, "account.txt")), "the account name must be recorded before its create, or destroy cannot name what to sweep");
        var destroy = Exec("destroy", s);
        Assert.True(destroy.Exit == 0, $"the sweep of a half-built run must read back clean: exit={destroy.Exit} out={destroy.Out} err={destroy.Err}");
        Assert.Contains("OK live-m52-aoai destroy:", destroy.Out, StringComparison.Ordinal);
        Assert.Contains("az group delete", destroy.Log, StringComparison.Ordinal);
        Assert.False(Directory.Exists(s.Scratch), "destroy must remove the scratch even for a half-built run");
    }

    [Fact]
    public void ProvisioningStateFailed_ReadbackDies_NamingIt()
    {
        var s = NewSet();
        var run = Exec("create", s, new() { ["STUB_AOAI_PROV_STATE"] = "Failed" });
        Assert.True(run.Exit == 1, $"a Failed provisioningState must die: exit={run.Exit} out={run.Out}");
        Assert.Contains("provisioningState is Failed", run.Out + run.Err, StringComparison.Ordinal);
    }

    [Fact]
    public void Create_UpdateReProvisions_CreateWaitsForSucceeded()
    {
        // live run 2 died at deployment create right after the local-auth PATCH.
        // Model its leading hypothesis: the update re-provisions the account,
        // which reports Updating twice and only then Succeeded. The script must
        // re-poll provisioningState after the update before anything else
        // touches the account: the create passes, and the poll log carries the
        // create poll once plus three post-update reads (Updating, Updating,
        // Succeeded). Dropping the update poll burns this cell: with no
        // post-update read the canned create answers Updating and exits 9.
        var s = NewSet();
        var run = Exec("create", s, new() { ["STUB_AOAI_UPDATE_SEQ"] = "Updating,Updating,Succeeded" });
        Assert.True(run.Exit == 0, $"create must wait out the post-update Updating: exit={run.Exit} out={run.Out} err={run.Err}");
        Assert.Equal(4, run.Log.Split("az account show provisioningState", StringSplitOptions.None).Length - 1);
    }

    [Fact]
    public void LocalAuthStillEnabled_ReadbackDies()
    {
        // the keyless rule is the whole point of this vendor: if the created
        // account still answers to keys, the run must not hand it to the cell.
        var s = NewSet();
        var run = Exec("create", s, new() { ["STUB_AOAI_LOCAL_AUTH"] = "False" });
        Assert.True(run.Exit == 1, $"an account with local auth enabled must die: exit={run.Exit} out={run.Out}");
        Assert.Contains("local (key) auth is not disabled", run.Out + run.Err, StringComparison.Ordinal);
    }

    [Fact]
    public void RoleAssignmentCountZero_ReadbackDies()
    {
        // the cell is about to dial with the Entra token; zero role assignments
        // means it would 403 for the whole wait budget - die at create instead.
        var s = NewSet();
        var run = Exec("create", s, new() { ["STUB_AOAI_ROLE_COUNT"] = "0" });
        Assert.True(run.Exit == 1, $"zero role assignments must die: exit={run.Exit} out={run.Out}");
        Assert.Contains("expected exactly 1 role assignment", run.Out + run.Err, StringComparison.Ordinal);
    }

    [Fact]
    public void Destroy_RoleListErrors_CountsAsTheZeroShape()
    {
        // the deleted-scope shape the docs leave UNVERIFIED: a list over the
        // dead scope may ERROR instead of returning []; either zero-shape is a
        // confirmed gone, so the read-back must pass and the OK line print.
        var s = NewSet();
        Assert.Equal(0, Exec("create", s).Exit);
        var destroy = Exec("destroy", s, new() { ["STUB_AOAI_ROLE_FAIL"] = "1" });
        Assert.True(destroy.Exit == 0, $"a list error over the deleted scope is the zero-shape: exit={destroy.Exit} out={destroy.Out} err={destroy.Err}");
        Assert.Contains("OK live-m52-aoai destroy:", destroy.Out, StringComparison.Ordinal);
    }

    [Fact]
    public void Destroy_RolesStillAssignedAfterDelete_FailsReadback()
    {
        // a real positive count after the group delete is a genuine leftover -
        // the destroy must say so in words that will not be mistaken for clean.
        var s = NewSet();
        Assert.Equal(0, Exec("create", s).Exit);
        var destroy = Exec("destroy", s, new() { ["STUB_AOAI_ROLE_COUNT"] = "1" });
        Assert.True(destroy.Exit == 1, $"a still-assigned role must fail the read-back: exit={destroy.Exit} out={destroy.Out}");
        Assert.Contains("DESTROY-READBACK FAILED", destroy.Out + destroy.Err, StringComparison.Ordinal);
        Assert.Contains("role assignments zero=0", destroy.Out + destroy.Err, StringComparison.Ordinal);
        // the retry needs the recorded names: a failed read-back retains the
        // handoff - and the retention line must name the runner as the retry
        // path (a bare re-run works too now: group, account and purge location
        // are all read back from the scratch, not from the environment).
        Assert.True(Directory.Exists(s.Scratch), "a failed read-back must RETAIN the scratch handoff");
        Assert.Contains("RETAINED", destroy.Out + destroy.Err, StringComparison.Ordinal);
        Assert.Contains("live-run.sh", destroy.Out + destroy.Err, StringComparison.Ordinal);
    }

    [Fact]
    public void Destroy_GroupAlreadyGone_SkipsTheDeleteAndStaysClean()
    {
        // re-entering destroy must not flail: an already-gone group means no
        // group delete call at all, and the run is clean anyway.
        var s = NewSet();
        Directory.CreateDirectory(s.Scratch);
        File.WriteAllText(Path.Combine(s.Scratch, "rg.txt"), "credprox-m52\n");
        File.WriteAllText(Path.Combine(s.Scratch, "account.txt"), "credprox-m52-abc123\n");
        File.WriteAllText(Path.Combine(s.Scratch, "location.txt"), Loc + "\n");
        File.WriteAllText(Path.Combine(s.Scratch, "deployment.txt"), "credprox-m52\n");
        File.WriteAllText(Path.Combine(s.Scratch, "endpoint.txt"), CannedEndpoint + "\n");
        // no create ran in this set, so no group delete ever happens - and only
        // the delete moves the stub's group reality (a read must not mutate it),
        // so the role zero that a genuinely deleted scope would answer is pinned
        // explicitly here instead.
        var destroy = Exec("destroy", s, new() { ["STUB_AOAI_EXISTS_SEQ"] = "false", ["STUB_AOAI_ROLE_COUNT"] = "0" });
        Assert.True(destroy.Exit == 0, $"destroying an already-gone group is clean: exit={destroy.Exit} out={destroy.Out} err={destroy.Err}");
        Assert.DoesNotContain("az group delete", destroy.Log, StringComparison.Ordinal);
        Assert.Contains("OK live-m52-aoai destroy:", destroy.Out, StringComparison.Ordinal);
        Assert.False(Directory.Exists(s.Scratch));
    }

    [Fact]
    public void Destroy_NoRgTxt_NoGroupDelete_NotConfirmed()
    {
        // a handoff without rg.txt records no group this run made (a create
        // that died before its group create succeeded). Destroy issues NO
        // group delete - guessing the fixed name could delete a group this run
        // never created - and says in words AND in the exit code that nothing
        // about a group was confirmed.
        var s = NewSet();
        Directory.CreateDirectory(s.Scratch);
        File.WriteAllText(Path.Combine(s.Scratch, "account.txt"), "credprox-m52-abc123\n");
        File.WriteAllText(Path.Combine(s.Scratch, "deployment.txt"), "credprox-m52\n");
        File.WriteAllText(Path.Combine(s.Scratch, "endpoint.txt"), CannedEndpoint + "\n");
        var destroy = Exec("destroy", s);
        Assert.True(destroy.Exit != 0, $"with no recorded group the exit says nothing was confirmed: exit={destroy.Exit} out={destroy.Out} err={destroy.Err}");
        Assert.Contains("SKIPPED: resource-group read-back", destroy.Out, StringComparison.Ordinal);
        Assert.Contains("NOT a confirmed deletion", destroy.Out, StringComparison.Ordinal);
        Assert.DoesNotContain("az group delete", destroy.Log, StringComparison.Ordinal);
        // the purge block never ran: the report says not-attempted, not a
        // verdict word this destroy did not earn.
        Assert.Contains("deleted account purge=not-attempted", destroy.Out + destroy.Err, StringComparison.Ordinal);
        Assert.True(Directory.Exists(s.Scratch), "an unconfirmed group read-back must RETAIN the handoff that records what was made");
    }

    [Fact]
    public void Destroy_NoLocationTxt_RefusesBeforeAnyAzWrite()
    {
        // a handoff that records a group AND an account but no location cannot
        // scope the purge: destroy dies at the top guard BEFORE any az WRITE -
        // only the signed-in probe may precede it, never the group delete, when
        // the refusal would come with the resources already gone - and retains
        // the handoff.
        var s = NewSet();
        Directory.CreateDirectory(s.Scratch);
        File.WriteAllText(Path.Combine(s.Scratch, "rg.txt"), "credprox-m52\n");
        File.WriteAllText(Path.Combine(s.Scratch, "account.txt"), "credprox-m52-abc123\n");
        var destroy = Exec("destroy", s);
        Assert.True(destroy.Exit != 0, $"a handoff without the recorded location must be refused: exit={destroy.Exit} out={destroy.Out} err={destroy.Err}");
        Assert.Contains("location.txt", destroy.Err, StringComparison.Ordinal);
        Assert.True("az account get-access-token" == destroy.Log.Trim(), $"the only az call before the refusal is the signed-in probe - no write happened: log={destroy.Log}");
        Assert.True(Directory.Exists(s.Scratch), "a refused destroy retains the handoff it could not act on");
    }

    [Fact]
    public void Destroy_BadPurgeWaitRefusesBeforeGroupDelete()
    {
        // the purge-budget shape guard is hoisted to the top of destroy: a
        // malformed value fails the whole destroy BEFORE the group delete, not
        // after the resources are already gone.
        var s = NewSet();
        Directory.CreateDirectory(s.Scratch);
        File.WriteAllText(Path.Combine(s.Scratch, "rg.txt"), "credprox-m52\n");
        File.WriteAllText(Path.Combine(s.Scratch, "account.txt"), "credprox-m52-abc123\n");
        File.WriteAllText(Path.Combine(s.Scratch, "location.txt"), Loc + "\n");
        var destroy = Exec("destroy", s, new() { ["CREDPROX_M52_AOAI_PURGE_WAIT_SECONDS"] = "12x" });
        Assert.True(destroy.Exit != 0, $"a malformed purge budget must refuse the destroy: exit={destroy.Exit} out={destroy.Out} err={destroy.Err}");
        Assert.Contains("PURGE_WAIT_SECONDS", destroy.Err, StringComparison.Ordinal);
        Assert.True("az account get-access-token" == destroy.Log.Trim(), $"the only az call before the refusal is the signed-in probe - no write happened: log={destroy.Log}");
        Assert.DoesNotContain("az group delete", destroy.Log, StringComparison.Ordinal);

        // An explicitly EMPTY budget is not an unset one: the documented
        // default belongs to absence. A caller that exported the knob with no
        // value meant to set a budget and set nothing - it must refuse like
        // any other malformed value, before the group delete, not silently
        // borrow the 300s default.
        var s2 = NewSet();
        Directory.CreateDirectory(s2.Scratch);
        File.WriteAllText(Path.Combine(s2.Scratch, "rg.txt"), "credprox-m52\n");
        File.WriteAllText(Path.Combine(s2.Scratch, "account.txt"), "credprox-m52-abc123\n");
        File.WriteAllText(Path.Combine(s2.Scratch, "location.txt"), Loc + "\n");
        var empty = Exec("destroy", s2, new() { ["CREDPROX_M52_AOAI_PURGE_WAIT_SECONDS"] = "" });
        Assert.True(empty.Exit != 0, $"an empty purge budget must refuse the destroy: exit={empty.Exit} out={empty.Out} err={empty.Err}");
        Assert.Contains("PURGE_WAIT_SECONDS", empty.Err, StringComparison.Ordinal);
        Assert.True("az account get-access-token" == empty.Log.Trim(), $"the empty-value refusal must also precede every write: log={empty.Log}");
        Assert.DoesNotContain("az group delete", empty.Log, StringComparison.Ordinal);
    }

    [Fact]
    public void Destroy_PurgesSoftDeletedAccount_ReadBackAbsent()
    {
        // a deleted Cognitive Services account keeps its name reserved until
        // purged: the run must purge it AND prove the purge with the
        // soft-deleted list read-back, not with the verb's exit.
        var s = NewSet();
        Assert.Equal(0, Exec("create", s).Exit);
        var destroy = Exec("destroy", s);
        Assert.True(destroy.Exit == 0, $"the happy destroy must report the purge: exit={destroy.Exit} out={destroy.Out} err={destroy.Err}");
        Assert.Contains("az account purge", destroy.Log, StringComparison.Ordinal);
        Assert.Contains("az account list-deleted", destroy.Log, StringComparison.Ordinal);
        Assert.Contains("deleted account purged (absent from the soft-deleted list)", destroy.Out, StringComparison.Ordinal);
        // default settle answer is absent from the first read: no polling sleep,
        // and the clean verdict is the ONLY one the OK line may claim.
        Assert.DoesNotContain("DESTROY-READBACK FAILED", destroy.Out + destroy.Err, StringComparison.Ordinal);
    }

    [Fact]
    public void Destroy_DeletedAccountStillListed_FailsReadback()
    {
        // the read-back is the verdict: if the soft-deleted list still names
        // the run's account, that reserved name is a leftover and the destroy
        // must say so in words AND in the exit code.
        var s = NewSet();
        Assert.Equal(0, Exec("create", s).Exit);
        // the poll budget knob rides small so the cell waits one cycle, not the
        // default five minutes; the answer stays listed the whole time.
        var destroy = Exec("destroy", s, new()
        {
            ["STUB_AOAI_PURGE_STILL"] = "1",
            ["CREDPROX_M52_AOAI_PURGE_WAIT_SECONDS"] = "5",
        });
        Assert.True(destroy.Exit == 1, $"a still-listed deleted account must fail the destroy: exit={destroy.Exit} out={destroy.Out}");
        Assert.Contains("DESTROY-READBACK FAILED", destroy.Out + destroy.Err, StringComparison.Ordinal);
        Assert.Contains("deleted account purge=still-listed", destroy.Out + destroy.Err, StringComparison.Ordinal);
        Assert.DoesNotContain("could-not-verify", destroy.Out + destroy.Err, StringComparison.Ordinal);
    }

    [Fact]
    public void Destroy_DeletedAccountSettlesLater_PollWaitsAndPasses()
    {
        // the async settle live run 1 observed (listed at destroy, absent
        // minutes later): the poll must WAIT it out - a single-shot read would
        // fail a destroy that is actually finishing. Answers: listed, listed,
        // absent - the verdict is clean with no FAILED line.
        // This cell asserts THREE reads, so it pins its own budget: reads land
        // at t=0 and then each 5s, the third at t=10, so the minimum is above
        // 10 by real jitter - 20, never the single-read siblings' 5 (a legal
        // small export would expire the poll before read three and burn a
        // clean tree; the script default is a user knob, not a fixture).
        var s = NewSet();
        Assert.Equal(0, Exec("create", s).Exit);
        var destroy = Exec("destroy", s, new()
        {
            ["STUB_AOAI_PURGE_SEQ"] = "1,1,0",
            ["CREDPROX_M52_AOAI_PURGE_WAIT_SECONDS"] = "20",
        });
        Assert.True(destroy.Exit == 0, $"a purge that settles within the budget must pass: exit={destroy.Exit} out={destroy.Out} err={destroy.Err}");
        Assert.Equal(3, destroy.Log.Split("az account list-deleted", StringSplitOptions.None).Length - 1);
        Assert.DoesNotContain("DESTROY-READBACK FAILED", destroy.Out + destroy.Err, StringComparison.Ordinal);
        Assert.Contains("deleted account purged (absent from the soft-deleted list)", destroy.Out, StringComparison.Ordinal);
    }

    [Fact]
    public void Destroy_PurgeDeadlineElapses_FailsWithPrintedDeadlineAndRetainsScratch()
    {
        // listed for the whole 5s budget: FAILED names the verdict AND the
        // deadline it polled to, and the handoff survives so a re-run can
        // confirm the settle against the recorded name.
        var s = NewSet();
        Assert.Equal(0, Exec("create", s).Exit);
        var destroy = Exec("destroy", s, new()
        {
            ["STUB_AOAI_PURGE_SEQ"] = "1",
            ["CREDPROX_M52_AOAI_PURGE_WAIT_SECONDS"] = "5",
        });
        Assert.True(destroy.Exit == 1, $"deadline expiry on a listed name must fail: exit={destroy.Exit} out={destroy.Out}");
        Assert.Contains("deleted account purge=still-listed", destroy.Out + destroy.Err, StringComparison.Ordinal);
        Assert.Contains("deadline of 5s", destroy.Err, StringComparison.Ordinal);
        Assert.True(Directory.Exists(s.Scratch), "the retained handoff is what lets the retry name the account to re-check");
    }

    [Fact]
    public void Destroy_ListDeletedErrors_CouldNotVerify_FailsClosedRetainingScratch()
    {
        // the third state, fail-closed: when the list read never answers (every
        // poll errors), the destroy must NOT claim purged - the exit is non-zero
        // like any failed read-back, the words say could-not-verify rather than
        // borrowing the clean or the listed verdict, and the scratch survives.
        var s = NewSet();
        Assert.Equal(0, Exec("create", s).Exit);
        var destroy = Exec("destroy", s, new()
        {
            ["STUB_AOAI_FAIL"] = "listdeleted",
            ["CREDPROX_M52_AOAI_PURGE_WAIT_SECONDS"] = "5",
        });
        Assert.True(destroy.Exit != 0, $"an unanswerable purge read-back must fail closed: exit={destroy.Exit} out={destroy.Out}");
        Assert.Contains("deleted account purge=could-not-verify", destroy.Out + destroy.Err, StringComparison.Ordinal);
        Assert.Contains("purge read-back ended as could-not-verify", destroy.Err, StringComparison.Ordinal);
        Assert.DoesNotContain("purged", destroy.Out + destroy.Err, StringComparison.Ordinal);
        Assert.True(Directory.Exists(s.Scratch), "could-not-verify retains the handoff exactly like a confirmed leftover");
    }

    [Fact]
    public void Destroy_PurgeVerbFails_ReadBackStillDecides()
    {
        // the verb's exit is never the verdict - a never-created account makes
        // purge error as a matter of course: with the read-back clean the
        // destroy still reads back clean.
        var s = NewSet();
        Assert.Equal(0, Exec("create", s).Exit);
        var destroy = Exec("destroy", s, new() { ["STUB_AOAI_FAIL"] = "purge" });
        Assert.True(destroy.Exit == 0, $"a purge verb failure with a clean read-back is still clean: exit={destroy.Exit} out={destroy.Out} err={destroy.Err}");
        Assert.Contains("az account purge", destroy.Log, StringComparison.Ordinal);
        Assert.Contains("OK live-m52-aoai destroy:", destroy.Out, StringComparison.Ordinal);
        // the swallowed error is not silent any more: the code is named, the
        // body (with its planted id) is not - and the read-back stays verdict:
        Assert.Contains("NOTE: the purge verb reported an error (az error code: Conflict)", destroy.Err, StringComparison.Ordinal);
        Assert.DoesNotContain(PlantedPrincipal, destroy.Out + destroy.Err, StringComparison.Ordinal);
    }

    [Fact]
    public void Destroy_ScopeUnreachable_ReportsSkipped_NotAConfirmedZero()
    {
        // if the recorded account no longer resolves, the scope the role was
        // granted at cannot be listed: the honest output is a loud SKIPPED that
        // refuses to claim a zero - and the exit stays clean (the group itself
        // is verifiably gone), so the line is what the lead reads, not a code.
        var s = NewSet();
        Assert.Equal(0, Exec("create", s).Exit);
        var destroy = Exec("destroy", s, new() { ["STUB_AOAI_SHOW_ID_FAIL"] = "1" });
        Assert.True(destroy.Exit == 0, $"an unresolved scope is a SKIPPED, not a failure: exit={destroy.Exit} out={destroy.Out} err={destroy.Err}");
        Assert.Contains("SKIPPED: role-assignment read-back", destroy.Out, StringComparison.Ordinal);
        Assert.Contains("NOT a confirmed zero", destroy.Out, StringComparison.Ordinal);
        // a skipped read-back is not a confirmed one: the handoff stays so a
        // later run can finish what this one could not measure.
        Assert.True(Directory.Exists(s.Scratch), "a skipped role read-back must RETAIN the scratch handoff for a retry");
        Assert.Contains("RETAINED", destroy.Out, StringComparison.Ordinal);
    }

    [Fact]
    public void Usage_UnknownVerb_ExitsTwo_WithoutTouchingAz()
    {
        var s = NewSet();
        var run = Exec("bogus", s);
        Assert.True(run.Exit == 2, $"an unknown verb must exit 2: exit={run.Exit} out={run.Out}");
        Assert.Contains("usage: live-m52-aoai.sh create|destroy|--dry-run", run.Out + run.Err, StringComparison.Ordinal);
        Assert.DoesNotContain("az ", run.Log, StringComparison.Ordinal);
    }

    // one set of per-run stub paths: shared across the create and destroy execs
    // of a cell (the exists-counter and the gone-marker model one resource
    // lifecycle), fresh between cells so no state leaks between tests.
    private sealed class CellSet
    {
        public required string Scratch { get; init; }
        public required string ExistsCounter { get; init; }
        public required string GoneMarker { get; init; }
        public required string AzLog { get; init; }
    }

    private CellSet NewSet() => new()
    {
        Scratch = Path.Combine(_stubBin, $"scratch-{Guid.NewGuid():N}"),
        ExistsCounter = Path.Combine(_stubBin, $"exists-{Guid.NewGuid():N}"),
        GoneMarker = Path.Combine(_stubBin, $"gone-{Guid.NewGuid():N}"),
        AzLog = Path.Combine(_stubBin, $"azlog-{Guid.NewGuid():N}.log"),
    };

    private sealed record ExecResult(int Exit, string Out, string Err, string Log);

    private ExecResult Exec(string verb, CellSet set, Dictionary<string, string>? stubEnv = null)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "/bin/bash",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add(_script);
        psi.ArgumentList.Add(verb);
        // the stub dir LEADS PATH: the canned az shadows the machine's real one;
        // nothing here can reach a tenant, the network or a resource.
        psi.Environment["PATH"] = _stubBin + ":/usr/bin:/bin";
        psi.Environment["AZURE_OPENAI_LOCATION"] = Loc;
        psi.Environment["AZURE_OPENAI_MODEL"] = Model;
        psi.Environment["AZURE_OPENAI_MODEL_VERSION"] = ModelVersion;
        psi.Environment["AZURE_OPENAI_SKU"] = Sku;
        psi.Environment["AZURE_OPENAI_DEPLOYMENT_SKU"] = DeploymentSku;
        psi.Environment["CREDPROX_M52_AOAI_SCRATCH"] = set.Scratch;
        psi.Environment["STUB_AZ_LOG"] = set.AzLog;
        psi.Environment["STUB_AOAI_EXISTS_COUNT"] = set.ExistsCounter;
        psi.Environment["STUB_AOAI_MARKER"] = set.GoneMarker;
        if (stubEnv is not null)
        {
            foreach (var (name, value) in stubEnv)
            {
                psi.Environment[name] = value;
            }
        }

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("live-m52-aoai.sh did not start");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        Assert.True(process.WaitForExit(120_000), "live-m52-aoai.sh did not exit within 120 s");
        var log = File.Exists(set.AzLog) ? File.ReadAllText(set.AzLog) : string.Empty;
        return new ExecResult(process.ExitCode, stdout.Result, stderr.Result, log);
    }

    // runs the canned az DIRECTLY - the script never involved - to pin the
    // verbs against the real CLI: a flag Azure refuses must be refused here
    // too (rc 2, "unrecognized arguments:"), or the stub hides exactly the
    // class of bug live run 2 proved.
    private (int Exit, string Out, string Err) ExecStub(params string[] args)
    {
        var psi = new ProcessStartInfo(Path.Combine(_stubBin, "az"))
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var arg in args)
        {
            psi.ArgumentList.Add(arg);
        }

        psi.Environment["PATH"] = _stubBin + ":/usr/bin:/bin";
        psi.Environment["STUB_AZ_LOG"] = Path.Combine(_stubBin, $"direct-{Guid.NewGuid():N}.log");
        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("the canned az did not start");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        Assert.True(process.WaitForExit(30_000), "the canned az did not exit within 30 s");
        return (process.ExitCode, stdout.Result, stderr.Result);
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
