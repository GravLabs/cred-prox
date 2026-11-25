using System.Diagnostics;
using Xunit;

namespace CredProx.LiveTests;

// The offline legs of the azureopenai vendor. Three classes: the machine-local env
// contract (temp files only — never the real live.env), the runner wiring read as text
// plus the shared marker gate armed for a marker-only vendor, and the canned-runner
// witnesses that exec the REAL live-run.sh for the azureopenai leg under stubbed az,
// curl and dotnet. The unarmed leg creates and dials nothing at all; the armed one
// runs the real lifecycle script against the canned az below, with the scratch under
// the stub dir so every handoff lands in a path the Dispose sweep removes.

[Trait("Layer", "Offline")]
public sealed class AzureOpenAIEnvContractTests : IDisposable
{
    private readonly string _tempPath =
        Path.Combine(Path.GetTempPath(), $"credprox-azureopenai-env-{Guid.NewGuid():N}.env");

    [Fact]
    public void FileGate_NamesTheVariable_ModeAndRoundTrip()
    {
        var absent = LiveEnv.Probe(AzureOpenAIEnv.Vendor, AzureOpenAIEnv.RequiredKeys, _tempPath + ".absent");
        Assert.False(absent.Available);
        Assert.Contains("~/.config/credprox-live/live.env", absent.SkipReason, StringComparison.Ordinal);
        Assert.Contains("AZURE_OPENAI_LOCATION", absent.SkipReason, StringComparison.Ordinal);

        File.WriteAllLines(_tempPath, new[]
        {
            "AZURE_OPENAI_LOCATION=credprox-witness-location",
            "AZURE_OPENAI_MODEL=credprox-witness-model",
            "AZURE_OPENAI_MODEL_VERSION=1.0",
            "AZURE_OPENAI_SKU=s0",
            "AZURE_OPENAI_DEPLOYMENT_SKU=Standard",
        });
        File.SetUnixFileMode(
            _tempPath,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead); // 644
        var loose = LiveEnv.Probe(AzureOpenAIEnv.Vendor, AzureOpenAIEnv.RequiredKeys, _tempPath);
        Assert.False(loose.Available);
        Assert.Contains("mode 644, must be exactly 600", string.Join("; ", loose.Problems), StringComparison.Ordinal);

        File.SetUnixFileMode(_tempPath, UnixFileMode.UserRead | UnixFileMode.UserWrite); // 600
        var good = LiveEnv.Probe(AzureOpenAIEnv.Vendor, AzureOpenAIEnv.RequiredKeys, _tempPath);
        Assert.True(good.Available, string.Join("; ", good.Problems));
        Assert.Equal("credprox-witness-model", good.Values["AZURE_OPENAI_MODEL"]);
    }

    [Fact]
    public void RequiredKeys_AreTheFiveCreationNames_Exactly()
    {
        // M52 part B: the central file names WHAT to create - region, model, version,
        // account SKU and deployment SKU - never a standing endpoint (that would be
        // the form the owner replaced). The runner's dispatch case repeats these
        // five names; the canned-runner missing-names cell proves the runner's list,
        // and drift between the two lists is caught by whichever side changes first.
        Assert.Equal(
            new[] { "AZURE_OPENAI_LOCATION", "AZURE_OPENAI_MODEL", "AZURE_OPENAI_MODEL_VERSION", "AZURE_OPENAI_SKU", "AZURE_OPENAI_DEPLOYMENT_SKU" },
            AzureOpenAIEnv.RequiredKeys);
    }

    [Fact]
    public void EndpointShape_StillGatesTheDial_TheRunnerExportedValue()
    {
        // The cell keeps the https Azure-suffix gate for the endpoint the runner
        // exports after create: a wrong-shape dial still cannot leave the harness.
        Assert.True(AzureOpenAIEnv.IsPlausibleEndpoint("https://credprox-witness.openai.azure.com"));
        Assert.True(AzureOpenAIEnv.IsPlausibleEndpoint("https://credprox-witness.cognitiveservices.azure.com"));
        foreach (var bad in new[] { "http://credprox-witness.openai.azure.com", "not a url", "https://contoso.example.com", "" })
        {
            Assert.False(AzureOpenAIEnv.IsPlausibleEndpoint(bad));
        }
    }

    public void Dispose()
    {
        try
        {
            if (File.Exists(_tempPath))
            {
                File.Delete(_tempPath);
            }
        }
        catch (IOException)
        {
            // temp litter is not a test failure
        }
    }
}

[Trait("Layer", "Offline")]
public sealed class AzureOpenAIScaffoldTests
{
    [Fact]
    public void RunnerWiring_AzureOpenAIVendorIsFullyArmed()
    {
        var runner = File.ReadAllText(Path.Combine(RepoRoot(), "scripts", "live-run.sh"));

        // The dispatch case, its vendor-scoped filter, and the five creation NAMES
        // the central file must carry (M52 part B: no standing endpoint is required
        // - the run creates its own resource).
        Assert.Contains("    azureopenai)\n", runner, StringComparison.Ordinal);
        Assert.Contains(
            "FullyQualifiedName~AzureOpenAI|FullyQualifiedName~LiveEnvContractTests",
            runner,
            StringComparison.Ordinal);
        Assert.Contains(
            "required=\"AZURE_OPENAI_LOCATION AZURE_OPENAI_MODEL AZURE_OPENAI_MODEL_VERSION AZURE_OPENAI_SKU AZURE_OPENAI_DEPLOYMENT_SKU\"",
            runner,
            StringComparison.Ordinal);

        // Named where a vendor is listed: the unknown-vendor help and the dead-file note.
        Assert.Contains("agenttokens, foundrylocal, aca, azureopenai)", runner, StringComparison.Ordinal);
        Assert.Contains("graph agenttokens foundrylocal aca azureopenai; do", runner, StringComparison.Ordinal);

        // The gates: azureopenai LEFT the shared az sign-in chain (its zero-spend
        // run creates and dials nothing and needs no az); its armed create leg
        // carries its own az and curl gates. It must still NOT join the
        // Entra-lifecycle chains, and the secret-propagation wait stays 3-vendor.
        Assert.DoesNotContain(
            "\"$vendor\" = \"aca\" ] || [ \"$vendor\" = \"azureopenai\" ]",
            runner,
            StringComparison.Ordinal);
        Assert.Equal(1, CountOccurrences(
            runner,
            "if [ \"$vendor\" = \"graph\" ] || [ \"$vendor\" = \"agenttokens\" ] || [ \"$vendor\" = \"foundrylocal\" ] || [ \"$vendor\" = \"aca\" ]; then"));
        Assert.Equal(1, CountOccurrences(
            runner,
            "if [ \"$vendor\" = \"graph\" ] || [ \"$vendor\" = \"agenttokens\" ] || [ \"$vendor\" = \"foundrylocal\" ]; then"));
        Assert.Equal(3, CountOccurrences(
            runner,
            "elif [ \"$vendor\" = \"agenttokens\" ] || [ \"$vendor\" = \"foundrylocal\" ]; then"));

        // The go-ahead is per-vendor opt-in from the central file ONLY (an ambient
        // CREDPROX_M52_BILLABLE in the caller's env arms nothing: the armed block
        // keys off $aoai_armed, set beside that single loaded[] check), and it arms
        // CREATE. The old standing-endpoint passthrough is gone.
        Assert.Equal(1, CountOccurrences(
            runner,
            "if [ \"$vendor\" = \"azureopenai\" ] && [ \"${loaded[CREDPROX_M52_BILLABLE]:-}\" = \"1\" ]; then"));
        Assert.DoesNotContain(
            "export AZURE_OPENAI_DEPLOYMENT=\"${loaded[AZURE_OPENAI_DEPLOYMENT]}\"",
            runner,
            StringComparison.Ordinal);
        Assert.Contains("aoai_armed=1", runner, StringComparison.Ordinal);
        Assert.Contains(
            "if [ \"$vendor\" = \"azureopenai\" ] && [ \"$aoai_armed\" = \"1\" ]; then",
            runner,
            StringComparison.Ordinal);

        // The create-and-destroy lifecycle wiring: the helper execs, the destroy is
        // ARMED BEFORE the create and joins the EXIT trap, and the dial names come
        // from the scratch handoff, exported for the live cell.
        Assert.Contains("\"$repo_root/scripts/live-m52-aoai.sh\" create 2>&1 | tee -a \"$log\"", runner, StringComparison.Ordinal);
        Assert.Contains("\"$repo_root/scripts/live-m52-aoai.sh\" destroy 2>&1 | tee -a \"$log\"", runner, StringComparison.Ordinal);
        Assert.True(
            runner.IndexOf("aoai_infra_created=1", StringComparison.Ordinal)
            < runner.IndexOf("\"$repo_root/scripts/live-m52-aoai.sh\" create", StringComparison.Ordinal),
            "the destroy must be armed before the create, not after it");
        Assert.Contains("trap 'graph_destroy; agenttokens_destroy; aca_destroy; aoai_destroy; leak_scan' EXIT", runner, StringComparison.Ordinal);
        Assert.Contains("export AZURE_OPENAI_ENDPOINT=\"$aoai_endpoint\"", runner, StringComparison.Ordinal);
        Assert.Contains("export AZURE_OPENAI_DEPLOYMENT=\"$aoai_deployment\"", runner, StringComparison.Ordinal);

        // The role-propagation wait: printed deadline, the GA data-plane MODELS-LIST
        // probe dialed through ONE named api-version variable (live run 4 died
        // because the runner dialed the REMOVED deployments-list verb - a caller
        // with the very role this run grants gets 404 there), so that literal is
        // pinned ABSENT; 401 AND 403 AND no-answer poll while anything-else fails;
        // the budget name-shaped like every other wait; and the old
        // standing-endpoint preflight stays gone.
        Assert.Contains("openai/models?api-version=$AOAI_DATA_PLANE_API_VERSION", runner, StringComparison.Ordinal);
        Assert.Contains("AOAI_DATA_PLANE_API_VERSION=\"2024-10-21\"", runner, StringComparison.Ordinal);
        Assert.Equal(1, CountOccurrences(runner, "api-version="));
        Assert.DoesNotContain("openai/deployments?api-version=", runner, StringComparison.Ordinal);
        Assert.Contains("401|403|000|'') ;;", runner, StringComparison.Ordinal);
        Assert.Contains("never went live within", runner, StringComparison.Ordinal);
        Assert.Contains("CREDPROX_M52_AOAI_ROLE_WAIT_SECONDS", runner, StringComparison.Ordinal);
        Assert.DoesNotContain("401|403) ;;", runner, StringComparison.Ordinal);
        Assert.DoesNotContain("did not answer (http $aoai_code)", runner, StringComparison.Ordinal);

        // The run's own principal id is leak-scanned: it names the owner, and the
        // helper/wait keep it in variables only.
        Assert.Contains("aoai-principal-guid", runner, StringComparison.Ordinal);

        // The runner still exports its vendor marker exactly once, and only in the
        // runner — the only token that can arm the marker-gated live cell.
        Assert.Equal(1, CountOccurrences(runner, "export CREDPROX_LIVE_VENDOR=\"$vendor\""));
    }

    [Fact]
    public void MarkerGate_MarkerOnlyVendor_NamesForeignAndMissingMarkers()
    {
        // azureopenai's attribute reads no run-created scratch file (the run's
        // endpoint and deployment travel as runner-exported env): the marker-only
        // overload is the whole gate, and it stays shut for a missing or foreign
        // marker.
        var missing = LiveRunnerGate.Problems(AzureOpenAIEnv.Vendor, null);
        Assert.Single(missing);
        Assert.Contains("CREDPROX_LIVE_VENDOR is not set", missing[0], StringComparison.Ordinal);
        Assert.Contains("azureopenai", missing[0], StringComparison.Ordinal);

        var foreign = LiveRunnerGate.Problems(AzureOpenAIEnv.Vendor, "graph");
        Assert.Single(foreign);
        Assert.Contains("\"graph\"", foreign[0], StringComparison.Ordinal);
        Assert.Contains("azureopenai", foreign[0], StringComparison.Ordinal);

        Assert.Empty(LiveRunnerGate.Problems(AzureOpenAIEnv.Vendor, AzureOpenAIEnv.Vendor));
    }

    [Fact]
    public void DeploymentName_OneFallback_SharedWithTheShippedAllowList()
    {
        // The live cell names one deployment, from AZURE_OPENAI_DEPLOYMENT or the same
        // literal the shipped chat-app allow-list pins — config and code cannot drift
        // silently, and the refused half of the live cell calls a name no rule admits.
        using var appsettings = System.Text.Json.JsonDocument.Parse(File.ReadAllText(
            Path.Combine(RepoRoot(), "samples", "AzureOpenAI", "appsettings.json")));
        var paths = appsettings.RootElement
            .GetProperty("CredProx").GetProperty("Callers").GetProperty("chat-app")
            .GetProperty("Operations")[0].GetProperty("Paths")[0].GetString();
        Assert.Equal("/aoai/openai/deployments/gpt-4o/**", paths);
        var liveSource = File.ReadAllText(
            Path.Combine(RepoRoot(), "tests", "CredProx.LiveTests", "AzureOpenAILiveTests.cs"));
        Assert.Contains("GetEnvironmentVariable(\"AZURE_OPENAI_DEPLOYMENT\") ?? \"gpt-4o\"", liveSource, StringComparison.Ordinal);
        Assert.Contains("/aoai/openai/deployments/credprox-not-admitted/chat/completions", liveSource, StringComparison.Ordinal);
        // The cell overrides the chat-app deployment rule for the deployment it dials
        // (see the env dict in the live cell): dropping that entry or repointing it
        // away from the {deployment} variable flips this pin RED.
        Assert.Contains(
            "[\"CredProx__Callers__chat-app__Operations__0__Paths__0\"] = $\"/aoai/openai/deployments/{deployment}/**\"",
            liveSource,
            StringComparison.Ordinal);
    }

    [Fact]
    public void LiveCellBody_ReasoningModelShape_NoLegacyField()
    {
        // The live cell dials whichever model live.env names, and the deployed one
        // is a reasoning model: Microsoft's reasoning how-to puts max_tokens on the
        // unsupported list for that family and counts reasoning tokens inside
        // max_completion_tokens. The live leg belongs to a separate run decision,
        // so the request shape is pinned here, offline, from the cell's own source:
        // the cap present, the legacy field gone, and the effort field ABSENT on
        // purpose - the accepted values for the deployed model are unverified and
        // omission is the one shape every reasoning model is known to take, so a
        // guessed effort must not creep back. The legacy max_tokens body fails
        // all three asserts; a body carrying a guessed effort fails the absence
        // one.
        var liveSource = File.ReadAllText(
            Path.Combine(RepoRoot(), "tests", "CredProx.LiveTests", "AzureOpenAILiveTests.cs"));
        // The three body asserts bind to the body REGION, not the whole file:
        // the region is the raw-string literal from `var body = """` to its
        // closing `""";`, and a historical note elsewhere in the live file that
        // names the legacy cap field must not move this cell. The version pins
        // below stay whole-file: they guard the two chat URLs, which the body
        // region cannot reach.
        var bodyStart = liveSource.IndexOf("var body = \"\"\"", StringComparison.Ordinal);
        Assert.True(bodyStart >= 0, "the live cell must build its chat body in one raw-string literal");
        var bodyEnd = liveSource.IndexOf("\"\"\";", bodyStart, StringComparison.Ordinal);
        Assert.True(bodyEnd > bodyStart, "the chat body literal must be closed");
        var body = liveSource.Substring(bodyStart, bodyEnd - bodyStart);
        Assert.Contains("\"max_completion_tokens\":2000", body, StringComparison.Ordinal);
        Assert.DoesNotContain("\"reasoning_effort\"", body, StringComparison.Ordinal);
        Assert.DoesNotContain("\"max_tokens\"", body, StringComparison.Ordinal);
        // The cap field has a release floor - the API version lifecycle guide
        // adds it in 2024-09-01-preview - so both of the cell's URLs must dial
        // the GA data-plane release the reference page names, through ONE named
        // const shared by the two URLs so a version can never drift between
        // them. A cell reverted to the older release it first shipped on, or a
        // version re-inlined at either URL, flips one of the two asserts below.
        Assert.Contains("ChatApiVersion = \"2024-10-21\"", liveSource, StringComparison.Ordinal);
        Assert.Equal(2, CountOccurrences(liveSource, "api-version={ChatApiVersion}"));
    }

    private static int CountOccurrences(string haystack, string needle)
    {
        var count = 0;
        var at = haystack.IndexOf(needle, StringComparison.Ordinal);
        while (at >= 0)
        {
            count++;
            at = haystack.IndexOf(needle, at + needle.Length, StringComparison.Ordinal);
        }

        return count;
    }

    private static string RepoRoot()
    {
        var parts = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar)
            .Split(Path.DirectorySeparatorChar);
        var binIndex = Array.IndexOf(parts, "bin");
        Assert.True(binIndex >= 3, $"unexpected test assembly location '{AppContext.BaseDirectory}'");
        return string.Join(Path.DirectorySeparatorChar, parts[..(binIndex - 2)]);
    }
}

// Witness for the azureopenai leg of scripts/live-run.sh as it now works: the runner
// CREATES the whole resource with scripts/live-m52-aoai.sh, waits for the role to go
// live on the created endpoint, exports endpoint + deployment to the test process, and
// destroys everything again on exit. These cells exec the REAL runner under a canned az
// that plays the ENTIRE lifecycle (group, account, deployment, role assignment and
// their teardown, every query the helper asks answered), a curl that answers the
// role-propagation probe with scripted codes, and a dotnet stub that records the three
// names the runner exported into a side file, never its stdout, because the runner's
// own leak scan would rightly fail the leg on anything echoed into the log. The canned
// az logs ONE short verb line per call - flags never logged - so the planted principal
// GUID and the canned resource scope must be provably absent from EVERY stream, the
// instrument's own log included. No real az, no network, no endpoint beyond the
// obviously-fake canned one. The class name and every
// method name here deliberately avoid ALL of live-run.sh's --filter tokens (hence "Aoai",
// the vendor's own route prefix, never "AzureOpenAI"): a leg filter substring-matches the
// fully-qualified name case-insensitively, so a token-bearing name on a class that execs
// the real runner would be SELECTED by that vendor's live leg and exec a nested runner.
// That invariant is enforced against live-run.sh itself by
// RunnerRunCreatedScanTests.NamesCarryNoRunnerFilterToken.
[Trait("Layer", "Offline")]
public sealed class AoaiRunnerWitnessTests : ExecutesLiveRunner, IDisposable
{
    // the five NAMES a run builds its own resource from — all the azureopenai
    // entries the central file carries now (fake witness values: a location string,
    // a model name, a version, an account SKU, a deployment SKU tier; no endpoint
    // and no dial ever comes from here):
    private static readonly string[] NamesLines =
    [
        "AZURE_OPENAI_LOCATION=credprox-witness-location",
        "AZURE_OPENAI_MODEL=credprox-witness-model",
        "AZURE_OPENAI_MODEL_VERSION=1.0",
        "AZURE_OPENAI_SKU=s0",
        "AZURE_OPENAI_DEPLOYMENT_SKU=Standard",
    ];

    // obviously fake by construction: a patterned GUID, an all-zero-ish resource
    // id, and an endpoint host that routes nowhere:
    private const string PlantedPrincipal = "11112222-3333-4444-5555-666677778888";
    private const string CannedScope =
        "/subscriptions/aaaaaaaa-0000-0000-0000-000000000000/resourceGroups/credprox-m52"
        + "/providers/Microsoft.CognitiveServices/accounts/canned-account";
    private const string CannedEndpoint = "https://canned-host.openai.azure.com";

    // canned az: plays the WHOLE live-m52-aoai.sh + live-run.sh azureopenai
    // lifecycle offline. Every call logs one short verb line (flags NEVER logged -
    // the planted principal and canned scope must be absent from the instrument too),
    // so witness cells can assert verb ORDER and the total absence of any write verb.
    // The arms answer exactly the queries the helper and the runner ask:
    //   STUB_AZ_LOG                 one verb line per call (shared harness name)
    //   STUB_AOAI_FAIL=group|account|deployment|role|delete|purge|resource|listdeleted
    //                               that verb exits 7 (listdeleted: 4, every poll)
    //   STUB_AOAI_PROV_STATE        provisioningState answer (default Succeeded)
    //   STUB_AOAI_LOCAL_AUTH        disableLocalAuth answer OVERRIDE; unset default
    //                               is True ONLY after the az resource update set
    //                               verb ran (marker ${STUB_AZ_LOG}.lauth), empty
    //                               before it - the live read-back reality
    //   STUB_AOAI_MODEL_LIFECYCLE   model list answer for the named name+version
    //                               (unset default GenerallyAvailable; '' answers '')
    //   STUB_AOAI_ENDPOINT          properties.endpoint answer (default the canned one)
    //   STUB_AOAI_PRINCIPAL         signed-in user id (default the planted GUID)
    //   STUB_AOAI_ROLE_COUNT        force every role-list answer (else: 1 until the
    //                               group is deleted or found gone, then 0 - reality)
    //   STUB_AOAI_ROLE_FAIL=1       role list errors (the deleted-scope zero-shape)
    //   STUB_AOAI_SHOW_ID_FAIL=1    account show --query id errors (already gone)
    //   STUB_AOAI_NO_TOKEN=1        the --query accessToken call fails (no bearer)
    //   STUB_AOAI_EXISTS_COUNT      counter-file path: indexes the exists answers
    //   STUB_AOAI_EXISTS_SEQ        comma list of group-exists answers, the last one
    //                               repeats once spent (default false,true,false:
    //                               create finds the name free, destroy finds it
    //                               present, the poll finds it gone). A read NEVER
    //                               trips the gone marker - reads report, only the
    //                               group delete mutates the reality model
    //   STUB_AOAI_PURGE_STILL       soft-deleted-list answer pinned to 1 forever
    //                               (the name is still listed after purge)
    //   STUB_AOAI_PURGE_SEQ         comma list of list-deleted answers, the last
    //                               one repeating once spent (default "0" = absent
    //                               from the first read; "1,1,0" = the async settle
    //                               live run 1 observed). Indexed by a counter
    //                               beside the per-exec log (${STUB_AZ_LOG}.pcount)
    //   STUB_AOAI_MARKER            file touched once the group is gone
    //   STUB_AOAI_UPDATE_SEQ        answers provisioningState reads AFTER the
    //                               local-auth PATCH (live run 2 hypothesis: the
    //                               update re-provisions; default Succeeded)
    // Each verb rejects '-' flags the real CLI does not take (rc 2), and the
    // local-auth reality marker is set ONLY by the literal
    // --set properties.disableLocalAuth=true.
    public const string StubAoaiAz = """
        #!/usr/bin/env bash
        log() { if [ -n "${STUB_AZ_LOG:-}" ]; then printf 'az %s\n' "$*" >> "$STUB_AZ_LOG"; fi; }
        gone_marker() { if [ -n "${STUB_AOAI_MARKER:-}" ]; then : > "$STUB_AOAI_MARKER"; fi; }
        # the id-shaped string the real CLI embeds in error bodies, and a
        # planted principal - both must stay INSIDE the stub's stderr, never
        # on the script's output: az_write prints only the error code.
        CANNED_ARM_ID="/subscriptions/aaaaaaaa-0000-0000-0000-000000000000/resourceGroups/credprox-m52/providers/Microsoft.CognitiveServices/accounts/canned-account"
        fail_body() {
            # $1 = shape: code (Code: token), paren ((Word) fallback), or junk
            # (neither shape); $2 = the code word. The body always carries the
            # planted principal and the canned id - a leak path if the script
            # ever echoes stderr instead of extracting the code.
            case "$1" in
                code)
                    printf 'Long running operation failed with status InternalServerError. The client object id %s with scope %s could not be resolved. Message body that must never be printed. Service request id: canned-rid.\nCode: %s\n' \
                        "${STUB_AOAI_PRINCIPAL:-11112222-3333-4444-5555-666677778888}" "$CANNED_ARM_ID" "$2" 1>&2 ;;
                paren)
                    printf 'Assertion failed: (%s) The client with object id %s does not have authorization to perform the action over scope %s. Message body that must never be printed.\n' \
                        "$2" "${STUB_AOAI_PRINCIPAL:-11112222-3333-4444-5555-666677778888}" "$CANNED_ARM_ID" 1>&2 ;;
                *)
                    printf 'unexpected internal error with no code token at all, object id %s over scope %s, message body that must never be printed\n' \
                        "${STUB_AOAI_PRINCIPAL:-11112222-3333-4444-5555-666677778888}" "$CANNED_ARM_ID" 1>&2 ;;
            esac
        }
        # each verb answers ONLY the PRIMARY flag forms the real CLI takes for
        # it (audited against az <verb> --help on this host): a stub that
        # accepted everything is what hid the location flag on list-deleted in
        # live run 2. Short aliases (-l, -y, -n) are NOT on the lists, so the
        # stub is deliberately STRICTER than the real CLI: an edit that drifts
        # to an alias form false-REDs offline instead of sailing through. A
        # '-' token off the verb's list: rc 2, "unrecognized arguments:", and
        # a reject line in the log - the REJECTION SHAPE like the real CLI.
        chk() {
            local list="$1" tok
            shift
            for tok in "$@"; do
                case "$tok" in
                    -*)
                        case " $list " in
                            *" $tok "*) ;;
                            *)
                                printf 'unrecognized arguments: %s\n' "$tok" 1>&2
                                log "reject $tok"
                                exit 2 ;;
                        esac ;;
                esac
            done
        }
        case "$*" in
            *"get-access-token"*accessToken*)
                chk "--scope --query -o" "$@"
                log "account get-access-token"
                if [ "${STUB_AOAI_NO_TOKEN:-}" = "1" ]; then exit 1; fi
                printf 'canned-fake-token-not-a-jwt\n'; exit 0 ;;
            *"get-access-token"*)
                chk "--scope --query -o" "$@"
                log "account get-access-token"; exit 0 ;;
            *"signed-in-user show"*)
                chk "--query -o" "$@"
                log "ad signed-in-user show"
                printf '%s\n' "${STUB_AOAI_PRINCIPAL:-11112222-3333-4444-5555-666677778888}"; exit 0 ;;
            *"model list"*)
                chk "--location --query -o" "$@"
                log "cognitiveservices model list"
                # The answer keys on the query text: only the FULL predicate the
                # helper sends - kind, the run's own name and version equality,
                # and the lifecycleStatus projection - gets the knob's answer.
                # A query missing a clause (a broken JMESPath) matches nothing
                # here, exactly what the real catalog read prints for a query
                # naming no listed entry: empty, which the guard reads as
                # uncatalogued.
                case "$*" in
                    *"kind=='OpenAI'"*"model.name=='$AZURE_OPENAI_MODEL'"*"model.version=='$AZURE_OPENAI_MODEL_VERSION'"*"model.lifecycleStatus"*)
                        # '-' not ':-': an explicitly empty knob answers empty, which is
                        # what the real catalog read prints for a name+version it does
                        # not list; unset still answers the healthy default.
                        printf '%s\n' "${STUB_AOAI_MODEL_LIFECYCLE-GenerallyAvailable}" ;;
                esac
                exit 0 ;;
            *"group exists"*)
                chk "--name --query -o" "$@"
                log "group exists"
                n=0; if [ -f "${STUB_AOAI_EXISTS_COUNT:-/nonexistent}" ]; then n="$(cat "$STUB_AOAI_EXISTS_COUNT")"; fi
                n=$((n+1)); printf '%s' "$n" > "$STUB_AOAI_EXISTS_COUNT"
                # scripted answer sequence: answer number n of STUB_AOAI_EXISTS_SEQ,
                # the last answer repeating once the list is spent. A read NEVER
                # touches the gone marker: reads report, only the delete mutates.
                IFS=','; set -- ${STUB_AOAI_EXISTS_SEQ:-false,true,false}; unset IFS
                if [ "$n" -le "$#" ]; then printf '%s\n' "${!n}"; else printf '%s\n' "${@: -1}"; fi
                exit 0 ;;
            *"group delete"*)
                chk "--name --yes --no-wait" "$@"
                log "group delete"
                if [ "${STUB_AOAI_FAIL:-}" = "delete" ]; then fail_body code Conflict; exit 7; fi
                gone_marker; exit 0 ;;
            *"group create"*)
                chk "--name --location" "$@"
                log "group create"
                if [ "${STUB_AOAI_FAIL:-}" = "group" ]; then fail_body code AuthorizationFailed; exit 7; fi
                exit 0 ;;
            *"account deployment create"*)
                chk "--resource-group --name --deployment-name --model-name --model-version --model-format --sku-name --sku-capacity --query -o" "$@"
                log "deployment create"
                if [ "${STUB_AOAI_FAIL:-}" = "deployment" ]; then fail_body junk; exit 7; fi
                # live run 2 collision model: a deployment create against the
                # account while its post-update provisioning has not reached
                # Succeeded fails. The answer is the NEXT entry of the scripted
                # post-update sequence - what the last poll saw, or the first
                # entry when no post-update poll ran at all.
                if [ -n "${STUB_AZ_LOG:-}" ] && [ -f "${STUB_AZ_LOG}.lauth" ]; then
                    n=0; if [ -f "${STUB_AZ_LOG}.ucount" ]; then n="$(cat "${STUB_AZ_LOG}.ucount")"; fi
                    i=$((n+1))
                    IFS=','; set -- ${STUB_AOAI_UPDATE_SEQ:-Succeeded}; unset IFS
                    if [ "$i" -le "$#" ]; then ans="${!i}"; else ans="${@: -1}"; fi
                    [ "$ans" = "Succeeded" ] || exit 9
                fi
                exit 0 ;;
            *"deployment show"*)
                chk "--resource-group --name --deployment-name --query -o" "$@"
                log "deployment show"; exit 0 ;;
            *"account create"*)
                chk "--name --resource-group --location --kind --sku --custom-domain --yes" "$@"
                log "account create"
                if [ "${STUB_AOAI_FAIL:-}" = "account" ]; then fail_body code ServiceQuotaExceeded; exit 7; fi
                exit 0 ;;
            *"account purge"*)
                chk "--location --resource-group --name" "$@"
                log "account purge"
                if [ "${STUB_AOAI_FAIL:-}" = "purge" ]; then fail_body code Conflict; exit 7; fi
                exit 0 ;;
            *"account list-deleted"*)
                # NO location or scope argument - the real verb takes none
                # (live run 2: --location = rc 2 unrecognized arguments).
                # FAIL arms every poll (the error shape the third state is
                # graded against); else the pinned-still knob, else the scripted
                # settle sequence indexed by the per-exec counter file.
                chk "--query -o" "$@"
                log "account list-deleted"
                if [ "${STUB_AOAI_FAIL:-}" = "listdeleted" ]; then exit 4; fi
                if [ "${STUB_AOAI_PURGE_STILL:-}" = "1" ]; then printf '1\n'; exit 0; fi
                n=1
                if [ -n "${STUB_AZ_LOG:-}" ]; then
                    n=0; if [ -f "${STUB_AZ_LOG}.pcount" ]; then n="$(cat "${STUB_AZ_LOG}.pcount")"; fi
                    n=$((n+1)); printf '%s' "$n" > "${STUB_AZ_LOG}.pcount"
                fi
                IFS=','; set -- ${STUB_AOAI_PURGE_SEQ:-0}; unset IFS
                if [ "$n" -le "$#" ]; then printf '%s\n' "${!n}"; else printf '%s\n' "${@: -1}"; fi
                exit 0 ;;
            *provisioningState*)
                chk "--name --resource-group --query -o" "$@"
                log "account show provisioningState"
                # After the local-auth ARM PATCH the account can report Updating
                # again (live run 2 hypothesis). Post-update reads answer the
                # scripted STUB_AOAI_UPDATE_SEQ, indexed by a per-exec counter
                # beside the log (same shape as STUB_AOAI_PURGE_SEQ); pre-update
                # reads keep answering STUB_AOAI_PROV_STATE. The marker is set
                # only by the resource update WRITE below - a read never flips
                # reality.
                if [ -n "${STUB_AZ_LOG:-}" ] && [ -f "${STUB_AZ_LOG}.lauth" ]; then
                    n=0; if [ -f "${STUB_AZ_LOG}.ucount" ]; then n="$(cat "${STUB_AZ_LOG}.ucount")"; fi
                    n=$((n+1)); printf '%s' "$n" > "${STUB_AZ_LOG}.ucount"
                    IFS=','; set -- ${STUB_AOAI_UPDATE_SEQ:-Succeeded}; unset IFS
                    if [ "$n" -le "$#" ]; then printf '%s\n' "${!n}"; else printf '%s\n' "${@: -1}"; fi
                    exit 0
                fi
                printf '%s\n' "${STUB_AOAI_PROV_STATE:-Succeeded}"; exit 0 ;;
            *"resource update"*)
                # the ARM PATCH that actually sets disableLocalAuth; WRITE verb,
                # so it sets the reality marker the read arm below consults -
                # but ONLY for the literal documented set: a PATCH flipping any
                # other property must leave reality untouched, so a script that
                # patches the wrong path fails the behavioural read-back, not
                # just the text pin.
                chk "--ids --set" "$@"
                log "resource update localAuth"
                if [ "${STUB_AOAI_FAIL:-}" = "resource" ]; then fail_body code ResourceNotFound; exit 7; fi
                case "$*" in
                    *"--set properties.disableLocalAuth=true"*)
                        if [ -n "${STUB_AZ_LOG:-}" ]; then : > "${STUB_AZ_LOG}.lauth"; fi ;;
                esac
                exit 0 ;;
            *disableLocalAuth*)
                # matches the read AND (without the arm above) the set verb - the
                # resource update arm must stay in front of this one. Answers True
                # only once the set verb ran: a create flag that never set the
                # property reads back empty, as live run 1 proved.
                chk "--name --resource-group --query -o" "$@"
                log "account show disableLocalAuth"
                if [ -n "${STUB_AOAI_LOCAL_AUTH:-}" ]; then printf '%s\n' "$STUB_AOAI_LOCAL_AUTH"; exit 0; fi
                if [ -n "${STUB_AZ_LOG:-}" ] && [ -f "${STUB_AZ_LOG}.lauth" ]; then printf 'True\n'; else printf '\n'; fi
                exit 0 ;;
            *properties.endpoint*)
                chk "--name --resource-group --query -o" "$@"
                log "account show endpoint"
                printf '%s\n' "${STUB_AOAI_ENDPOINT:-https://canned-host.openai.azure.com}"; exit 0 ;;
            *"account show"*"--query id"*)
                chk "--name --resource-group --query -o" "$@"
                log "account show id"
                if [ "${STUB_AOAI_SHOW_ID_FAIL:-}" = "1" ]; then exit 4; fi
                printf '%s\n' "/subscriptions/aaaaaaaa-0000-0000-0000-000000000000/resourceGroups/credprox-m52/providers/Microsoft.CognitiveServices/accounts/canned-account"
                exit 0 ;;
            *"role assignment create"*)
                chk "--role --assignee-object-id --assignee-principal-type --scope" "$@"
                log "role assignment create"
                if [ "${STUB_AOAI_FAIL:-}" = "role" ]; then fail_body paren Forbidden; exit 7; fi
                exit 0 ;;
            *"role assignment list"*)
                chk "--scope --role --query -o" "$@"
                log "role assignment list"
                if [ "${STUB_AOAI_ROLE_FAIL:-}" = "1" ]; then exit 3; fi
                if [ -n "${STUB_AOAI_ROLE_COUNT:-}" ]; then printf '%s\n' "$STUB_AOAI_ROLE_COUNT"; exit 0; fi
                if [ -n "${STUB_AOAI_MARKER:-}" ] && [ -f "$STUB_AOAI_MARKER" ]; then printf '0\n'; else printf '1\n'; fi
                exit 0 ;;
            *)
                log "other"; exit 0 ;;
        esac
        """;

    // dotnet stub: records the THREE names the runner exported into the test
    // process (the go-ahead flag, the endpoint and the deployment) into
    // $STUB_DOTNET_ENV (values NEVER on stdout — the runner tees test stdout into
    // the scanned log), then reports like a passing leg.
    private const string StubDotnetCapture = """
        #!/usr/bin/env bash
        if [ -n "${STUB_AZ_LOG:-}" ]; then printf 'dotnet %s\n' "$*" >> "$STUB_AZ_LOG"; fi
        if [ -n "${STUB_DOTNET_ENV:-}" ]; then
            printf 'M52_BILLABLE=%s\nENDPOINT=%s\nDEPLOYMENT=%s\n' "${CREDPROX_M52_BILLABLE:-}" "${AZURE_OPENAI_ENDPOINT:-}" "${AZURE_OPENAI_DEPLOYMENT:-}" > "$STUB_DOTNET_ENV"
        fi
        echo "OBSERVED azureopenai-billable-stub"
        exit 0
        """;

    // curl stub: the shared counted-code shape — the role-propagation probe is
    // the only caller this leg makes (-o /dev/null with -w %{http_code}; the
    // bearer header arrives as a -K - config on stdin, which cat consumes and
    // drops) — but ROUTE-AWARE, because the path-blind answer is exactly what let
    // the removed deployments-list verb pass every offline gate while live run 4
    // got 404: the deployments-list path answers 404 ALWAYS and consumes no
    // scripted code (the verb is not in the current data-plane API, Azure 404s
    // any caller there), the models-list probe answers STUB_CURL_CODES (last
    // value repeating), and anything else still answers 200. Reverting the
    // runner's probe path to the deployments list burns the go-ahead cell against
    // its scripted 200.
    private const string StubCurlCodes = """
        #!/usr/bin/env bash
        if [ -n "${STUB_AZ_LOG:-}" ]; then printf 'curl %s\n' "$*" >> "$STUB_AZ_LOG"; fi
        cat >/dev/null
        case "$*" in
            *openai/deployments\?api-version=*)
                # removed verb: a 404 for every caller, role or not - never a scripted code
                printf '%s' '404'
                ;;
            *-o\ /dev/null*openai/models*)
                n=0
                if [ -n "${STUB_CURL_COUNT:-}" ] && [ -f "$STUB_CURL_COUNT" ]; then n="$(cat "$STUB_CURL_COUNT")"; fi
                n=$((n+1)); printf '%s' "$n" > "$STUB_CURL_COUNT"
                codes=(${STUB_CURL_CODES:-401})
                i=$((n-1)); if [ "$i" -ge "${#codes[@]}" ]; then i=$(( ${#codes[@]} - 1 )); fi
                printf '%s' "${codes[$i]}"
                ;;
            *)
                printf '%s' '200'
                ;;
        esac
        """;

    private readonly string _stubBin;
    private readonly string _countFile;
    private readonly string _runner;
    private string? _home;
    private string? _runnerLog;

    public AoaiRunnerWitnessTests()
    {
        _stubBin = Path.Combine(Path.GetTempPath(), $"credprox-m52-awsstub-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_stubBin);
        SecretPropagationStubs.WriteExec(_stubBin, "az", StubAoaiAz);
        SecretPropagationStubs.WriteExec(_stubBin, "dotnet", StubDotnetCapture);
        SecretPropagationStubs.WriteExec(_stubBin, "curl", StubCurlCodes);
        _countFile = Path.Combine(_stubBin, "curl-count");
        _runner = SecretPropagationStubs.LocateRunner();
    }

    [Fact]
    public void GoAhead_CreatesWaitsExportsAndDestroysCleanly()
    {
        // the full billable story end to end, against canned az: create in the
        // promised order, wait for the role on the CREATED endpoint, hand the cell
        // the flag + created endpoint + created deployment, then destroy with both
        // read-backs clean and no identity material anywhere.
        var run = Run("azureopenai", NamesLines.Append("CREDPROX_M52_BILLABLE=1").ToArray(), "200");
        Assert.True(run.Exit == 0, $"the armed leg must pass: exit={run.Exit} out={run.Out} err={run.Err}");
        Assert.Contains("PASS azureopenai: azureopenai-billable-stub", run.Out, StringComparison.Ordinal);
        // a leg that exited 0 must have opened its log — without this the absence
        // checks would pass vacuously:
        Assert.NotEmpty(run.RunnerLog);
        // the capture must live inside the stub dir the sweep removes, and it can
        // carry values, so it must not sit world-readable behind a umask:
        Assert.StartsWith(_stubBin, run.Capture, StringComparison.Ordinal);
        var captured = Capture(run.Capture);
        Assert.Equal("1", captured["M52_BILLABLE"]);
        Assert.Equal(CannedEndpoint, captured["ENDPOINT"]);
        Assert.Equal("credprox-m52", captured["DEPLOYMENT"]);
        // the create/teardown ORDER, read off the instrument's verb log:
        var at = new Dictionary<string, int>();
        foreach (var verb in new[] { "az group create", "az account create", "az deployment create", "az role assignment create", "az group delete" })
        {
            var i = run.Log.IndexOf(verb, StringComparison.Ordinal);
            Assert.True(i >= 0, $"the canned az never saw '{verb}':\n{run.Log}");
            at[verb] = i;
        }

        Assert.True(
            at["az group create"] < at["az account create"]
            && at["az account create"] < at["az deployment create"]
            && at["az deployment create"] < at["az role assignment create"]
            && at["az role assignment create"] < at["az group delete"],
            $"wrong create/teardown verb order:\n{run.Log}");
        Assert.Contains("OK: the role is live on the endpoint after", run.Out, StringComparison.Ordinal);
        Assert.Contains("aoai destroy: read-back clean (resource group gone, role assignments zero)", run.Out, StringComparison.Ordinal);
        Assert.False(Directory.Exists(run.Scratch), "the run's scratch handoff dir must be gone after destroy");
        // the owner's identity material reaches NO stream the leg records - stdout,
        // stderr, the verb instrument and the real runner log the leak scan reads:
        foreach (var secret in new[] { PlantedPrincipal, CannedScope })
        {
            Assert.DoesNotContain(secret, run.Out + run.Err + run.Log + run.RunnerLog, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void UnarmedRun_CreatesNothingAndStaysInsideTheRunner()
    {
        // the zero-billable core of the redesign: the same shaped file, the flag
        // NOT set, and a stray AZURE_OPENAI_DEPLOYMENT sitting in the central file -
        // the leg passes having created nothing, dialed nothing and exported nothing.
        var run = Run(
            "azureopenai",
            NamesLines.Append("CREDPROX_M52_BILLABLE=0").Append("AZURE_OPENAI_DEPLOYMENT=canary-deployment").ToArray(),
            "401");
        Assert.True(run.Exit == 0, $"the unarmed leg must still pass: exit={run.Exit} out={run.Out} err={run.Err}");
        Assert.Contains("OBSERVED azureopenai-billable-stub", run.Out, StringComparison.Ordinal);
        Assert.DoesNotContain("az group create", run.Log, StringComparison.Ordinal);
        Assert.DoesNotContain("az account create", run.Log, StringComparison.Ordinal);
        Assert.DoesNotContain("curl", run.Log, StringComparison.Ordinal);
        var captured = Capture(run.Capture);
        Assert.Equal(string.Empty, captured["M52_BILLABLE"]);
        Assert.Equal(string.Empty, captured["ENDPOINT"]);
        Assert.Equal(string.Empty, captured["DEPLOYMENT"]);
        Assert.DoesNotContain("canary-deployment", run.Out + run.Err + run.Log, StringComparison.Ordinal);
    }

    [Fact]
    public void ForeignVendorLeg_DoesNotCarryTheAoaiOptIns()
    {
        // the same flag and stray deployment lines, but the leg is another vendor's:
        // the passthrough is per-vendor, so the capture must see neither. (aigateway
        // is the cheapest real leg: one required name, no lifecycle, no preflight.)
        var run = Run("aigateway", new[] { "ANTHROPIC_API_KEY=canary-m52-aigw-key-0123456789abcdef", "CREDPROX_M52_BILLABLE=1", "AZURE_OPENAI_DEPLOYMENT=canary-deployment" }, "401");
        Assert.True(run.Exit == 0, $"the aigateway leg must pass: exit={run.Exit} out={run.Out} err={run.Err}");
        var captured = Capture(run.Capture);
        Assert.Equal(string.Empty, captured["M52_BILLABLE"]);
        Assert.Equal(string.Empty, captured["ENDPOINT"]);
        Assert.Equal(string.Empty, captured["DEPLOYMENT"]);
        Assert.DoesNotContain("canary-m52-aigw", run.Out + run.Err + run.Log, StringComparison.Ordinal);
    }

    [Fact]
    public void MissingCreationNames_SkipNamingAllFive()
    {
        var run = Run("azureopenai", new[] { "# nothing this vendor needs" }, "401");
        Assert.True(run.Exit == 2, $"missing required variables must SKIP: exit={run.Exit} out={run.Out}");
        Assert.Contains(
            "missing variables: AZURE_OPENAI_LOCATION AZURE_OPENAI_MODEL AZURE_OPENAI_MODEL_VERSION AZURE_OPENAI_SKU AZURE_OPENAI_DEPLOYMENT_SKU",
            run.Out,
            StringComparison.Ordinal);
    }

    [Fact]
    public void CreateFails_ArmedDestroySweepsAnyway()
    {
        // the account create fails after the group is already up - the step that
        // would leave the most behind: the armed destroy must run and report clean
        // anyway, and the leg must fail WITHOUT reaching the test process.
        var run = Run(
            "azureopenai",
            NamesLines.Append("CREDPROX_M52_BILLABLE=1").ToArray(),
            "200",
            new Dictionary<string, string> { ["STUB_AOAI_FAIL"] = "account" });
        Assert.True(run.Exit == 1, $"a failed create must FAIL the leg: exit={run.Exit} out={run.Out} err={run.Err}");
        Assert.Contains("FAIL: live-m52-aoai.sh create failed (ids never shown)", run.Out, StringComparison.Ordinal);
        Assert.Contains("aoai destroy: read-back clean (resource group gone, role assignments zero)", run.Out, StringComparison.Ordinal);
        Assert.Contains("az group delete", run.Log, StringComparison.Ordinal);
        Assert.False(File.Exists(run.Capture), "a leg that died at create must never reach the test process");
    }

    [Fact]
    public void RoleNeverLive_FailsTheLegBeforeTheCell_AndStillDestroys()
    {
        // 403 forever is propagation that never lands: the leg must fail on its
        // PRINTED deadline without ever running the cell (zero spend), and the
        // destroy must still sweep. The 1 s budget makes exactly one poll happen.
        var run = Run(
            "azureopenai",
            NamesLines.Append("CREDPROX_M52_BILLABLE=1").ToArray(),
            "403",
            new Dictionary<string, string> { ["CREDPROX_M52_AOAI_ROLE_WAIT_SECONDS"] = "1" });
        Assert.True(run.Exit == 1, $"a role that never propagates must FAIL the leg: exit={run.Exit} out={run.Out} err={run.Err}");
        Assert.Contains("aoai role wait: polling the created endpoint up to 1 s - deadline", run.Out, StringComparison.Ordinal);
        Assert.Contains("FAIL: the role never went live within 1 s of polling the endpoint", run.Out, StringComparison.Ordinal);
        Assert.False(File.Exists(run.Capture), "the live cell must never have been reached");
        Assert.Contains("az role assignment create", run.Log, StringComparison.Ordinal);
        Assert.Contains("az group delete", run.Log, StringComparison.Ordinal);
    }

    [Fact]
    public void RoleWait401_IsKeptWaiting_AndFailsOnDeadlineLike403()
    {
        // a 401 to the authenticated models list is the role decision not having
        // reached this resource yet - propagation still propagating, exactly the
        // 403 sibling above: the waiter must burn its budget and fail on the
        // PRINTED deadline, never on the not-propagation abort, never reach the
        // cell, and still sweep the destroy. The arm that drops 401 from the
        // keep-waiting codes would abort this leg as "not role propagation"
        // instead; this cell is the behavioural witness that arm must stay wide.
        // The 1 s budget makes exactly one poll happen.
        var run = Run(
            "azureopenai",
            NamesLines.Append("CREDPROX_M52_BILLABLE=1").ToArray(),
            "401",
            new Dictionary<string, string> { ["CREDPROX_M52_AOAI_ROLE_WAIT_SECONDS"] = "1" });
        Assert.True(run.Exit == 1, $"a kept-waiting 401 must FAIL the leg: exit={run.Exit} out={run.Out} err={run.Err}");
        Assert.Contains("aoai role wait: polling the created endpoint up to 1 s - deadline", run.Out, StringComparison.Ordinal);
        Assert.Contains("FAIL: the role never went live within 1 s of polling the endpoint", run.Out, StringComparison.Ordinal);
        Assert.DoesNotContain("that is not role propagation", run.Out, StringComparison.Ordinal);
        Assert.False(File.Exists(run.Capture), "the live cell must never have been reached");
        Assert.Contains("az role assignment create", run.Log, StringComparison.Ordinal);
        Assert.Contains("az group delete", run.Log, StringComparison.Ordinal);
    }

    [Fact]
    public void RoleWaitBadAnswer_FailsImmediatelyNotAsPropagation()
    {
        // a 404 to an AUTHENTICATED models list is not "still propagating" -
        // waiting on it would hide a broken leg, so it fails at once, still armed
        // to destroy. (This is the answer the runner saw live on the REMOVED
        // deployments-list verb; the probe no longer dials that path, and the
        // curl stub 404s it regardless of any scripted codes.)
        var run = Run("azureopenai", NamesLines.Append("CREDPROX_M52_BILLABLE=1").ToArray(), "404");
        Assert.True(run.Exit == 1, $"a non-403 answer must FAIL the leg: exit={run.Exit} out={run.Out}");
        Assert.Contains("- that is not role propagation; aborting before the live cell", run.Out, StringComparison.Ordinal);
        Assert.False(File.Exists(run.Capture), "the live cell must never have been reached");
        Assert.Contains("az group delete", run.Log, StringComparison.Ordinal);
    }

    [Fact]
    public void RoleWaitWithoutBearerToken_FailsImmediately()
    {
        // no token means the probe can only ever see 403s - exactly the pattern the
        // waiter treats as propagating - so it must abort before the wait, not poll
        // an unauthenticated door for five minutes.
        var run = Run(
            "azureopenai",
            NamesLines.Append("CREDPROX_M52_BILLABLE=1").ToArray(),
            "200",
            new Dictionary<string, string> { ["STUB_AOAI_NO_TOKEN"] = "1" });
        Assert.True(run.Exit == 1, $"a missing bearer token must FAIL the leg: exit={run.Exit} out={run.Out}");
        Assert.Contains("FAIL: no bearer token for the role-propagation probe", run.Out, StringComparison.Ordinal);
        Assert.False(File.Exists(run.Capture), "the live cell must never have been reached");
        Assert.Contains("az group delete", run.Log, StringComparison.Ordinal);
    }

    [Fact]
    public void UnknownVendor_HelpNamesAoaiVendor()
    {
        var run = Run("nopevendor", NamesLines, "401");
        Assert.True(run.Exit == 2, $"an unknown vendor must SKIP: exit={run.Exit} out={run.Out}");
        Assert.Contains("known vendors: githubapp, aigateway, graph, agenttokens, foundrylocal, aca, azureopenai)", run.Out, StringComparison.Ordinal);
    }

    private static Dictionary<string, string> Capture(string captureFile)
    {
        var lines = File.ReadAllLines(captureFile);
        Assert.Equal(3, lines.Length);
        var map = new Dictionary<string, string>();
        foreach (var line in lines)
        {
            var split = line.IndexOf('=', StringComparison.Ordinal);
            Assert.True(split > 0, $"capture line without a name: {line}");
            map[line[..split]] = line[(split + 1)..];
        }

        return map;
    }

    private sealed record RunnerRun(int Exit, string Out, string Err, string Log, string RunnerLog, string Capture, string Scratch);

    // stubEnv entries ride into the runner's environment (and so into the canned
    // az, the helper and the curl stub); the three fixed stub-plumbing names are
    // set here so every run gets its OWN scratch, exists-counter and gone-marker.
    private RunnerRun Run(string vendor, string[] envFileLines, string curlCodes, Dictionary<string, string>? stubEnv = null)
    {
        _home = Path.Combine(Path.GetTempPath(), $"credprox-m52-awshome-{Guid.NewGuid():N}");
        var confDir = Path.Combine(_home, ".config", "credprox-live");
        Directory.CreateDirectory(confDir);
        var envFile = Path.Combine(confDir, "live.env");
        File.WriteAllText(envFile, string.Join('\n', envFileLines) + "\n");
        File.SetUnixFileMode(envFile, UnixFileMode.UserRead | UnixFileMode.UserWrite); // exactly 600
        var azLogPath = Path.Combine(Path.GetTempPath(), $"credprox-m52-awzlog-{Guid.NewGuid():N}.log");
        // inside the stub dir, so the directory cleanup in Dispose sweeps it too —
        // the values never leave a loose file in the shared temp dir:
        var capturePath = Path.Combine(_stubBin, $"dotnetenv-{Guid.NewGuid():N}.txt");
        // the run's scratch lands inside the stub dir the sweep removes (the helper
        // mkdirs it 700; destroy rm -rf's it; Dispose catches any leftover):
        var scratch = Path.Combine(_stubBin, $"scratch-{Guid.NewGuid():N}");
        var psi = new ProcessStartInfo
        {
            FileName = "/bin/bash",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add(_runner);
        psi.ArgumentList.Add(vendor);
        // the stub dir LEADS PATH: it shadows the machine's az, any real dotnet and
        // the real curl (nothing may reach a tenant, the network or a resource);
        psi.Environment["PATH"] = _stubBin + ":/usr/bin:/bin";
        psi.Environment["HOME"] = _home;
        psi.Environment["STUB_AZ_LOG"] = azLogPath;
        psi.Environment["STUB_DOTNET_ENV"] = capturePath;
        psi.Environment["STUB_CURL_COUNT"] = _countFile;
        psi.Environment["STUB_CURL_CODES"] = curlCodes;
        psi.Environment["CREDPROX_M52_AOAI_SCRATCH"] = scratch;
        psi.Environment["STUB_AOAI_EXISTS_COUNT"] = Path.Combine(_stubBin, $"exists-{Guid.NewGuid():N}");
        psi.Environment["STUB_AOAI_MARKER"] = Path.Combine(_stubBin, $"gone-{Guid.NewGuid():N}");
        if (stubEnv is not null)
        {
            foreach (var (name, value) in stubEnv)
            {
                psi.Environment[name] = value;
            }
        }

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("live-run.sh did not start");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        string azLog;
        try
        {
            Assert.True(process.WaitForExit(120_000), "live-run.sh did not exit within 120 s");
            azLog = File.Exists(azLogPath) ? File.ReadAllText(azLogPath) : string.Empty;
        }
        finally
        {
            // the delete rides a finally: the timeout assert used to throw PAST
            // it and orphan the canned az log (verbs only, but still a file
            // this harness promised to clean) under /tmp.
            File.Delete(azLogPath);
        }
        // the stub wrote the capture with the process umask; it can carry values,
        // so it gets the env file's exact 600. On SKIP/FAIL legs the runner exits
        // before the dotnet stub ever runs - then there is no capture to protect:
        if (File.Exists(capturePath))
        {
            File.SetUnixFileMode(capturePath, UnixFileMode.UserRead | UnixFileMode.UserWrite); // exactly 600
        }

        var runnerLog = RunnerLogPath(stdout.Result);
        _runnerLog = runnerLog;
        return new RunnerRun(
            process.ExitCode,
            stdout.Result,
            stderr.Result,
            azLog,
            runnerLog,
            capturePath,
            scratch);
    }

    // the runner mktemp-creates its log in the shared temp dir and echoes "log: <path>"
    // — the PATH is what Dispose must keep (reading the content here instead would
    // throw the name away and orphan one log per run).
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
        foreach (var dir in new[] { _stubBin, _home })
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
