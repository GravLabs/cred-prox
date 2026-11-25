using Xunit;

namespace CredProx.LiveTests;

// The offline witness for the rule that no bare or filtered dotnet test arms a
// live cell: EVERY live attribute requires the shared runner marker naming its
// own vendor. The cells evaluate the attributes themselves — attributes are pure
// env/file probes at construction time; they construct no fixture, start no
// host and open no socket — against a fake but well-shaped live env file (mode
// 600, placeholder ids, fake key material, nothing routable) inside a scratch
// HOME, so the env-shape arm passes deterministically on every machine and the
// owner's real env file is never in the path. Three arms per attribute: the
// variable absent skips naming the variable, a wrong vendor's marker skips
// naming the variable, and the matching vendor would run (no skip). Vendors
// whose cells read a run-created handoff take the would-run arm with a witness-
// planted handoff under a witness-owned scratch dir, and a fourth arm witnesses
// the handoff condition ALONE — matching marker over an empty scratch must skip
// naming the handoff — because every other scratch cell plants the handoff, so
// nothing else would notice the check being removed. The two foundrylocal
// attributes whose paths never touch Entra (the free gateway leg, the opt-in
// cloud billable leg) are marker-only and take the would-run arm without a
// handoff; the billable leg's two opt-in arms are each witnessed skipping
// loudly alone, as does the azureopenai billable leg's CREDPROX_M52_BILLABLE arm
// (AzureOpenAIBillableArm). Table_NamesEveryLiveFactAttribute is the completeness
// arm: the table is hand-written, so an attribute added without an entry would
// silently get no offline witness at all. There is no ACA live attribute: that vendor's cells are offline
// loopback by design.
[Trait("Layer", "Offline")]
public sealed class RunnerGateWitnessTests : IDisposable
{
    private const string FakeKey = "sk-ant-fake-witness-key-not-a-secret-000000";

    private readonly string _home = Path.Combine(Path.GetTempPath(), $"credprox-gate-witness-{Guid.NewGuid():N}");
    private readonly string? _originalHome = Environment.GetEnvironmentVariable("HOME");
    private readonly string? _originalVendor = Environment.GetEnvironmentVariable(LiveRunnerGate.RunnerVendorVariable);
    private readonly string? _originalScratch = Environment.GetEnvironmentVariable("CREDPROX_M46_SCRATCH");
    private readonly string? _originalMetered = Environment.GetEnvironmentVariable("CREDPROX_LIVE_METERED");
    private readonly string? _originalBillable = Environment.GetEnvironmentVariable("CREDPROX_M53_BILLABLE");
    private readonly string? _originalM54Billable = Environment.GetEnvironmentVariable("CREDPROX_M54_BILLABLE");
    private readonly string? _originalM52Billable = Environment.GetEnvironmentVariable("CREDPROX_M52_BILLABLE");
    private readonly string? _originalApiKey = Environment.GetEnvironmentVariable("ANTHROPIC_API_KEY");

    public RunnerGateWitnessTests()
    {
        // The fake env is shaped so every vendor's probe reports Available: a
        // GUID tenant, all-digit GitHub ids, a base64 that decodes to text
        // carrying "PRIVATE KEY", and a sk-ant- key that is fake by construction.
        var dir = Path.Combine(_home, ".config", "credprox-live");
        Directory.CreateDirectory(dir);
        var envFile = Path.Combine(dir, "live.env");
        File.WriteAllLines(envFile, new[]
        {
            "TENANT_ID=11111111-1111-1111-1111-111111111111",
            $"ANTHROPIC_API_KEY={FakeKey}",
            "APP_ID=123456",
            "INSTALLATION_ID=789012",
            "PRIVATE_KEY_BASE64=" + Convert.ToBase64String(
                System.Text.Encoding.UTF8.GetBytes("-----FAKE PRIVATE KEY----- witness filler, never a real key")),
            // shaped so the azureopenai probe reports Available too: the five
            // creation NAMES it builds a run's own resource from (witness values;
            // no dial and no create ever happens from this file here):
            "AZURE_OPENAI_LOCATION=credprox-witness-location",
            "AZURE_OPENAI_MODEL=credprox-witness-model",
            "AZURE_OPENAI_MODEL_VERSION=1.0",
            "AZURE_OPENAI_SKU=s0",
            "AZURE_OPENAI_DEPLOYMENT_SKU=Standard",
        });
        File.SetUnixFileMode(envFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        Environment.SetEnvironmentVariable("HOME", _home);
        Environment.SetEnvironmentVariable(LiveRunnerGate.RunnerVendorVariable, null);
    }

    // The whole witness stands on the central env path following HOME; if the
    // platform resolved the user profile from the account database instead,
    // this cell is RED and no attribute below is faked — the witness would be
    // reading the owner's file, which is exactly what it must never do.
    [Fact]
    public void HomeOverride_MovesTheCentralEnvPath()
    {
        Assert.StartsWith(_home, LiveEnv.CentralFilePath, StringComparison.Ordinal);
    }

    [Fact]
    public void VariableAbsent_EnvShapePresent_EveryLiveAttribute_SkipsNamingTheVariable()
    {
        Environment.SetEnvironmentVariable(LiveRunnerGate.RunnerVendorVariable, null);
        foreach (var (name, _, _, build) in LiveAttributes)
        {
            var skip = build().Skip;
            Assert.True(
                skip is not null && skip.Contains(LiveRunnerGate.RunnerVendorVariable, StringComparison.Ordinal),
                $"{name} armed with env shape present and no runner marker - skip: {skip}");
        }
    }

    [Fact]
    public void WrongVendorMarker_EveryLiveAttribute_SkipsNamingTheVariable()
    {
        // The most adversarial wrong value available: another live vendor's
        // legitimate marker — an in-flight agenttokens or aigateway leg arms
        // nothing else's cells.
        var wrongOf = new Dictionary<string, string>
        {
            [AgentTokensEnv.Vendor] = AiGatewayEnv.Vendor,
            [AiGatewayEnv.Vendor] = AgentTokensEnv.Vendor,
            [GitHubAppEnv.Vendor] = AgentTokensEnv.Vendor,
            [GraphEnv.Vendor] = AgentTokensEnv.Vendor,
            [FoundryLocalEnv.Vendor] = AiGatewayEnv.Vendor,
            [AzureOpenAIEnv.Vendor] = AgentTokensEnv.Vendor,
        };
        foreach (var (name, vendor, _, build) in LiveAttributes)
        {
            Environment.SetEnvironmentVariable(LiveRunnerGate.RunnerVendorVariable, wrongOf[vendor]);
            var skip = build().Skip;
            Assert.True(
                skip is not null && skip.Contains(LiveRunnerGate.RunnerVendorVariable, StringComparison.Ordinal),
                $"{name} armed on the {wrongOf[vendor]} vendor's marker - skip: {skip}");
        }
    }

    [Fact]
    public void MatchingVendorMarker_EnvOnlyAttributes_WouldRun()
    {
        Environment.SetEnvironmentVariable("CREDPROX_LIVE_METERED", "1");
        // The billable attribute's own opt-in arms are process variables; fake
        // values, and nothing runs anyway — the cell asserts the decision only.
        Environment.SetEnvironmentVariable("CREDPROX_M54_BILLABLE", "1");
        Environment.SetEnvironmentVariable("CREDPROX_M52_BILLABLE", "1");
        Environment.SetEnvironmentVariable("ANTHROPIC_API_KEY", FakeKey);
        foreach (var (name, vendor, needsScratch, build) in LiveAttributes)
        {
            if (needsScratch)
            {
                continue; // scratch-gated attributes have their own would-run cell
            }

            Environment.SetEnvironmentVariable(LiveRunnerGate.RunnerVendorVariable, vendor);
            var skip = build().Skip;
            Assert.True(skip is null, $"{name} skipped despite its matching marker - skip: {skip}");
        }
    }

    [Fact]
    public void MatchingVendorMarker_ScratchAttributes_WouldRun()
    {
        // Would-run for the scratch-gated attributes needs both arms: this
        // leg's marker AND a handoff — planted here, under a scratch dir this
        // cell owns, so no leftover scratch from any real run is in the path.
        var scratch = Path.Combine(_home, "scratch");
        Directory.CreateDirectory(scratch);
        File.WriteAllText(
            Path.Combine(scratch, "resource-audience.txt"),
            "44444444-4444-4444-4444-444444444444");
        Environment.SetEnvironmentVariable("CREDPROX_M46_SCRATCH", scratch);
        // The billable attribute's own opt-in arms are process variables; fake
        // values, and nothing runs anyway — the cell asserts the decision only.
        Environment.SetEnvironmentVariable("CREDPROX_M53_BILLABLE", "1");
        Environment.SetEnvironmentVariable("CREDPROX_M54_BILLABLE", "1");
        Environment.SetEnvironmentVariable("ANTHROPIC_API_KEY", FakeKey);
        foreach (var (name, vendor, needsScratch, build) in LiveAttributes)
        {
            if (!needsScratch)
            {
                continue;
            }

            Environment.SetEnvironmentVariable(LiveRunnerGate.RunnerVendorVariable, vendor);
            var skip = build().Skip;
            Assert.True(
                skip is null,
                $"{name} skipped with its matching marker and a planted handoff - skip: {skip}");
        }
    }

    [Fact]
    public void MatchingVendorMarker_EmptyScratch_SkipsNamingTheHandoff()
    {
        // The gate's second condition, witnessed alone: the marker matches and
        // the scratch dir exists but holds no handoff. Deadening the
        // File.Exists check would arm these attributes with nothing created —
        // real az apps that no leg owns — and no other cell here would notice,
        // so this one asserts the skip names exactly the missing handoff and
        // nothing else.
        var scratch = Path.Combine(_home, "empty-scratch");
        Directory.CreateDirectory(scratch);
        Environment.SetEnvironmentVariable("CREDPROX_M46_SCRATCH", scratch);
        // The billable attribute's own opt-ins are set so the handoff is the
        // only problem in its skip; nothing runs — the decision is asserted.
        Environment.SetEnvironmentVariable("CREDPROX_M53_BILLABLE", "1");
        Environment.SetEnvironmentVariable("ANTHROPIC_API_KEY", FakeKey);
        foreach (var (name, vendor, needsScratch, build) in LiveAttributes)
        {
            if (!needsScratch)
            {
                continue;
            }

            Environment.SetEnvironmentVariable(LiveRunnerGate.RunnerVendorVariable, vendor);
            var skip = build().Skip;
            Assert.True(
                skip is not null
                    && skip.Contains("run-created app handoff", StringComparison.Ordinal)
                    && !skip.Contains(LiveRunnerGate.RunnerVendorVariable, StringComparison.Ordinal),
                $"{name} with its matching marker over an empty scratch must skip naming exactly the handoff - skip: {skip}");
        }
    }

    [Fact]
    public void CloudBillableArms_EachMissingOptIn_SkipsNamingIt()
    {
        // The cloud cell's two extra arms, each witnessed alone (the shared
        // marker is present throughout): without the go-ahead the skip names
        // CREDPROX_M54_BILLABLE; with the go-ahead but no key it names
        // ANTHROPIC_API_KEY. Both present with the matching marker is the
        // would-run case, covered by the env-only would-run cell.
        Environment.SetEnvironmentVariable(LiveRunnerGate.RunnerVendorVariable, FoundryLocalEnv.Vendor);
        Environment.SetEnvironmentVariable("CREDPROX_M54_BILLABLE", null);
        var noGoAhead = new FoundryLocalCloudBillableLiveFactAttribute().Skip;
        Assert.True(
            noGoAhead is not null && noGoAhead.Contains("CREDPROX_M54_BILLABLE", StringComparison.Ordinal),
            $"the cloud billable cell armed without the go-ahead - skip: {noGoAhead}");
        Environment.SetEnvironmentVariable("CREDPROX_M54_BILLABLE", "1");
        Environment.SetEnvironmentVariable("ANTHROPIC_API_KEY", null);
        var noKey = new FoundryLocalCloudBillableLiveFactAttribute().Skip;
        Assert.True(
            noKey is not null && noKey.Contains("ANTHROPIC_API_KEY", StringComparison.Ordinal),
            $"the cloud billable cell armed without an Anthropic key - skip: {noKey}");
    }
    [Fact]
    public void AzureOpenAIBillableArm_MissingGoAhead_SkipsNamingIt()
    {
        // The azureopenai billable leg's own arm, witnessed alone: the env file is
        // shaped and the marker matches, so the only problem left is the missing
        // CREDPROX_M52_BILLABLE=1 go-ahead — and the skip must name exactly it.
        // The armed case is the env-only would-run cell; the env-shape and marker
        // arms are the shared cells above. Nothing runs — the decision is asserted.
        Environment.SetEnvironmentVariable(LiveRunnerGate.RunnerVendorVariable, AzureOpenAIEnv.Vendor);
        Environment.SetEnvironmentVariable("CREDPROX_M52_BILLABLE", null);
        var noGoAhead = new AzureOpenAILiveFactAttribute().Skip;
        Assert.True(
            noGoAhead is not null && noGoAhead.Contains("CREDPROX_M52_BILLABLE", StringComparison.Ordinal),
            $"the azureopenai billable attribute armed without the go-ahead - skip: {noGoAhead}");
    }
    [Fact]
    public void Table_NamesEveryLiveFactAttribute()
    {
        // The completeness arm: the table above is hand-written, and a future live
        // attribute that skips it would get zero offline witness — every one of
        // its skip arms would go dark exactly when it is added. The assembly's
        // live attributes are found by the ILiveFactAttribute MARKER, not by the
        // name suffix (post-release item 7: the suffix was never the concept -
        // renaming a live gate darkened its witness silently, and an ordinary
        // attribute carrying the suffix would have been drafted into the live
        // table), and the two sets must agree in both directions so a stale
        // table entry is as RED as a missing one.
        var tabled = LiveAttributes
            .Select(e => e.Build().GetType().Name)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();
        var present = typeof(RunnerGateWitnessTests).Assembly.GetTypes()
            .Where(t => !t.IsAbstract && typeof(FactAttribute).IsAssignableFrom(t)
                && typeof(ILiveFactAttribute).IsAssignableFrom(t))
            .Select(t => t.Name)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();
        Assert.True(tabled.SequenceEqual(present),
            $"the witness table and the assembly disagree; untabled attributes: "
            + $"[{string.Join(", ", present.Except(tabled))}]; table entries with no such attribute: "
            + $"[{string.Join(", ", tabled.Except(present))}]");
    }

    // Each entry is (witness label, the vendor whose marker arms it, whether the
    // attribute also demands the run-created handoff, a factory) — attributes
    // decide at construction, so the marker is set BEFORE the factory runs,
    // never after. The two foundrylocal marker-only attributes are the gateway
    // free leg (no Entra anywhere on its path, so the handoff would be evidence
    // about a route it never takes) and the cloud billable leg (marker plus its
    // own two opt-in arms, witnessed skipping loudly in CloudBillableArms).
    private static (string Name, string Vendor, bool NeedsScratch, Func<FactAttribute> Build)[] LiveAttributes { get; } =
    [
        ("aigateway", AiGatewayEnv.Vendor, false, static () => new AiGatewayLiveFactAttribute()),
        ("aigateway-metered", AiGatewayEnv.Vendor, false, static () => new AiGatewayMeteredLiveFactAttribute()),
        ("githubapp", GitHubAppEnv.Vendor, false, static () => new GitHubAppLiveFactAttribute()),
        ("graph", GraphEnv.Vendor, false, static () => new GraphLiveFactAttribute()),
        ("agenttokens", AgentTokensEnv.Vendor, true, static () => new AgentTokensLiveFactAttribute()),
        ("agenttokens-billable", AgentTokensEnv.Vendor, true, static () => new AgentTokensBillableLiveFactAttribute()),
        ("foundrylocal", FoundryLocalEnv.Vendor, true, static () => new FoundryLocalLiveFactAttribute()),
        ("foundrylocal-gateway", FoundryLocalEnv.Vendor, false, static () => new FoundryLocalGatewayLiveFactAttribute()),
        ("foundrylocal-cloud-billable", FoundryLocalEnv.Vendor, false, static () => new FoundryLocalCloudBillableLiveFactAttribute()),
        // marker-only like the foundrylocal legs, though this one's run DOES mint a
        // resource: its handoff is the runner-exported endpoint and deployment env,
        // not a scratch file this attribute reads. Billable: its
        // CREDPROX_M52_BILLABLE skip is witnessed alone in AzureOpenAIBillableArm
        // below, mirroring CloudBillableArms.
        ("azureopenai-billable", AzureOpenAIEnv.Vendor, false, static () => new AzureOpenAILiveFactAttribute()),
    ];

    public void Dispose()
    {
        Environment.SetEnvironmentVariable("HOME", _originalHome);
        Environment.SetEnvironmentVariable(LiveRunnerGate.RunnerVendorVariable, _originalVendor);
        Environment.SetEnvironmentVariable("CREDPROX_M46_SCRATCH", _originalScratch);
        Environment.SetEnvironmentVariable("CREDPROX_LIVE_METERED", _originalMetered);
        Environment.SetEnvironmentVariable("CREDPROX_M53_BILLABLE", _originalBillable);
        Environment.SetEnvironmentVariable("CREDPROX_M54_BILLABLE", _originalM54Billable);
        Environment.SetEnvironmentVariable("CREDPROX_M52_BILLABLE", _originalM52Billable);
        Environment.SetEnvironmentVariable("ANTHROPIC_API_KEY", _originalApiKey);
        try
        {
            Directory.Delete(_home, recursive: true);
        }
        catch (IOException)
        {
            // temp litter is not a test failure
        }
    }
}
