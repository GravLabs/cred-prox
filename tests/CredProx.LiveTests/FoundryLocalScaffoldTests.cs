using System.Text.Json;
using Xunit;

namespace CredProx.LiveTests;

// The offline legs of the foundrylocal vendor: the machine-local env contract
// (temp files only — never the real live.env), the scratch handoff contract
// (a temp dir the cell owns), and the runner wiring — live-run.sh read as text,
// pinning that the foundrylocal vendor is fully armed: its case, filters, gate
// extensions, shared lifecycle arms, free-model gate, and the destroy-echo
// generalization that keeps the agenttokens pinned string byte-identical.
[Trait("Layer", "Offline")]
public sealed class FoundryLocalScaffoldTests : IDisposable
{
    private readonly string _tempPath =
        Path.Combine(Path.GetTempPath(), $"credprox-foundrylocal-env-{Guid.NewGuid():N}.env");
    private readonly string _scratchDir;

    public FoundryLocalScaffoldTests()
    {
        _scratchDir = _tempPath + ".scratch";
        Directory.CreateDirectory(_scratchDir);
    }

    [Fact]
    public void FileGate_NamesTheVariable_ModeAndRoundTrip()
    {
        var absent = LiveEnv.Probe(FoundryLocalEnv.Vendor, FoundryLocalEnv.RequiredKeys, _tempPath + ".absent");
        Assert.False(absent.Available);
        Assert.Contains("~/.config/credprox-live/live.env", absent.SkipReason, StringComparison.Ordinal);
        Assert.Contains("TENANT_ID", absent.SkipReason, StringComparison.Ordinal);

        File.WriteAllLines(_tempPath, new[] { "TENANT_ID=00000000-0000-0000-0000-000000000000" });
        File.SetUnixFileMode(
            _tempPath,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead); // 644
        var loose = LiveEnv.Probe(FoundryLocalEnv.Vendor, FoundryLocalEnv.RequiredKeys, _tempPath);
        Assert.False(loose.Available);
        Assert.Contains("mode 644, must be exactly 600", string.Join("; ", loose.Problems), StringComparison.Ordinal);

        File.SetUnixFileMode(_tempPath, UnixFileMode.UserRead | UnixFileMode.UserWrite); // 600
        var good = LiveEnv.Probe(FoundryLocalEnv.Vendor, FoundryLocalEnv.RequiredKeys, _tempPath);
        Assert.True(good.Available, string.Join("; ", good.Problems));
        Assert.Equal("00000000-0000-0000-0000-000000000000", good.Values["TENANT_ID"]);
    }

    [Fact]
    public void ValueProblems_GuidPasses_NonGuidNamesTheVariable()
    {
        Assert.Empty(FoundryLocalEnv.ValueProblems(
            new Dictionary<string, string> { ["TENANT_ID"] = "11111111-1111-1111-1111-111111111111" }));
        var problems = FoundryLocalEnv.ValueProblems(
            new Dictionary<string, string> { ["TENANT_ID"] = "not-a-guid" });
        Assert.Single(problems);
        Assert.Contains("TENANT_ID must be the Entra tenant id (a GUID)", problems[0], StringComparison.Ordinal);
    }

    [Fact]
    public void ScratchReaders_NameMissingFiles_EmptyFiles_AndTheAudienceShape()
    {
        var missing = Assert.Throws<InvalidOperationException>(
            () => FoundryLocalLiveFixture.ReadScratchApps(_scratchDir));
        Assert.Contains("app2-id.txt", missing.Message, StringComparison.Ordinal);
        Assert.Contains("scripts/live-run.sh foundrylocal", missing.Message, StringComparison.Ordinal);

        File.WriteAllText(Path.Combine(_scratchDir, "app2-id.txt"), "");
        var empty = Assert.Throws<InvalidOperationException>(
            () => FoundryLocalLiveFixture.ReadScratchApps(_scratchDir));
        Assert.Contains("zero-length", empty.Message, StringComparison.Ordinal);

        File.WriteAllText(Path.Combine(_scratchDir, "app2-id.txt"), "id-mapped");
        File.WriteAllText(Path.Combine(_scratchDir, "app2-secret.txt"), "secret-mapped");
        File.WriteAllText(Path.Combine(_scratchDir, "app3-id.txt"), "id-unmapped");
        File.WriteAllText(Path.Combine(_scratchDir, "app3-secret.txt"), "secret-unmapped");
        var apps = FoundryLocalLiveFixture.ReadScratchApps(_scratchDir);
        Assert.Equal(("id-mapped", "secret-mapped", "id-unmapped", "secret-unmapped"), apps);

        var audienceMissing = Assert.Throws<InvalidOperationException>(
            () => FoundryLocalLiveFixture.ReadScratchAudience(_scratchDir));
        Assert.Contains("resource-audience.txt", audienceMissing.Message, StringComparison.Ordinal);

        // v2 access tokens carry the API's client id as aud — a non-GUID here is
        // a wrong handoff, named without echoing its content.
        File.WriteAllText(Path.Combine(_scratchDir, "resource-audience.txt"), "not-a-guid");
        var audienceBad = Assert.Throws<InvalidOperationException>(
            () => FoundryLocalLiveFixture.ReadScratchAudience(_scratchDir));
        Assert.Contains("not the API's client id", audienceBad.Message, StringComparison.Ordinal);

        File.WriteAllText(Path.Combine(_scratchDir, "resource-audience.txt"), "22222222-2222-2222-2222-222222222222");
        Assert.Equal(
            "22222222-2222-2222-2222-222222222222",
            FoundryLocalLiveFixture.ReadScratchAudience(_scratchDir));
    }

    [Fact]
    public void RunnerWiring_FoundryLocalVendorIsFullyArmed()
    {
        var runner = File.ReadAllText(Path.Combine(RepoRoot(), "scripts", "live-run.sh"));

        // The dispatch case and its vendor-scoped filter.
        Assert.Contains("    foundrylocal)\n", runner, StringComparison.Ordinal);
        Assert.Contains(
            "FullyQualifiedName~FoundryLocal|FullyQualifiedName~LiveEnvContractTests",
            runner,
            StringComparison.Ordinal);

        // Named where a vendor is listed: unknown-vendor help and the dead-file note.
        Assert.Contains("agenttokens, foundrylocal, aca", runner, StringComparison.Ordinal);
        Assert.Contains("graph agenttokens foundrylocal aca", runner, StringComparison.Ordinal);

        // The gates: az sign-in and curl join the agenttokens arms; the three
        // shared lifecycle arms (leak scan over run-created secrets, create,
        // destroy) pair agenttokens with foundrylocal — the same script, the same
        // scratch, so exactly three such arms exist.
        Assert.Contains(
            "\"$vendor\" = \"foundrylocal\" ] || [ \"$vendor\" = \"aca\"",
            runner,
            StringComparison.Ordinal);
        Assert.Contains(
            "\"$vendor\" = \"agenttokens\" ] || [ \"$vendor\" = \"foundrylocal\" ]",
            runner,
            StringComparison.Ordinal);
        // The gate chains also carry that pair; the lifecycle arms are the elif
        // form — pin those three by their own shape (leak scan, create, destroy).
        Assert.Equal(3, CountOccurrences(
            runner,
            "elif [ \"$vendor\" = \"agenttokens\" ] || [ \"$vendor\" = \"foundrylocal\" ]; then"));
        // The billable passthrough is per-vendor opt-in: the free local model
        // itself needs no go-ahead (the gateway cell is marker-only), but the
        // vendor's cloud cell is billable, so the foundrylocal arm exists and is
        // keyed on the flag - it fires only when the central file sets
        // CREDPROX_M54_BILLABLE=1, and the key rides only with it. Exactly one
        // bare agenttokens-only if-arm remains.
        Assert.Equal(1, CountOccurrences(runner, "if [ \"$vendor\" = \"agenttokens\" ]; then"));
        Assert.Equal(1, CountOccurrences(
            runner,
            "if [ \"$vendor\" = \"foundrylocal\" ] && [ \"${loaded[CREDPROX_M54_BILLABLE]:-}\" = \"1\" ]; then"));

        // The free-model gate: dialled before any create, SKIP (not FAIL) when
        // absent, and its default is the same loopback base the code defaults to.
        Assert.Contains("no Foundry Local server answered", runner, StringComparison.Ordinal);
        Assert.Contains("/v1/models", runner, StringComparison.Ordinal);
        Assert.Contains("CREDPROX_FOUNDRYLOCAL_URL:-http://127.0.0.1:5273", runner, StringComparison.Ordinal);
        // One model predicate shared by gate and cell: the gate validates the
        // selected id with one tiny chat BEFORE any create, names a clear FAIL
        // when no id is selectable, and exports exactly the id it proved.
        Assert.Contains("export FOUNDRY_LOCAL_MODEL=", runner, StringComparison.Ordinal);
        Assert.Contains("/v1/chat/completions", runner, StringComparison.Ordinal);
        Assert.Contains("not loaded and answering", runner, StringComparison.Ordinal);

        // The runner exports its own vendor marker — the only token that can arm
        // a scratch-gated live cell, so the export exists exactly once and only
        // in the runner.
        Assert.Contains("export CREDPROX_LIVE_VENDOR=\"$vendor\"", runner, StringComparison.Ordinal);

        // The destroy echo generalizes to the vendor name, which keeps the
        // agenttokens pinned string byte-identical (vendor expands to the same
        // word) — so no literal agenttokens-prefixed echo may remain.
        Assert.Contains("$vendor destroy: read-back clean", runner, StringComparison.Ordinal);
        Assert.DoesNotContain("\"agenttokens destroy: read-back", runner, StringComparison.Ordinal);
    }

    [Fact]
    public void GatewayMeteredCell_ConsoleExporter_ShipsWithTheExportInterval()
    {
        // The gateway live cell waits for console counter batches, and the
        // console exporter prints on the OTEL cadence - default 60 s, longer
        // than the cell's settle window, and LiveHosts.CounterValue reads -1
        // until a batch has printed. A gateway env dict that turns the console
        // exporter on without shortening the cadence is a cell that false-REDs
        // on live runs, so refuse that shape here, offline: every
        // Metrics__Console line in that file must be matched by the interval
        // line its sibling metered cells use.
        var gateway = File.ReadAllText(Path.Combine(
            RepoRoot(), "tests", "CredProx.LiveTests", "FoundryLocalGatewayLiveTests.cs"));
        var consoles = CountOccurrences(gateway, "[\"Metrics__Console\"] = \"true\"");
        Assert.Equal(1, consoles);
        Assert.Equal(
            consoles,
            CountOccurrences(gateway, "[\"OTEL_METRIC_EXPORT_INTERVAL\"] = \"1000\""));
    }

    [Fact]
    public void ModelId_OneConfiguredSource_ExportedToTheCell_NeverCatalogOrder()
    {
        // The three parties name ONE model id: the configured id in the sample's
        // appsettings equals the shipped Agent's literal fallback (config and
        // code cannot drift silently), the runner validates and exports exactly
        // that selected id, and the live cell reads the exported variable — the
        // cell source keeps no first-of-catalog pick (the measured live-run-2
        // failure: the first /v1/models entry was never downloaded).
        var root = RepoRoot();
        using var appsettings = JsonDocument.Parse(
            File.ReadAllText(Path.Combine(root, "samples", "FoundryLocalAgent", "appsettings.json")));
        var configured = appsettings.RootElement
            .GetProperty("FoundryLocal").GetProperty("Model").GetString();
        Assert.False(string.IsNullOrWhiteSpace(configured), "the sample appsettings names no FoundryLocal Model");
        var agentProgram = File.ReadAllText(
            Path.Combine(root, "samples", "FoundryLocalAgent", "Agent", "Program.cs"));
        Assert.Contains($"?? \"{configured}\"", agentProgram, StringComparison.Ordinal);
        var liveSource = File.ReadAllText(
            Path.Combine(root, "tests", "CredProx.LiveTests", "FoundryLocalLiveTests.cs"));
        Assert.Contains("GetEnvironmentVariable(\"FOUNDRY_LOCAL_MODEL\")", liveSource, StringComparison.Ordinal);
        Assert.DoesNotContain("data\")[0]", liveSource, StringComparison.Ordinal);
        var runner = File.ReadAllText(Path.Combine(root, "scripts", "live-run.sh"));
        Assert.Contains("export FOUNDRY_LOCAL_MODEL=\"$fl_model\"", runner, StringComparison.Ordinal);
    }

    [Fact]
    public void PlantedScratch_NoRunnerMarker_KeepsScratchGatedCellsSkipped()
    {
        // The shared scratch planted WHOLE, exactly as a runner's create leaves
        // it — the point is that the handoff alone never arms a cell, whoever
        // created it.
        PlantHandoff(_scratchDir);

        // Offline leg (no marker): foundrylocal cells skip on the marker arm,
        // not on the scratch arm — revert the marker check and this cell is RED.
        var offline = LiveRunnerGate.Problems(FoundryLocalEnv.Vendor, null, _scratchDir);
        Assert.True(
            offline.Any(p => p.Contains("CREDPROX_LIVE_VENDOR", StringComparison.Ordinal)),
            "the marker arm vanished: a bare offline run would arm scratch-gated live cells");

        // An agenttokens marker (or an in-flight agenttokens leg) does not arm
        // foundrylocal cells either, and symmetrically a missing marker keeps the
        // agenttokens cells skipped even with this scratch planted.
        var mismatched = LiveRunnerGate.Problems(FoundryLocalEnv.Vendor, "agenttokens", _scratchDir);
        Assert.True(mismatched.Count > 0);
        var agenttokensOffline = LiveRunnerGate.Problems(AgentTokensEnv.Vendor, null, _scratchDir);
        Assert.True(
            agenttokensOffline.Any(p => p.Contains("CREDPROX_LIVE_VENDOR", StringComparison.Ordinal)),
            "the agenttokens cells armed on shared scratch alone");

        // The matching marker arms — and only then: without the handoff even the
        // right marker skips on the scratch arm.
        Assert.Empty(LiveRunnerGate.Problems(FoundryLocalEnv.Vendor, "foundrylocal", _scratchDir));
        var noScratch = _scratchDir + ".empty";
        Directory.CreateDirectory(noScratch);
        var missing = LiveRunnerGate.Problems(FoundryLocalEnv.Vendor, "foundrylocal", noScratch);
        Assert.True(
            missing.Any(p => p.Contains("handoff is missing", StringComparison.Ordinal)),
            "the right marker armed the cell with no handoff present");
    }

    [Fact]
    public void EveryLiveAttribute_WiresTheSharedRunnerGate()
    {
        // Mechanism claim, checked at the consumers: every live attribute — all
        // seven, not just the scratch-gated three — must route through the one
        // gate, or the marker rule lives in several places that can drift apart.
        // The metered attribute is declared inside its test file; the consumer
        // pin reads that file for the same reason.
        var root = RepoRoot();
        foreach (var file in new[]
                 {
                     "FoundryLocalLiveFactAttribute.cs",
                     "AgentTokensLiveFactAttribute.cs",
                     "AgentTokensBillableLiveFactAttribute.cs",
                     "AiGatewayLiveFactAttribute.cs",
                     "AiGatewayMeteredLiveTests.cs",
                     "GitHubAppLiveFactAttribute.cs",
                     "GraphLiveFactAttribute.cs",
                 })
        {
            var src = File.ReadAllText(Path.Combine(root, "tests", "CredProx.LiveTests", file));
            Assert.Contains("LiveRunnerGate.Problems", src, StringComparison.Ordinal);
        }
    }

    private static void PlantHandoff(string dir)
    {
        File.WriteAllText(Path.Combine(dir, "app2-id.txt"), "11111111-1111-1111-1111-111111111111");
        File.WriteAllText(Path.Combine(dir, "app2-secret.txt"), "planted-not-a-secret");
        File.WriteAllText(Path.Combine(dir, "app3-id.txt"), "33333333-3333-3333-3333-333333333333");
        File.WriteAllText(Path.Combine(dir, "app3-secret.txt"), "planted-not-a-secret");
        File.WriteAllText(Path.Combine(dir, "resource-audience.txt"), "44444444-4444-4444-4444-444444444444");
    }

    [Fact]
    public void ModelBaseUrl_DefaultMatchesTheRunnerGate_OverrideWins()
    {
        const string runnerDefault = "http://127.0.0.1:5273";
        var overrideValue = Environment.GetEnvironmentVariable("CREDPROX_FOUNDRYLOCAL_URL");
        if (string.IsNullOrEmpty(overrideValue))
        {
            Assert.Equal(runnerDefault, FoundryLocalEnv.ModelBaseUrl);
        }
        else
        {
            Assert.Equal(overrideValue.TrimEnd('/'), FoundryLocalEnv.ModelBaseUrl);
        }
    }

    private static int CountOccurrences(string haystack, string needle)
    {
        var count = 0;
        var at = 0;
        while ((at = haystack.IndexOf(needle, at, StringComparison.Ordinal)) >= 0)
        {
            count++;
            at += needle.Length;
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

        try
        {
            Directory.Delete(_scratchDir, recursive: true);
        }
        catch (IOException)
        {
            // temp litter is not a test failure
        }
    }
}
