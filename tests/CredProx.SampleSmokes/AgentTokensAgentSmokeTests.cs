using Xunit;

namespace CredProx.SampleSmokes;

// M53: the sample's real tool-calling agent, run as its own process against the scripted
// Anthropic stand-in. These cells drive the SAME Agent.dll a developer runs, so what they
// prove is the shipped sample path, not a test fixture. Same collection as the identity
// smokes: same host, same stubs, no second stack.
[Collection("AgentTokens")]
public sealed class AgentTokensAgentSmokeTests
{
    // The committed demo vendor key (appsettings.json Secrets). It must reach the provider
    // stub (attached by CredProx) and must NEVER appear in the agent's output.
    private const string DemoVendorKey = "credprox-agent-sample-demo-key-replace-me";

    private readonly AgentTokensFixture _stub;

    public AgentTokensAgentSmokeTests(AgentTokensFixture stub) => _stub = stub;

    [Fact]
    [Trait("Sample", "AgentTokens")]
    public async Task AgentLoop_RunsBothTools_TheRefusalIsAToolError_NotACrash()
    {
        await _stub.ResetProviderScenariosAsync();
        var token = _stub.Issue("demo-agent-client", new[] { "docs-read", "model-call" }, _stub.Now, "tok-loop");

        var (exit, output) = await _stub.RunAgentAsync(token);

        Assert.True(exit == 0, $"agent exited {exit}, want 0.\noutput:\n{output}");

        // "Refused before a connection is made", pinned where the meta tool actually
        // runs: this token holds no meta rule, so the github_meta call is refused at
        // the allow-list and the per-cell cleared journal must show the proxy never
        // connected for it. The arm sits BEFORE the text asserts so a config grant of
        // the meta route reaches THIS assert first instead of only the tool-line text.
        using var journal = System.Text.Json.JsonDocument.Parse(
            await _stub.UpstreamAdmin.GetStringAsync("/__admin/requests"));
        var metaRecords = journal.RootElement.GetProperty("requests").EnumerateArray()
            .Count(r => r.GetProperty("request").GetProperty("url").GetString()?.StartsWith("/meta") == true);
        Assert.Equal(0, metaRecords);

        Assert.Contains("tool fetch_docs -> OK (HTTP 200)", output);
        Assert.Contains("tool github_meta -> refused: the proxy answered HTTP 403", output);
        Assert.Contains("The docs readme says", output);
        Assert.DoesNotContain(DemoVendorKey, output);
        Assert.DoesNotContain("x-api-key", output);
    }

    [Fact]
    [Trait("Sample", "AgentTokens")]
    public async Task ModelRoute_CarriesTheVendorKeyButNeverTheCallersBearer()
    {
        // Run one full loop from THIS cell so the journal proof does not depend on order.
        await _stub.ResetProviderScenariosAsync();
        var token = _stub.Issue("demo-agent-client", new[] { "docs-read", "model-call" }, _stub.Now, "tok-journal-model");
        var (exit, output) = await _stub.RunAgentAsync(token);
        Assert.True(exit == 0, $"agent exited {exit}, want 0.\noutput:\n{output}");

        using var journal = System.Text.Json.JsonDocument.Parse(
            await _stub.UpstreamAdmin.GetStringAsync("/__admin/requests"));
        var records = journal.RootElement.GetProperty("requests").EnumerateArray()
            .Where(r => r.GetProperty("request").GetProperty("url").GetString()?.StartsWith("/v1/messages") == true)
            .ToList();
        var leaked = records.Any(r =>
            r.GetProperty("request").GetProperty("headers").TryGetProperty("Authorization", out _));
        // The journal serializes header values either as a plain string or as a
        // {key, values[]} object depending on the entry; accept both shapes.
        static bool HasVendorKey(System.Text.Json.JsonElement record)
            => SmokeJournalShapes.HeaderCarriesExactlyOneValue(
                record.GetProperty("request").GetProperty("headers"), "x-api-key", DemoVendorKey);

        static bool HasPinnedVersion(System.Text.Json.JsonElement record)
            => SmokeJournalShapes.HeaderCarriesExactlyOneValue(
                record.GetProperty("request").GetProperty("headers"), "anthropic-version", "2023-06-01");

        // EVERY /v1/messages record must carry the CredProx-attached key: the agent never
        // sends one itself, so a record without it reached the provider unauthenticated.
        var vendorKeyOnEveryRecord = records.All(HasVendorKey);
        // And every record must carry the route-set version header: the agent sends no
        // version of its own either, so a record without it means the model route's Set
        // transform was dropped — the shape that costs every caller a live 400.
        var versionOnEveryRecord = records.All(HasPinnedVersion);

        Assert.True(
            records.Count == 3,
            $"the provider journal holds {records.Count} /v1/messages records after this cell cleared it, want exactly the 3-turn loop");
        Assert.False(leaked, "the caller's Entra bearer reached the provider");
        Assert.True(
            vendorKeyOnEveryRecord,
            "a /v1/messages record reached the provider without the CredProx-attached x-api-key");
        Assert.True(
            versionOnEveryRecord,
            "a /v1/messages record reached the provider without the route-set anthropic-version");
    }

    [Fact]
    [Trait("Sample", "AgentTokens")]
    public async Task MeteringOptIn_ModelRouteMovesTheUsageCounters_Offline()
    {
        // The model route opts into usage metering (CredProx.Metering.Usage names the
        // anthropic format). This cell proves the opt-in MOVES the shipped host's
        // vendor-reported token counters — read from the console exporter's own output,
        // offline. Delete that config line from the shipped appsettings and this cell REDs
        // on the metered wait: the opt-in is load-bearing.
        await _stub.ResetProviderScenariosAsync();
        var token = _stub.Issue("demo-agent-client", new[] { "docs-read", "model-call" }, _stub.Now, "tok-meter");

        var (exit, output) = await _stub.RunAgentAsync(token);
        Assert.True(exit == 0, $"agent exited {exit}, want 0.\noutput:\n{output}");

        await _stub.WaitUntilMeteredAsync("credprox.usage.input_tokens", "credprox.usage.output_tokens");
        var hostOutput = _stub.HostOutput();
        var inputs = AgentTokensFixture.CounterValue(hostOutput, "credprox.usage.input_tokens");
        var outputs = AgentTokensFixture.CounterValue(hostOutput, "credprox.usage.output_tokens");
        Assert.True(
            inputs > 0,
            $"the meter shows input={inputs}, want > 0 (-1 means no batch); host output:\n{hostOutput}");
        Assert.True(
            outputs > 0,
            $"the meter shows output={outputs}, want > 0 (-1 means no batch); host output:\n{hostOutput}");
    }

    [Fact]
    [Trait("Sample", "AgentTokens")]
    public async Task AgentWithUnmappedApp_ModelCallIsRefused401()
    {
        await _stub.ResetProviderScenariosAsync();
        // A validly signed token from an app nobody listed: the agent never reaches the model.
        var token = _stub.Issue("rogue-client", new[] { "docs-read", "model-call" }, _stub.Now, "tok-rogue-loop");

        var (exit, output) = await _stub.RunAgentAsync(token);

        Assert.True(exit == 1, $"agent exited {exit}, want 1.\noutput:\n{output}");
        Assert.Contains("the model call was refused with HTTP 401", output);
    }

    [Fact]
    [Trait("Sample", "AgentTokens")]
    public async Task AgentWithoutModelCallRole_ModelRouteRefused403()
    {
        await _stub.ResetProviderScenariosAsync();
        // The token names docs-read only: the model-call rule is not in scope, so the
        // named-rule intersection refuses at 403 — the agent is a caller, just not for this.
        var token = _stub.Issue("demo-agent-client", new[] { "docs-read" }, _stub.Now, "tok-nomodelcall");

        var (exit, output) = await _stub.RunAgentAsync(token);

        Assert.True(exit == 1, $"agent exited {exit}, want 1.\noutput:\n{output}");
        Assert.Contains("the model call was refused with HTTP 403", output);

        // Hygiene: this cell cleared the journal and its run dies at the model refusal
        // before any tool call executes, so nothing — least of all a /meta request —
        // may be in it. The refusal-before-connection arm lives in the full-loop cell,
        // the one cell whose agent actually issues the github_meta call.
        using var journal = System.Text.Json.JsonDocument.Parse(
            await _stub.UpstreamAdmin.GetStringAsync("/__admin/requests"));
        var metaRecords = journal.RootElement.GetProperty("requests").EnumerateArray()
            .Count(r => r.GetProperty("request").GetProperty("url").GetString()?.StartsWith("/meta") == true);
        Assert.Equal(0, metaRecords);
    }
}

// M54 finding 1: the journal's header shape is shared by the vendor-key and version pins
// above, so the decision lives here, once, pinned offline by the cell below. The journal
// serializes a header either as a plain string or as a {key, values[]} object; exactly one
// value must equal the expected string, so a route change that APPENDS a second copy of a
// header instead of replacing it goes RED instead of matching values[0].
internal static class SmokeJournalShapes
{
    internal static bool HeaderCarriesExactlyOneValue(
        System.Text.Json.JsonElement headers, string name, string expected)
    {
        if (!headers.TryGetProperty(name, out var header))
        {
            return false;
        }

        if (header.ValueKind == System.Text.Json.JsonValueKind.String)
        {
            return header.GetString() == expected;
        }

        var values = header.GetProperty("values");
        return values.GetArrayLength() == 1 && values[0].GetString() == expected;
    }
}

public sealed class SmokeJournalShapePins
{
    [Fact]
    [Trait("Sample", "AgentTokens")]
    public void HeaderShape_PinCoversBothSerializations_AndBurnsADuplicatedValue()
    {
        using var doc = System.Text.Json.JsonDocument.Parse("""
        {
          "plain":  { "x-api-key": "V" },
          "plainWrong": { "x-api-key": "other" },
          "one":    { "x-api-key": { "key": "x-api-key", "values": ["V"] } },
          "oneWrong": { "x-api-key": { "key": "x-api-key", "values": ["other"] } },
          "twice":  { "x-api-key": { "key": "x-api-key", "values": ["V", "V"] } },
          "none":   { }
        }
        """);
        var root = doc.RootElement;

        Assert.True(SmokeJournalShapes.HeaderCarriesExactlyOneValue(root.GetProperty("plain"), "x-api-key", "V"));
        Assert.True(SmokeJournalShapes.HeaderCarriesExactlyOneValue(root.GetProperty("one"), "x-api-key", "V"));
        Assert.False(SmokeJournalShapes.HeaderCarriesExactlyOneValue(root.GetProperty("twice"), "x-api-key", "V"));
        Assert.False(SmokeJournalShapes.HeaderCarriesExactlyOneValue(root.GetProperty("plainWrong"), "x-api-key", "V"));
        Assert.False(SmokeJournalShapes.HeaderCarriesExactlyOneValue(root.GetProperty("oneWrong"), "x-api-key", "V"));
        Assert.False(SmokeJournalShapes.HeaderCarriesExactlyOneValue(root.GetProperty("none"), "x-api-key", "V"));
    }
}
