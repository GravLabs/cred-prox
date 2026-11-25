using Xunit;
using Xunit.Abstractions;

namespace CredProx.LiveTests;

// M53's live proof, and the only cell in the suite that reaches a real vendor: the shipped
// AgentTokens sample, its Anthropic model route real (api.anthropic.com with the run's key),
// the shipped Agent.dll run as its own process authenticating with a REAL Entra token it
// mints itself. Proves end to end: the mapped agent's model call answers and its docs tool
// passes; the disallowed tool is refused 403 by CredProx — the agent sees it as a tool
// error and carries on; an unmapped app's agent is refused 401 and its run moves no meter
// (nothing reached the vendor, so it costs nothing). The M50 console counters carry the
// vendor's own usage numbers attributed to the caller. The bearer-never-reaches-the-vendor
// arm is journal-proven offline at these same bytes (the real vendor's inbound headers are
// not observable from here) — disclosed deviation.
//
// Gated by AgentTokensBillableLiveFactAttribute: skipped with a named reason unless
// CREDPROX_M53_BILLABLE=1 — the owner's separate go-ahead. Billable calls: a few cents
// (cheapest model, small max_tokens, fixed short prompt). Disclosed deviation, as in the
// M46 cell: the docs placeholder is repointed at the loopback stand-in; the meta route is
// never connected because CredProx refuses it before connecting.
[Collection("AgentTokens")]
[Trait("Layer", "Live")]
public sealed class AgentTokensAgentBillableLiveTests
{
    private readonly AgentTokensFixture _fixture;
    private readonly ITestOutputHelper _output;

    public AgentTokensAgentBillableLiveTests(AgentTokensFixture fixture, ITestOutputHelper output)
    {
        _fixture = fixture;
        _output = output;
    }

    [AgentTokensBillableLiveFact]
    public async Task RealAgent_MappedPasses_DisallowedToolIsA403Error_UnmappedMovesNoMeter()
    {
        var probe = AgentTokensEnv.Probe();
        Assert.True(probe.Available, probe.SkipReason);
        var tenant = probe.Values["TENANT_ID"];
        var anthropicKey = Environment.GetEnvironmentVariable("ANTHROPIC_API_KEY") ?? "";
        Assert.True(anthropicKey.Length > 0, "ANTHROPIC_API_KEY is empty in the live env");

        var (mappedId, mappedSecret, unmappedId, unmappedSecret) = AgentTokensFixture.ReadScratchApps();
        var audience = AgentTokensFixture.ReadScratchAudience();
        var secrets = new List<string> { mappedSecret, unmappedSecret, anthropicKey };

        _fixture.StartStandIn();
        var host = _fixture.StartHost(new Dictionary<string, string>
        {
            ["CredProx__CallerToken__Authority"] = $"https://login.microsoftonline.com/{tenant}/v2.0",
            ["CredProx__CallerToken__Audience"] = audience,
            ["CredProx__Callers__doc-reader__TokenClientIds__0"] = mappedId,
            ["CredProx__Secrets__anthropic-key"] = anthropicKey,
            ["Metrics__Console"] = "true",
            // the console exporter prints on a cadence and the default is 60 s — longer
            // than the whole loop, so shorten it (the shape the AiGateway live cell uses)
            ["OTEL_METRIC_EXPORT_INTERVAL"] = "1000",
            ["CredProx__Destinations__upstream__Template"] = AgentTokensFixture.StandInUrl,
            ["ReverseProxy__Clusters__upstream__Destinations__upstream__Address"] =
                AgentTokensFixture.StandInUrl + "/",
        }, secrets);
        await _fixture.WaitForHostAsync(host);

        // 1) The mapped agent runs the real loop against the real Anthropic.
        // The stand-in counter is collection-wide (shared fixture): take where it
        // stands NOW so the docs assert counts this cell's agent call only.
        var docsBefore = _fixture.DocsRequestCount;
        var (exit, transcript) = await RunAgentAsync(tenant, audience, mappedId, mappedSecret);
        Assert.True(
            exit == 0,
            $"the mapped agent exited {exit}, want 0; sanitized agent+host output:\n" +
            $"{SecretLeakScanner.Sanitize(transcript + host.Stdout + host.Stderr, secrets)}");
        Assert.Contains("tool fetch_docs -> OK (HTTP 200)", transcript);
        Assert.Contains("tool github_meta -> refused: the proxy answered HTTP 403", transcript);
        Assert.Contains("agent: ", transcript, StringComparison.Ordinal);
        Assert.True(
            _fixture.DocsRequestCount >= docsBefore + 1,
            $"the allowed docs tool never reached the stand-in (count went {docsBefore} -> {_fixture.DocsRequestCount})");
        Assert.False(_fixture.SawBearerToken, "the agent's Entra bearer reached the docs stand-in");

        // 2) The vendor's own usage numbers landed on the meter (M50 parse, console
        // exporter) AND the meter has gone quiet. The baseline is NOT the first
        // non-zero batch: batches printed after the mapped agent still carry its
        // own remaining turns (live run 4 at e4e7ff2: baseline 484 was overtaken
        // by the agent's late 1283 batch and step 3 then blamed the unmapped run).
        // Settle first — the first pair repeated across two consecutive export
        // batches, both non-zero (a -1 no-batch never settles; the fold rule
        // refuses -1) — and only then take the baseline. Failure text builds at
        // failure time.
        var (inputs, outputs) = await LiveHosts.WaitTokenCountersSettled(
            () => (LiveHosts.CounterValue(host.Stdout, "credprox.usage.input_tokens"),
                   LiveHosts.CounterValue(host.Stdout, "credprox.usage.output_tokens")),
            1000,
            30,
            () => "the token counters never settled to the same non-zero values across two consecutive " +
                  "export batches within 30 s; sanitized host output:\n" +
                  SecretLeakScanner.Sanitize(host.Stdout + host.Stderr, secrets));

        // 3) The unmapped app's agent: 401 before the vendor, zero billable, meter unmoved.
        var (unmappedExit, unmappedTranscript) = await RunAgentAsync(tenant, audience, unmappedId, unmappedSecret);
        Assert.True(
            unmappedExit != 0 && unmappedTranscript.Contains("the model call was refused with HTTP 401", StringComparison.Ordinal),
            $"the unmapped agent was not refused with 401 (exit {unmappedExit}); sanitized output:\n" +
            SecretLeakScanner.Sanitize(unmappedTranscript + host.Stdout + host.Stderr, secrets));
        // Unmoved means the SAME positive numbers as the SETTLED baseline: -1 == -1
        // (no batch) must never pass this comparison — the fold rule is that every
        // counter comparison refuses -1. Because the baseline only formed after two
        // identical consecutive batches, the mapped agent's own late batch can no
        // longer masquerade as movement caused by the unmapped run (live finding
        // 2026-11-23).
        var unmovedInputs = LiveHosts.CounterValue(host.Stdout, "credprox.usage.input_tokens");
        var unmovedOutputs = LiveHosts.CounterValue(host.Stdout, "credprox.usage.output_tokens");
        Assert.True(
            unmovedInputs == inputs && unmovedInputs > 0,
            $"the unmapped run moved the input counter ({inputs} -> {unmovedInputs}) or its batch vanished (-1 means no batch); sanitized host output:\n" +
            SecretLeakScanner.Sanitize(host.Stdout + host.Stderr, secrets));
        Assert.True(
            unmovedOutputs == outputs && unmovedOutputs > 0,
            $"the unmapped run moved the output counter ({outputs} -> {unmovedOutputs}) or its batch vanished (-1 means no batch); sanitized host output:\n" +
            SecretLeakScanner.Sanitize(host.Stdout + host.Stderr, secrets));

        // 4) Leak scan over everything visible: neither minted secret, the vendor key, nor
        // any JWT shape may appear in the agent transcripts or the host log.
        Assert.Empty(SecretLeakScanner.FindLeaks(transcript, secrets));
        Assert.Empty(SecretLeakScanner.FindLeaks(unmappedTranscript, secrets));
        Assert.Empty(SecretLeakScanner.FindLeaks(host.Stdout + host.Stderr, secrets));

        _output.WriteLine(
            $"OBSERVED m53_agent_pass=1 m53_tool_403=1 m53_unmapped_401=1 input_tokens={inputs} output_tokens={outputs}");
    }

    private async Task<(int Exit, string Transcript)> RunAgentAsync(
        string tenant, string audience, string clientId, string clientSecret)
    {
        var agent = _fixture.StartAgent(new Dictionary<string, string>
        {
            ["CREDPROX_URL"] = AgentTokensFixture.LiveHostUrl,
            ["AGENT_TENANT_ID"] = tenant,
            ["AGENT_CLIENT_ID"] = clientId,
            ["AGENT_CLIENT_SECRET"] = clientSecret,
            ["AGENT_API_SCOPE"] = $"{audience}/.default",
        });
        await LiveHosts.WaitUntilAsync(
            () => Task.FromResult(agent.Process.HasExited),
            "the sample agent never finished within 120 s",
            120);
        return (agent.Process.ExitCode, agent.Stdout + agent.Stderr);
    }
}
