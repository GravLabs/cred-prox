using System.Net.Http;
using Xunit;

namespace CredProx.SampleSmokes;

/// <summary>
/// The FoundryLocalAgent sample end-to-end: a bare OpenAI-format agent loop drives a
/// tool-calling conversation through CredProx to a local-model stand-in, carrying its
/// own caller token (minted against the stub issuer — the same test-token approach the
/// AgentTokens smokes use). The cells pin the shipped config's and agent's claims: a
/// tool round trip completes through the gate, the thinking shape (empty content beside
/// reasoning_content) is handled without treating it as failure, a tool no named rule
/// admits is refused at the gate — the tool server never sees it, and the model
/// receives the refusal as a tool error it can answer around — and a token from an
/// unlisted client id is refused at the gate without moving anything.
/// </summary>
[Collection("FoundryLocalAgent")]
public sealed class FoundryLocalAgentSmokeTests
{
    private readonly FoundryLocalAgentFixture _world;

    public FoundryLocalAgentSmokeTests(FoundryLocalAgentFixture world)
    {
        _world = world;
    }

    [Fact]
    [Trait("Sample", "FoundryLocalAgent")]
    public async Task DocsToolRoundTrip_CompletesThroughTheGate()
    {
        var host = _world.StartHost();
        await _world.WaitForHostAsync(host);
        var docsBefore = await _world.DocsAsync();
        var (exit, output) = await _world.RunAgentAsync(
            "qwen3-4b-generic-cpu:3", _world.IssueAgentToken("round-trip"));
        Assert.True(exit == 0, $"agent exited {exit}:\n{output}");
        Assert.Contains("[tool docs_lookup -> ok]", output, StringComparison.Ordinal);
        Assert.Contains("[answer] The answer is doc-42.", output, StringComparison.Ordinal);
        Assert.Equal(docsBefore + 1, await _world.DocsAsync());
    }

    [Fact]
    [Trait("Sample", "FoundryLocalAgent")]
    public async Task EmptyContentBesideReasoning_IsNotTreatedAsFailure()
    {
        // The thinking-model shape: the first turn answers with empty content plus
        // reasoning_content and a tool call. An agent that reads emptiness as failure
        // exits nonzero here; this one notes the reasoning and acts on the call.
        var host = _world.StartHost();
        await _world.WaitForHostAsync(host);
        var (exit, output) = await _world.RunAgentAsync(
            "reasoner-demo", _world.IssueAgentToken("reasoning"));
        Assert.True(exit == 0, $"agent exited {exit}:\n{output}");
        Assert.Contains("[reasoning]", output, StringComparison.Ordinal);
        Assert.Contains("[tool docs_lookup -> ok]", output, StringComparison.Ordinal);
        Assert.Contains("[answer] The answer is doc-42.", output, StringComparison.Ordinal);
        Assert.DoesNotContain("[error]", output, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Sample", "FoundryLocalAgent")]
    public async Task ToolNotOnTheAllowList_403AtTheGate_ReachesTheModelAsAToolError()
    {
        // admin_reset is addressed by the agent but named by no rule the token's roles
        // admit: CredProx refuses at the gate, the refusal travels back as a readable
        // tool error, and the conversation survives to an answer that mentions the
        // refusal. The tool server's admin counter staying at zero is the witness that
        // the refusal happened upstream of it.
        var host = _world.StartHost();
        await _world.WaitForHostAsync(host);
        var adminBefore = await _world.AdminAsync();
        var (exit, output) = await _world.RunAgentAsync(
            "admin-demo", _world.IssueAgentToken("admin-refusal"));
        Assert.True(exit == 0, $"agent exited {exit}:\n{output}");
        Assert.Contains("[tool admin_reset -> gateway_refused 403]", output, StringComparison.Ordinal);
        Assert.Contains("[answer] cannot reset that", output, StringComparison.Ordinal);
        Assert.Equal(adminBefore, await _world.AdminAsync());
    }

    [Fact]
    [Trait("Sample", "FoundryLocalAgent")]
    public async Task UnmappedClientToken_401AtTheGate_MovesNothing()
    {
        // A well-formed token (right issuer, audience, signature, roles) from a client
        // id the config never lists: admission is the client id list, not the
        // signature. The gate refuses 401 before routing, the model stand-in's counter
        // never moves, and the agent reports the refusal on its error line. The live
        // vendor proves this same rule against a real Entra tenant with an unmapped app.
        var host = _world.StartHost();
        await _world.WaitForHostAsync(host);
        var modelBefore = await _world.ModelCallsAsync();
        var (exit, output) = await _world.RunAgentAsync(
            "qwen3-4b-generic-cpu:3",
            _world.Issue("some-other-app", ["model-call", "docs-read"], "unmapped"));
        Assert.Equal(4, exit);
        Assert.Contains("[error] model route refused: 401", output, StringComparison.Ordinal);
        Assert.Equal(modelBefore, await _world.ModelCallsAsync());
    }
}
