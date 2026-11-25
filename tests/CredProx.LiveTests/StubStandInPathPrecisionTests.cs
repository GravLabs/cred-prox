using System.Net;
using System.Net.Http;
using Xunit;

namespace CredProx.LiveTests;

// The live stand-in stubs answer only their documented upstream paths, exactly — a
// prefix match let /docsXYZ and /tools/v1/docsXYZ sail through the docs arm, so a
// routing bug that sent requests to a lookalike path would still be answered (and
// counted) as if it were the real tool call. The fixtures are INJECTED from their
// collections, never constructed here: each owns a fixed stand-in port, the
// collection shares one instance, and the build-graph guard polices that rule (a
// local construction burns it — the first full offline battery caught exactly that).
// Counters are collection-wide, so every cell reads where they stand NOW and asserts
// its own delta, the same rule the live cells and the counter cells follow. The
// bearer-shape promise lives in the predicate cell at the bottom: the collection's
// witness flag is sticky and the live cells pin it false for their traffic, so no
// offline cell may latch it and leave the outcome to class order.
[Collection("AgentTokens")]
public sealed class AgentTokensStandInPathTests
{
    private readonly AgentTokensFixture _fixture;

    public AgentTokensStandInPathTests(AgentTokensFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    [Trait("Layer", "Offline")]
    public async Task AgentTokensStandIn_AnswersExactlyTheDocumentedPath()
    {
        _fixture.StartStandIn();
        using var client = new HttpClient { BaseAddress = new Uri(AgentTokensFixture.StandInUrl) };

        var docsBefore = _fixture.DocsRequestCount;

        var ok = await client.GetAsync("/docs/readme");
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.Contains(AgentTokensFixture.StandInMarker, await ok.Content.ReadAsStringAsync());
        Assert.Equal(docsBefore + 1, _fixture.DocsRequestCount);

        var bare = await client.GetAsync("/docs");
        Assert.Equal(HttpStatusCode.NotFound, bare.StatusCode);

        // The old StartsWith("/docs") arm answered this (and counted it): a lookalike
        // path is not the documented tool call.
        var lookalike = await client.GetAsync("/docsXYZ");
        Assert.Equal(HttpStatusCode.NotFound, lookalike.StatusCode);
        Assert.Equal(docsBefore + 1, _fixture.DocsRequestCount);

        // The documented arm answers whatever Authorization shape arrives — the bearer
        // witness is the predicate cell's promise, not a drive of the sticky flag.
        using (var basic = new HttpRequestMessage(HttpMethod.Get, "/docs/readme"))
        {
            basic.Headers.TryAddWithoutValidation("Authorization", "Basic notajwt");
            using var basicResponse = await client.SendAsync(basic);
            Assert.Equal(HttpStatusCode.OK, basicResponse.StatusCode);
        }

        Assert.Equal(docsBefore + 2, _fixture.DocsRequestCount);
    }
}

[Collection("FoundryLocal")]
public sealed class FoundryLocalStandInPathTests
{
    private readonly FoundryLocalLiveFixture _fixture;

    public FoundryLocalStandInPathTests(FoundryLocalLiveFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    [Trait("Layer", "Offline")]
    public async Task FoundryLocalStandIn_AnswersExactlyTheToolPaths_TheAdminArmStillAnswers()
    {
        _fixture.StartStandIn();
        using var client = new HttpClient { BaseAddress = new Uri(FoundryLocalLiveFixture.StandInUrl) };

        var docsBefore = _fixture.DocsRequestCount;
        var adminBefore = _fixture.AdminRequestCount;

        var ok = await client.GetAsync("/tools/v1/docs/lookup");
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.Contains(FoundryLocalLiveFixture.StandInMarker, await ok.Content.ReadAsStringAsync());
        Assert.Equal(docsBefore + 1, _fixture.DocsRequestCount);

        // The old StartsWith("/tools/v1/docs") arm answered and counted this lookalike.
        var lookalike = await client.GetAsync("/tools/v1/docsXYZ");
        Assert.Equal(HttpStatusCode.NotFound, lookalike.StatusCode);
        Assert.Equal(docsBefore + 1, _fixture.DocsRequestCount);

        // The admin arm stays live-and-answerable on purpose (the gate refuses upstream).
        var admin = await client.GetAsync("/tools/v1/admin/reset");
        Assert.Equal(HttpStatusCode.OK, admin.StatusCode);
        Assert.Equal(adminBefore + 1, _fixture.AdminRequestCount);
    }
}

public sealed class StandInBearerWitnessTests
{
    [Fact]
    [Trait("Layer", "Offline")]
    public void StandInBearerWitness_OnlyJwtShapesSetTheWitness()
    {
        Assert.False(StandInBearerWitness.IsJwtShaped(null));
        Assert.False(StandInBearerWitness.IsJwtShaped("Basic notajwt"));
        Assert.False(StandInBearerWitness.IsJwtShaped("Bearer notjwt"), "a non-JWT bearer shape must not latch the witness");
        Assert.True(StandInBearerWitness.IsJwtShaped("Bearer eyJhbGciOi.test.sig"), "the shipped arms must latch on the JWT shape they see");
    }
}
