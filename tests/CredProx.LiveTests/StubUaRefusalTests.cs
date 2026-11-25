using System.Net;
using Xunit;

namespace CredProx.LiveTests;

/// <summary>
/// Direct coverage-pin for the GitHubApp stand-in's User-Agent enforcement arm (the
/// class that hid the product bug of 2026-11-22: GitHub's administrative edge answers a
/// UA-less request 403 before any credential is read, while every offline cell passed).
/// The arm existed at merge of the stand-in change; these cells drive it head-on so a
/// silent removal of the 403 check — or of the enforcement in the shipped
/// CredProx client path — lands here, not on the next live run. Offline stand-in
/// only: nothing here reaches the network, and no vendor live leg runs these cells.
/// Deliberately NOT in the GitHubApp collection: its own collection definition gives
/// this class its own fixture instance — a stub nobody else's cell shares — and the
/// assembly's serial runner plus the fixture's dispose-between-collections keeps the
/// fixed stub port between the two collections. The class name matches no vendor test
/// filter in scripts/live-run.sh, by the same rule as the witness class.
/// </summary>
[CollectionDefinition("StubUaRefusal")]
public sealed class StubUaRefusalCollection : ICollectionFixture<GitHubAppFixture>
{
}

[Collection("StubUaRefusal")]
[Trait("Layer", "Offline")]
public sealed class StubUaRefusalTests
{
    private readonly GitHubAppFixture _fixture;

    public StubUaRefusalTests(GitHubAppFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task UaLessTokenPost_StubAnswers403LikeGithubsAdministrativeEdge()
    {
        var (_, publicPem) = _fixture.GenerateSigningPair();
        await _fixture.StartStubAsync(publicPem);

        using var client = new HttpClient { BaseAddress = new Uri(GitHubAppFixture.StubUrl) };
        var body = await Run(() => PostTokenRequest(client, userAgent: null));

        Assert.Equal((int)HttpStatusCode.Forbidden, body.StatusCode);
        Assert.Contains("Request forbidden by administrative rules", body.Text, StringComparison.Ordinal);
        Assert.Contains("User-Agent", body.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TokenPostWithUserAgent_ReachesTheCredentialCheck_NotTheUaRefusal()
    {
        // Same POST, one variable changed: with a User-Agent the stand-in moves past the
        // administrative edge to the Authorization check (401 "Bad credentials" — no
        // valid app JWT was sent). The pair proves the 403 above is the UA arm
        // discriminating, not a blanket refusal of this endpoint.
        var (_, publicPem) = _fixture.GenerateSigningPair();
        await _fixture.StartStubAsync(publicPem);

        using var client = new HttpClient { BaseAddress = new Uri(GitHubAppFixture.StubUrl) };
        var body = await Run(() => PostTokenRequest(client, userAgent: "CredProx/test"));

        Assert.Equal((int)HttpStatusCode.Unauthorized, body.StatusCode);
        Assert.Contains("Bad credentials", body.Text, StringComparison.Ordinal);
    }

    // xUnit1031: blocking calls live in the helper, not in the fact bodies.
    private static Task<(int StatusCode, string Text)> Run(
        Func<Task<(int StatusCode, string Text)>> leg) => leg();

    private static async Task<(int StatusCode, string Text)> PostTokenRequest(HttpClient client, string? userAgent)
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Post, "/app/installations/789012/access_tokens");
        if (userAgent is not null)
        {
            request.Headers.TryAddWithoutValidation("User-Agent", userAgent);
        }

        using var response = await client.SendAsync(request);
        return ((int)response.StatusCode, await response.Content.ReadAsStringAsync());
    }
}
