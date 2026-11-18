using Xunit;

namespace CredProx.SampleSmokes;

// The E2 OAuthKeycloak smoke, cell by cell — the same checks the sample's old smoke
// script made against the real-Keycloak stack, unchanged in meaning, driven from
// outside the sample. Filter with --filter Sample=OAuthKeycloak.
[Collection("OAuthKeycloak")]
public sealed class OAuthKeycloakSmokeTests
{
    private readonly OAuthKeycloakFixture _stack;

    public OAuthKeycloakSmokeTests(OAuthKeycloakFixture stack) => _stack = stack;

    [Fact]
    [Trait("Sample", "OAuthKeycloak")]
    public async Task ProtectedPath_ProxiesWithATokenTheCallerNeverHad()
    {
        // The caller sends no credential; the API answers 200 because CredProx attached a
        // Keycloak-issued token. The caller's echo shows it redacted —
        // proven here; the token's identity is the API's record, checked below.
        var (status, body) = await _stack.GetSecretsAsync();

        Assert.Equal(200, status);
        Assert.Contains("redacted", body, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Sample", "OAuthKeycloak")]
    public async Task RevokedToken_TriggersOneTransparentRefresh()
    {
        // Revoke the token the API last accepted; the next request must still succeed and
        // the API must see a NEW token — a replay of the revoked token would 401.
        var seenBefore = await _stack.GetSeenAsync();
        await _stack.RevokeAsync();

        var (status, _) = await _stack.GetSecretsAsync();
        var seenAfter = await _stack.GetSeenAsync();

        Assert.Equal(200, status);
        Assert.NotEmpty(seenAfter);
        Assert.NotEqual(seenBefore, seenAfter);
    }

    [Fact]
    [Trait("Sample", "OAuthKeycloak")]
    public async Task ConcurrentBurst_SingleFlightKeepsOneToken()
    {
        // A burst on the warm cache must not mint anything new: the API's count of
        // distinct accepted tokens does not move across ten concurrent requests.
        var before = await _stack.GetSeenCountAsync();
        Assert.True(before >= 1, "the fixture's readiness call should have delivered a token");

        await Task.WhenAll(Enumerable.Range(0, 10).Select(_ => _stack.GetSecretsAsync()));

        Assert.Equal(before, await _stack.GetSeenCountAsync());
    }
}
