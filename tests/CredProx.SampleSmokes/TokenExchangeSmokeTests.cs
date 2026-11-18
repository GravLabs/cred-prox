using Xunit;

namespace CredProx.SampleSmokes;

// The E14 TokenExchange smoke, cell by cell — the same checks the sample's old smoke
// script made against the real-Keycloak stack, unchanged in meaning, driven from
// outside the sample. Filter with --filter Sample=TokenExchange.
[Collection("TokenExchange")]
public sealed class TokenExchangeSmokeTests
{
    private readonly TokenExchangeFixture _stack;

    public TokenExchangeSmokeTests(TokenExchangeFixture stack) => _stack = stack;

    [Fact]
    [Trait("Sample", "TokenExchange")]
    public async Task TwoUsers_EachGetTheirOwnExchangedToken()
    {
        // The api echoes "<sub>|<azp>": azp=credprox-proxy proves the downstream got the
        // EXCHANGED token, never the inbound one (azp=credprox-frontend); per-user cache
        // means bob's answer names bob.
        var alice = await _stack.MintUserTokenAsync("alice");
        var bob = await _stack.MintUserTokenAsync("bob");

        var (aliceStatus, aliceWho) = await _stack.ProxyGetAsync(alice);
        var (bobStatus, bobWho) = await _stack.ProxyGetAsync(bob);

        Assert.Equal(200, aliceStatus);
        Assert.Equal("alice|credprox-proxy", aliceWho);
        Assert.Equal(200, bobStatus);
        Assert.Equal("bob|credprox-proxy", bobWho);
    }

    [Fact]
    [Trait("Sample", "TokenExchange")]
    public async Task ForgedInbound_IsRefusedBeforeAnyExchange()
    {
        // An HS256 JWT on the attacker's secret, right issuer and audience: CredProx
        // validates the signature against the realm JWKS BEFORE exchanging anything.
        // The 401 (not 502) distinguishes "never exchanged" from "exchange failed".
        var forged = _stack.ForgeHs256Token();

        var (status, body) = await _stack.ProxyGetAsync(forged);

        Assert.Equal(401, status);
        Assert.Contains("credprox.inbound_token_invalid", body, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Sample", "TokenExchange")]
    public async Task MissingCallerKey_IsRefusedEvenWithAValidUserToken()
    {
        var alice = await _stack.MintUserTokenAsync("alice");

        var (status, _) = await _stack.ProxyGetAsync(alice, withKey: false);

        Assert.Equal(401, status);
    }

    [Fact]
    [Trait("Sample", "TokenExchange")]
    public async Task InboundToken_AtTheDownstream_IsRefusedByItsAudience()
    {
        // The point of E14: the inbound token (aud credprox-proxy) sent straight to the
        // downstream (validates credprox-downstream) is refused — only the swap passes.
        var alice = await _stack.MintUserTokenAsync("alice");

        var (status, _) = await _stack.ApiGetAsync(alice);

        Assert.Equal(401, status);
    }
}
