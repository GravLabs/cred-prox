using Xunit;

namespace CredProx.SampleSmokes;

// The offline cells for the PerCallerCredentials sample: two caller keys
// mapping to two Keycloak accounts on one route, the read-only caller's allow-list,
// the silent keyless rejection, and the audit records the proxy writes for all three.
[Collection("PerCallerCredentials")]
public sealed class PerCallerCredentialsSmokeTests
{
    private readonly PerCallerCredentialsFixture _world;

    public PerCallerCredentialsSmokeTests(PerCallerCredentialsFixture world)
    {
        _world = world;
    }

    [Fact]
    [Trait("Sample", "PerCallerCredentials")]
    public async Task TwoCallers_EachReachTheirOwnVendorAccount()
    {
        var (statusA, whoA) = await _world.CallAsync(PerCallerCredentialsFixture.KeyA);
        Assert.Equal(200, statusA);
        Assert.Equal("credprox-app-a", whoA);

        var (statusB, whoB) = await _world.CallAsync(PerCallerCredentialsFixture.KeyB);
        Assert.Equal(200, statusB);
        Assert.Equal("credprox-app-b", whoB);
    }

    [Fact]
    [Trait("Sample", "PerCallerCredentials")]
    public async Task ReadOnlyCaller_GetIsAllowedButPostIsBlocked()
    {
        var (getStatus, _) = await _world.CallAsync(PerCallerCredentialsFixture.KeyReadOnly);
        Assert.Equal(200, getStatus);

        var (postStatus, _) = await _world.CallAsync(
            PerCallerCredentialsFixture.KeyReadOnly, HttpMethod.Post);
        Assert.Equal(403, postStatus);
    }

    [Fact]
    [Trait("Sample", "PerCallerCredentials")]
    public async Task KeylessRequest_IsRejectedSilently()
    {
        var (status, _) = await _world.CallAsync(key: null);
        Assert.Equal(401, status);
    }

    [Fact]
    [Trait("Sample", "PerCallerCredentials")]
    public async Task AuditSink_RecordsProxiedCallsAndTheRejection()
    {
        // Self-contained: make the three calls fresh and read only what the proxy
        // writes after this point, so the records prove THESE calls were audited.
        var offset = _world.ProxyOutput.Length;

        await _world.CallAsync(PerCallerCredentialsFixture.KeyA);
        await _world.CallAsync(PerCallerCredentialsFixture.KeyB);
        await _world.CallAsync(PerCallerCredentialsFixture.KeyReadOnly, HttpMethod.Post);

        string[] wanted =
        [
            "credprox.audit credprox.proxied_call: caller=app-a",
            "credprox.audit credprox.proxied_call: caller=app-b",
            "credprox.audit credprox.rejected_call: caller=app-readonly",
        ];
        foreach (var want in wanted)
        {
            var deadline = DateTime.UtcNow.AddSeconds(30);
            while (!_world.ProxyOutput[offset..].Contains(want, StringComparison.Ordinal))
            {
                if (DateTime.UtcNow > deadline)
                {
                    throw new InvalidOperationException(
                        $"the proxy never wrote the audit record '{want}'.\nrecent output:\n{_world.ProxyOutput}");
                }

                await Task.Delay(250);
            }
        }
    }
}
