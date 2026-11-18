using Xunit;

namespace CredProx.SampleSmokes;

// The offline cells for the Operations sample: the three operational behaviors plus the
// credential-health endpoint. They mirror the load script assertion for assertion,
// against WireMock's three vendor personalities and a real host over real sockets.
[Collection("Operations")]
public sealed class OperationsSmokeTests
{
    private readonly OperationsFixture _world;

    public OperationsSmokeTests(OperationsFixture world)
    {
        _world = world;
    }

    [Fact]
    [Trait("Sample", "Operations")]
    public async Task BurstAgainstARateLimitedCluster_ShedsAndProtectsTheVendor()
    {
        await _world.ResetVendorAsync();

        var codes = await _world.BurstAsync("/limited", 30);
        var served = codes.Count(c => c == 200);
        var shed = codes.Count(c => c == 429);
        var vendorSaw = await _world.VendorRequestCountAsync();

        Assert.True(shed >= 15,
            $"burst expected >=15x429 from the full queue, got {shed} (served {served}).");
        Assert.InRange(vendorSaw, 1, 15); // the held queue never let the burst through
    }

    [Fact]
    [Trait("Sample", "Operations")]
    public async Task VendorThrottle_PausesTheClusterForTheAdvertisedRetryAfter()
    {
        await _world.ResetVendorAsync();

        var r1 = await _world.GetCodeAsync("/vendor");
        var r2 = await _world.GetCodeAsync("/vendor"); // the vendor's own 429 + Retry-After: 2
        Assert.Equal(200, r1);
        Assert.Equal(429, r2); // passed through untouched

        var start = DateTime.UtcNow;
        var r3 = await _world.GetCodeAsync("/vendor"); // arrives during the pause: held until it ends
        Assert.Equal(200, r3); // the held request waits the pause out and is forwarded, not answered 429
        var heldMs = (long)(DateTime.UtcNow - start).TotalMilliseconds;
        Assert.True(heldMs >= 1000, $"the cluster did not pause: the next request took only {heldMs} ms");

        Assert.Equal(200, await _world.GetCodeAsync("/vendor")); // traffic flows again
    }

    [Fact]
    [Trait("Sample", "Operations")]
    public async Task CircuitBreaker_OpensOnFailuresAnswers503AndHalfOpenRecovers()
    {
        await _world.ResetVendorAsync();

        var failures = new List<int>();
        for (var i = 0; i < 4; i++)
        {
            failures.Add(await _world.GetCodeAsync("/flaky")); // pass through while closed
        }

        Assert.All(failures, code => Assert.Equal(500, code));

        Assert.Equal(503, await _world.GetCodeAsync("/flaky")); // the 4th failure opens it
        Assert.Equal(503, await _world.GetCodeAsync("/flaky"));
        var vendorSaw = await _world.VendorRequestCountAsync();
        Assert.InRange(vendorSaw, 1, 5); // the open circuit stopped reaching the vendor

        await Task.Delay(4000); // wait out the 3 s break for the half-open probe
        Assert.Equal(200, await _world.GetCodeAsync("/flaky")); // probe closes the circuit
    }

    [Fact]
    [Trait("Sample", "Operations")]
    public async Task CredentialHealth_ReportsHealthy()
    {
        Assert.Equal("Healthy", await _world.HealthAsync());
    }
}
