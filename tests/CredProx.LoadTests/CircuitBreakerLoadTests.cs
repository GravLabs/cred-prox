using System.Net;
using System.Text.Json;
using CredProx;
using Xunit;

namespace CredProx.LoadTests;

/// <summary>
/// §5.2 "Resilience" under load: sustained failures open the cluster's circuit breaker
/// and the open circuit sheds concurrent callers without touching the upstream; when the
/// upstream recovers, the half-open probe closes the circuit and load flows again.
/// </summary>
[Trait("Layer", "Nightly")]
public sealed class CircuitBreakerLoadTests
{
    [Fact]
    public async Task SustainedFailures_OpenTheCircuit_ThenRecoveryClosesIt()
    {
        const int Waves = 10;
        const int PerWave = 6;
        var upstream = new SwitchableUpstreamHandler(healthy: false);
        var registry = new ClusterResilienceRegistry(new ResilienceOptions
        {
            MaxRetries = 0,
            RetryBaseDelay = TimeSpan.FromMilliseconds(1),
            AttemptTimeout = TimeSpan.FromSeconds(5),
            MinimumThroughput = 10,
            FailureRatio = 0.5,
            SamplingDuration = TimeSpan.FromSeconds(10),
            BreakDuration = TimeSpan.FromMilliseconds(500),
        });
        using var client = new HttpClient(
            new CredProxResilienceHandler(new TailHandler(upstream), registry.GetOrCreate("load")));

        // Sustained load: concurrent waves arriving over time, so the breaker has a
        // chance to open between waves and shed the callers that arrive after it does.
        var responses = new List<HttpResponseMessage>();
        for (var wave = 0; wave < Waves; wave++)
        {
            responses.AddRange(await Task
                .WhenAll(Enumerable.Range(0, PerWave).Select(_ => client.GetAsync("https://vendor.example/api")))
                .WaitBoundedAsync("a failing wave"));
            await Task.Delay(40);
        }

        var shed = responses.Count(r => r.StatusCode == HttpStatusCode.ServiceUnavailable);
        Assert.True(shed > 0, "The breaker never opened under sustained failures.");
        Assert.True(
            upstream.Arrivals < Waves * PerWave,
            $"The open circuit still forwarded every request ({upstream.Arrivals}/{Waves * PerWave}).");
        Assert.Contains(
            responses.Where(r => r.StatusCode == HttpStatusCode.ServiceUnavailable),
            r =>
            {
                using var document = JsonDocument.Parse(r.Content.ReadAsStringAsync().Result);
                return document.RootElement
                    .GetProperty("extensions").GetProperty("code").GetString() == "credprox.upstream_unavailable";
            });

        // Upstream recovers; past the break duration the half-open probe must let a real
        // request through, and the closed circuit must carry the next wave.
        upstream.Healthy = true;
        await Task.Delay(TimeSpan.FromSeconds(1));

        var probe = await client
            .GetAsync("https://vendor.example/api")
            .WaitBoundedAsync("the half-open probe");
        Assert.Equal(HttpStatusCode.OK, probe.StatusCode);

        var after = await Task
            .WhenAll(Enumerable.Range(0, 20).Select(_ => client.GetAsync("https://vendor.example/api")))
            .WaitBoundedAsync("the recovery wave");
        Assert.All(after, r => Assert.Equal(HttpStatusCode.OK, r.StatusCode));
    }
}
