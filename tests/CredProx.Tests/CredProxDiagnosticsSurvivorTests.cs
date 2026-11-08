using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using CredProx;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage of <see cref="CredProxDiagnostics"/>: every instrument's name,
/// unit and description is an operator-facing dashboard contract (§3.3), the health gauge
/// keys by (kind, name) so distinct items stay distinct points, and the record helpers
/// carry the pinned tag names.
/// </summary>
public sealed class CredProxDiagnosticsSurvivorTests
{
    private readonly record struct Point(string Instrument, double Value, Dictionary<string, object?> Tags);

    private static MeterListener Listen(ConcurrentQueue<Point> measurements)
    {
        var listener = new MeterListener
        {
            InstrumentPublished = (instrument, l) =>
            {
                if (instrument.Meter == CredProxDiagnostics.Meter)
                {
                    l.EnableMeasurementEvents(instrument);
                }
            },
        };
        listener.SetMeasurementEventCallback<double>((instrument, value, tags, _) =>
            measurements.Enqueue(new Point(
                instrument.Name, value, tags.ToArray().ToDictionary(t => t.Key, t => t.Value))));
        listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) =>
            measurements.Enqueue(new Point(
                instrument.Name, value, tags.ToArray().ToDictionary(t => t.Key, t => t.Value))));
        listener.Start();
        return listener;
    }

    [Fact]
    public void Instruments_PinTheirExactNamesUnitsAndDescriptions()
    {
        var published = new List<(string Name, string? Unit, string? Description)>();
        var listener = new MeterListener
        {
            InstrumentPublished = (instrument, l) =>
            {
                lock (published)
                {
                    published.Add((instrument.Name, instrument.Unit, instrument.Description));
                }

                if (instrument.Meter == CredProxDiagnostics.Meter)
                {
                    l.EnableMeasurementEvents(instrument);
                }
            },
        };
        listener.Start();
        listener.Dispose();

        var expected = new (string Name, string? Unit, string Description)[]
        {
            ("credprox.certificate.days_to_expiry", "d",
                "Days until each connection's client certificate expires (negative once expired)."),
            ("credprox.health.status", null,
                "Latest health status (0 healthy, 1 degraded, 2 unhealthy) by item (kind: credential, connection or probe)."),
            ("credprox.token.fetches", null,
                "Token fetch attempts by credential and outcome (success|failure)."),
            ("credprox.token.cache", null,
                "Token cache results by credential (hit|miss)."),
            ("credprox.token.fetch.duration", "s",
                "Wall-clock duration of token fetches by credential."),
            ("credprox.throttle.rejected", null,
                "Requests rejected with 429 by the outbound throttle (queue full or wait exceeded)."),
            ("credprox.throttle.paused", null,
                "Times a vendor 429 paused its cluster for the advertised Retry-After."),
            ("credprox.caller_throttle.rejections", null,
                "Requests rejected with 429 by a caller's per-app request budget."),
            ("credprox.killswitch.rejections", null,
                "Requests refused by the kill switch with 503 (disabled caller or cluster)."),
            ("credprox.resilience.retried", null,
                "Outbound attempts retried by the resilience adapter."),
            ("credprox.resilience.circuit_opened", null,
                "Times a cluster's circuit breaker opened."),
        };

        foreach (var (name, unit, description) in expected)
        {
            var seen = Assert.Single(published.Where(p => p.Name == name).ToList());
            Assert.Equal(unit, seen.Unit);
            Assert.Equal(description, seen.Description);
        }
    }

    [Fact]
    public void CertificateGauge_OnePointPerConnection_UnderTheConnectionTag()
    {
        var connectionA = "diag-a-" + Guid.NewGuid().ToString("N");
        var connectionB = "diag-b-" + Guid.NewGuid().ToString("N");
        CredProxDiagnostics.RecordCertificateDaysToExpiry(connectionA, 12.5);
        CredProxDiagnostics.RecordCertificateDaysToExpiry(connectionB, -3.25);

        var queue = new ConcurrentQueue<Point>();
        using var listener = Listen(queue);
        listener.RecordObservableInstruments();

        // Distinct connections must remain distinct points under credprox.connection.
        Assert.Contains(queue, p => p.Instrument == "credprox.certificate.days_to_expiry"
            && Equals(p.Tags.GetValueOrDefault("credprox.connection"), connectionA)
            && p.Value == 12.5);
        Assert.Contains(queue, p => p.Instrument == "credprox.certificate.days_to_expiry"
            && Equals(p.Tags.GetValueOrDefault("credprox.connection"), connectionB)
            && p.Value == -3.25);
    }

    [Fact]
    public void HealthGauge_KeysByKindAndName_SoItemsStayDistinct()
    {
        var suffix = Guid.NewGuid().ToString("N");
        CredProxDiagnostics.RecordHealthStatus("credential", "diag-cred-" + suffix, 1);
        CredProxDiagnostics.RecordHealthStatus("probe", "diag-probe-" + suffix, 2);
        CredProxDiagnostics.RecordHealthStatus("credential", "diag-cred-" + suffix, 0);

        var queue = new ConcurrentQueue<Point>();
        using var listener = Listen(queue);
        listener.RecordObservableInstruments();

        Assert.Collection(
            queue.Where(p => p.Instrument == "credprox.health.status"
                && Equals(p.Tags["credprox.item"], "diag-cred-" + suffix)).Select(p => p.Value).Distinct().ToList(),
            v => Assert.Equal(0.0, v)); // latest status per item: the 1 is superseded, not a second point
        Assert.Contains(queue, p => p.Instrument == "credprox.health.status"
            && Equals(p.Tags["credprox.item"], "diag-probe-" + suffix)
            && Equals(p.Tags["credprox.kind"], "probe")
            && p.Value == 2); // a distinct (kind, name) is its own point — an empty shared key would collapse these
    }

    [Fact]
    public void RecordFetch_PinsCredentialAndOutcomeTags_OnCountersAndDuration()
    {
        var credential = "diag-fetch-" + Guid.NewGuid().ToString("N");
        var queue = new ConcurrentQueue<Point>();
        using var listener = Listen(queue);

        CredProxDiagnostics.RecordFetch(credential, success: true, seconds: 1.5);
        CredProxDiagnostics.RecordFetch(credential, success: false, seconds: 2.5);

        Assert.Contains(queue, p => p.Instrument == "credprox.token.fetches"
            && p.Value == 1
            && Equals(p.Tags["credprox.credential"], credential)
            && Equals(p.Tags["outcome"], "success"));
        Assert.Contains(queue, p => p.Instrument == "credprox.token.fetches"
            && p.Value == 1
            && Equals(p.Tags["credprox.credential"], credential)
            && Equals(p.Tags["outcome"], "failure"));
        Assert.Contains(queue, p => p.Instrument == "credprox.token.fetch.duration"
            && p.Value == 1.5
            && p.Tags.Count == 1
            && Equals(p.Tags["credprox.credential"], credential));
    }

    [Fact]
    public void RecordCacheResult_PinsCredentialAndResultTags()
    {
        var credential = "diag-cache-" + Guid.NewGuid().ToString("N");
        var queue = new ConcurrentQueue<Point>();
        using var listener = Listen(queue);

        CredProxDiagnostics.RecordCacheResult(credential, hit: true);
        CredProxDiagnostics.RecordCacheResult(credential, hit: false);

        Assert.Contains(queue, p => p.Instrument == "credprox.token.cache"
            && p.Value == 1
            && Equals(p.Tags["credprox.credential"], credential)
            && Equals(p.Tags["result"], "hit"));
        Assert.Contains(queue, p => p.Instrument == "credprox.token.cache"
            && p.Value == 1
            && Equals(p.Tags["credprox.credential"], credential)
            && Equals(p.Tags["result"], "miss"));
    }
}
