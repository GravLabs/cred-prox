using System.Diagnostics.Metrics;
using CredProx;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// §5.2 (M50 row): "unit cells per counter and tag" for the metering instruments.
/// These cells pin the instrument identity (name, unit) and the fixed tag shape at the
/// instrument level; the pipeline-level emission (who fills which tags, the byte counts
/// and the usage gating) is asserted on a real host in
/// <c>CredProxMeteringPipelineTests</c>. The instruments are static and this collection
/// runs in parallel with others that may emit on the same meter, so cells emit unique
/// caller values and assert presence, never absence or counts.
/// </summary>
public sealed class CredProxMeteringInstrumentsTests
{
    private sealed record Measurement(string Instrument, long Value, Dictionary<string, object?> Tags);

    /// <summary>
    /// Enables the five metering instruments directly (they may publish before the listener
    /// exists under parallel collections — the CredProxDiagnosticsTests idiom) and collects
    /// every measurement emitted while <paramref name="emit"/> runs.
    /// </summary>
    private static List<Measurement> Collect(Action emit)
    {
        var seen = new System.Collections.Concurrent.ConcurrentQueue<Measurement>();
        using var listener = new MeterListener
        {
            InstrumentPublished = (instrument, l) =>
            {
                if (instrument.Meter.Name == "CredProx" && instrument.Name.StartsWith("credprox.", StringComparison.Ordinal))
                {
                    l.EnableMeasurementEvents(instrument);
                }
            },
        };
        listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) =>
            seen.Enqueue(new Measurement(instrument.Name, value, tags.ToArray().ToDictionary(t => t.Key, t => t.Value))));
        listener.Start();

        emit();

        return seen.ToList();
    }

    private static KeyValuePair<string, object?>[] FixedTags(string caller) =>
    [
        new(MeteringDiagnostics.CallerTag, caller),
        new(MeteringDiagnostics.CredentialTag, "vendor-a"),
        new(MeteringDiagnostics.DestinationTag, "vendor-a-dest"),
        new(MeteringDiagnostics.RouteTag, "route-1"),
        new(MeteringDiagnostics.StatusClassTag, "2xx"),
    ];

    [Theory]
    [InlineData(99, MeteringDiagnostics.Unknown)]
    [InlineData(100, "1xx")]
    [InlineData(199, "1xx")]
    [InlineData(200, "2xx")]
    [InlineData(204, "2xx")]
    [InlineData(301, "3xx")]
    [InlineData(404, "4xx")]
    [InlineData(499, "4xx")]
    [InlineData(500, "5xx")]
    [InlineData(599, "5xx")]
    [InlineData(600, MeteringDiagnostics.Unknown)]
    public void StatusClass_FallsIntoFixedBucket(int statusCode, string expected) =>
        Assert.Equal(expected, MeteringDiagnostics.StatusClass(statusCode));

    [Fact]
    public void RequestCounter_EmitsWithTheFiveConfigBoundedTags()
    {
        var caller = "m50-units-" + Guid.NewGuid();
        var seen = Collect(() => MeteringDiagnostics.Requests.Add(1, FixedTags(caller)));

        var m = Assert.Single(seen, x => x.Tags.TryGetValue(MeteringDiagnostics.CallerTag, out var c) && Equals(c, caller));
        Assert.Equal("credprox.requests", m.Instrument);
        Assert.Equal(1, m.Value);
        Assert.Equal(
            new[] { "credprox.caller", "credprox.credential", "credprox.destination", "credprox.route", "credprox.status_class" },
            m.Tags.Keys.OrderBy(k => k, StringComparer.Ordinal));
    }

    [Fact]
    public void RequestAndResponseByteHistograms_EmitBytesWithSameTags()
    {
        var caller = "m50-units-" + Guid.NewGuid();
        var seen = Collect(() =>
        {
            MeteringDiagnostics.RequestBytes.Record(1234, FixedTags(caller));
            MeteringDiagnostics.ResponseBytes.Record(5678, FixedTags(caller));
        });

        var req = Assert.Single(seen, x => x.Instrument == "credprox.request.bytes" && Equals(x.Tags[MeteringDiagnostics.CallerTag], caller));
        var resp = Assert.Single(seen, x => x.Instrument == "credprox.response.bytes" && Equals(x.Tags[MeteringDiagnostics.CallerTag], caller));
        Assert.Equal(1234, req.Value);
        Assert.Equal(5678, resp.Value);
        Assert.Equal(new[] { "credprox.caller", "credprox.credential", "credprox.destination", "credprox.route", "credprox.status_class" },
            req.Tags.Keys.OrderBy(k => k, StringComparer.Ordinal));
        Assert.Equal(new[] { "credprox.caller", "credprox.credential", "credprox.destination", "credprox.route", "credprox.status_class" },
            resp.Tags.Keys.OrderBy(k => k, StringComparer.Ordinal));
    }

    [Fact]
    public void UsageCounters_EmitTokensWithoutTheStatusClassTag()
    {
        var caller = "m50-units-" + Guid.NewGuid();
        var usageTags = new KeyValuePair<string, object?>[]
        {
            new(MeteringDiagnostics.CallerTag, caller),
            new(MeteringDiagnostics.CredentialTag, "vendor-a"),
            new(MeteringDiagnostics.DestinationTag, "vendor-a-dest"),
            new(MeteringDiagnostics.RouteTag, "route-1"),
        };
        var seen = Collect(() =>
        {
            MeteringDiagnostics.InputTokens.Add(7, usageTags);
            MeteringDiagnostics.OutputTokens.Add(42, usageTags);
        });

        var input = Assert.Single(seen, x => x.Instrument == "credprox.usage.input_tokens" && Equals(x.Tags[MeteringDiagnostics.CallerTag], caller));
        var output = Assert.Single(seen, x => x.Instrument == "credprox.usage.output_tokens" && Equals(x.Tags[MeteringDiagnostics.CallerTag], caller));
        Assert.Equal(7, input.Value);
        Assert.Equal(42, output.Value);
        // The provider-side attribution axis carries no status class (ADR-0008): a retried
        // 5xx must not fragment the token series of the same caller.
        Assert.DoesNotContain(MeteringDiagnostics.StatusClassTag, input.Tags.Keys);
        Assert.DoesNotContain(MeteringDiagnostics.StatusClassTag, output.Tags.Keys);
    }

    [Fact]
    public void InstrumentNames_UnitsAndMeterMatchTheAdr0008Contract()
    {
        Assert.Equal("CredProx", OperationsDiagnostics.Meter.Name);
        Assert.Equal("credprox.requests", MeteringDiagnostics.Requests.Name);
        Assert.Equal("credprox.request.bytes", MeteringDiagnostics.RequestBytes.Name);
        Assert.Equal("By", MeteringDiagnostics.RequestBytes.Unit);
        Assert.Equal("credprox.response.bytes", MeteringDiagnostics.ResponseBytes.Name);
        Assert.Equal("By", MeteringDiagnostics.ResponseBytes.Unit);
        Assert.Equal("credprox.usage.input_tokens", MeteringDiagnostics.InputTokens.Name);
        Assert.Equal("{token}", MeteringDiagnostics.InputTokens.Unit);
        Assert.Equal("credprox.usage.output_tokens", MeteringDiagnostics.OutputTokens.Name);
        Assert.Equal("{token}", MeteringDiagnostics.OutputTokens.Unit);
    }
}
