using Xunit;

namespace CredProx.LiveTests;

/// <summary>
/// Non-vacuity witness for LiveHosts.CounterValue (M50 live failure). Every live
/// metered wait reads the console exporter through that one helper, so if the
/// helper's markers ever stop matching the shipped exporter's bytes, the reads
/// silently return -1 forever — which is exactly how the M50 live cell failed on a
/// healthy pipeline (it parsed the pre-1.12 spelling "Metric name:" / "Metric
/// value:"; OpenTelemetry.Exporter.Console 1.15.3 prints "Metric Name:" and
/// "Value:"). The fixture below is captured verbatim from the console exporter of
/// the packaged sample host, so a future exporter that renames these lines fails
/// this cell loudly instead of leaving waits blind.
/// </summary>
[Trait("Layer", "Offline")]
public sealed class LiveHostsCounterParseTests
{
    // Captured byte-for-byte from the packaged AiGateway sample host run over the
    // h2c vendor stand-in (two forwarded requests: one GET, one usage-carrying POST).
    // RECAPTURE RULE (NANO-2): this fixture pins the console exporter's line shape.
    // Whenever any OpenTelemetry.* package version moves (Directory.Packages.props),
    // recapture it from a packaged-host run in the same battery — a renamed marker
    // line must fail THIS cell loudly (recapture = re-capture bytes + confirm the
    // cell's Contains pins still describe what the shipped dll actually prints),
    // not silently age into a blind probe.
    private const string CapturedBatch =
        "Metric Name: credprox.requests, Description: Forwarded requests, tagged by caller, credential, destination, route and status class., Metric Type: LongSum\n"
        + "Instrumentation scope (Meter):\n"
        + "\tName: CredProx\n"
        + "\tVersion: 0.1.0\n"
        + "(2026-11-23T03:11:52.2750486Z, 2026-11-23T03:12:04.3130229Z] credprox.caller: h2-metered credprox.credential: ai-provider credprox.destination: ai credprox.route: ai credprox.status_class: 2xx \n"
        + "Value: 2\n"
        + "Metric Name: credprox.response.bytes, Description: Body bytes delivered to the caller per metered request., Unit: By, Metric Type: Histogram\n"
        + "Instrumentation scope (Meter):\n"
        + "\tName: CredProx\n"
        + "\tVersion: 0.1.0\n"
        + "(2026-11-23T03:11:52.2756211Z, 2026-11-23T03:12:04.3130255Z] credprox.caller: h2-metered credprox.credential: ai-provider credprox.destination: ai credprox.route: ai credprox.status_class: 2xx \n"
        + "Value: Sum: 300 Count: 2 Min: 104 Max: 196 \n"
        + "(-Infinity,0]:0\n"
        + "(0,5]:0\n"
        + "(5,10]:0\n"
        + "(10,25]:0\n"
        + "(25,50]:0\n"
        + "(50,75]:0\n"
        + "(75,100]:0\n"
        + "(100,250]:2\n"
        + "(250,500]:0\n"
        + "(500,750]:0\n"
        + "(750,1000]:0\n"
        + "(1000,2500]:0\n"
        + "(2500,5000]:0\n"
        + "(5000,7500]:0\n"
        + "(7500,10000]:0\n"
        + "(10000,+Infinity]:0\n"
        + "Metric Name: credprox.usage.input_tokens, Description: Input tokens reported by the provider's own usage report (opted-in routes only); a response that reports no usage is not recorded., Unit: {token}, Metric Type: LongSum\n"
        + "Instrumentation scope (Meter):\n"
        + "\tName: CredProx\n"
        + "\tVersion: 0.1.0\n"
        + "(2026-11-23T03:11:52.2756374Z, 2026-11-23T03:12:04.3130259Z] credprox.caller: h2-metered credprox.credential: ai-provider credprox.destination: ai credprox.route: ai \n"
        + "Value: 9\n";

    [Fact]
    public void CounterValue_ParsesTheCapturedExporterBatch()
    {
        // the marker shape this helper is pinned to; reverting the helper to the
        // pre-1.12 spelling makes every assertion below go RED, never vacuous
        Assert.Contains("Metric Name: ", CapturedBatch, StringComparison.Ordinal);
        Assert.DoesNotContain("Metric name: ", CapturedBatch, StringComparison.Ordinal);
        Assert.Equal(2, LiveHosts.CounterValue(CapturedBatch, "credprox.requests"));
        Assert.Equal(9, LiveHosts.CounterValue(CapturedBatch, "credprox.usage.input_tokens"));
    }

    [Fact]
    public void CounterValue_NeverReadsAHistogramOrAMissingInstrument()
    {
        // the histogram value line is "Value: Sum:" — a counter read must not slip
        // past it into the following block's digits, and an instrument that is not
        // in the batch has no value to invent
        Assert.Equal(-1, LiveHosts.CounterValue(CapturedBatch, "credprox.response.bytes"));
        Assert.Equal(-1, LiveHosts.CounterValue(CapturedBatch, "credprox.usage.output_tokens"));
        Assert.Equal(-1, LiveHosts.CounterValue(CapturedBatch, "credprox.request.bytes"));
    }

    [Fact]
    public void BillableWaitGate_RefusesTheNoBatchMinusOne()
    {
        // LOW-1 fold witness for the billable agent cell: it gates every counter read on
        // exactly this predicate shape (BOTH token counters > 0 before the read, and again
        // on the unmoved comparison). On the captured batch the output counter is absent —
        // CounterValue honestly answers -1 — so the gate must refuse. -1 is a failing read,
        // never a pass and never a vacuous -1 vs -1 comparison. If this ever accepts the
        // captured batch, the billable wait is blind again and would burn the paid call.
        static bool BothCountersPositive(string stdout) =>
            LiveHosts.CounterValue(stdout, "credprox.usage.input_tokens") > 0
            && LiveHosts.CounterValue(stdout, "credprox.usage.output_tokens") > 0;

        Assert.False(BothCountersPositive(CapturedBatch));

        // and the refusal tracks the -1, not a broken parse: the same bytes plus the
        // missing counter's record satisfy the identical gate
        var withOutput = CapturedBatch
            + "Metric Name: credprox.usage.output_tokens, Description: Output tokens reported by the provider's own usage report (opted-in routes only)., Unit: {token}, Metric Type: LongSum\n"
            + "Instrumentation scope (Meter):\n"
            + "\tName: CredProx\n"
            + "\tVersion: 0.1.0\n"
            + "(2026-11-23T03:11:52.2756374Z, 2026-11-23T03:12:04.3130259Z] credprox.caller: h2-metered credprox.credential: ai-provider credprox.destination: ai credprox.route: ai \n"
            + "Value: 4\n";
        Assert.True(BothCountersPositive(withOutput));
    }
}
