using Xunit;

namespace CredProx.LiveTests;

/// <summary>
/// Non-vacuity witness for LiveHosts.ContainsOnOneLine, the audit-first probe the
/// metered live cells use (NANO-1, from the checker's M50 live verdict). The probe
/// that preceded it was two Contains calls over the WHOLE stdout, which two unrelated
/// audit lines can satisfy: the caller marker rides that caller's GET line too, and
/// a method=POST from another caller completes the pair. The split fixture below is
/// exactly that blindness case — the old form must pass it (recorded, so a revert of
/// the helper to two Contains is RED, not vacuous) and the helper must not.
/// </summary>
[Trait("Layer", "Offline")]
public sealed class LiveHostsAuditProbeTests
{
    private const string CallerMarker = "credprox.proxied_call: caller=live-metered";
    private const string MethodMarker = "method=POST";

    // This caller's GET audited; the only POST audit line on the console belongs to
    // a different caller — no single line carries both markers.
    private const string SplitAudits =
        "info: credprox.proxied_call: caller=live-metered dest=ai method=GET status=200 bytes=15821\n"
        + "info: credprox.proxied_call: caller=sibling dest=ai method=POST status=200 bytes=204\n";

    // The metered POST audited on its own line (shape as the live runs print it).
    private const string RealPostAudit =
        "info: credprox.proxied_call: caller=live-metered dest=ai method=POST status=200 bytes=204\n";

    [Fact]
    public void ProbeDoesNotPairTwoUnrelatedAuditLines()
    {
        // the blindness of the two-Contains form, pinned as an assertion: the OLD
        // probe is satisfied here although this caller's POST never audited...
        Assert.True(
            SplitAudits.Contains(CallerMarker, StringComparison.Ordinal)
            && SplitAudits.Contains(MethodMarker, StringComparison.Ordinal));
        // ...and the one-line helper is not
        Assert.False(LiveHosts.ContainsOnOneLine(SplitAudits, CallerMarker, MethodMarker));
    }

    [Fact]
    public void ProbeMatchesTheRealAuditLine()
    {
        Assert.True(LiveHosts.ContainsOnOneLine(RealPostAudit, CallerMarker, MethodMarker));
        // and a console without any POST at all stays negative
        Assert.False(LiveHosts.ContainsOnOneLine(
            "info: credprox.proxied_call: caller=live-metered dest=ai method=GET status=200 bytes=15821\n",
            CallerMarker,
            MethodMarker));
    }
}
