using System.Net.Http;
using Xunit;
using Xunit.Abstractions;

namespace CredProx.LiveTests;

// Offline witnesses for the two live-cell instruments that false-REDed live run 4
// at e4e7ff2 (item 0b): (1) the settled-counter baseline — a console stream whose
// late batch overtakes the first non-zero one must NOT settle on the early value,
// or the mapped agent's own tail gets blamed on the unmapped run; (2) the
// collection-wide stand-in request counter — two cells sharing one fixture must
// each assert their own delta, so cell order cannot matter. Lives in the
// AgentTokens collection so the live-run leg executes it strictly in turn with
// the live cells (the stand-in port is fixed; two holders at once cannot coexist
// — which is exactly why the fixture is INJECTED, the collection's shared
// instance, never constructed here: the live leg holds that instance's stand-in
// from the billable cell to the end of the collection, and a local construction
// would die on the already-bound port right after the billable call was paid
// for).
[Collection("AgentTokens")]
[Trait("Layer", "Offline")]
public sealed class AgentTokensCounterInstrumentsTests
{
    private readonly AgentTokensFixture _fixture;
    private readonly ITestOutputHelper _output;

    public AgentTokensCounterInstrumentsTests(AgentTokensFixture fixture, ITestOutputHelper output)
    {
        _fixture = fixture;
        _output = output;
    }

    [Fact]
    public async Task WaitTokenCountersSettled_LateBatch_IsNotTheBaseline()
    {
        // The canned console stream: an early batch mid-drain (484/300), then the
        // agent's late batch (1283/800), then quiet (1283/800 again). The settled
        // baseline must be the late pair — the first-snapshot shape would have
        // taken 484 and blamed 1283 on the next run.
        (long, long)[] stream = { (484L, 300L), (1283L, 800L), (1283L, 800L), (1283L, 800L) };
        var i = 0;
        var settled = await LiveHosts.WaitTokenCountersSettled(
            () => stream[Math.Min(i++, stream.Length - 1)],
            5,
            10,
            () => "settled-witness: stream never settled");

        Assert.Equal(1283L, settled.Inputs);
        Assert.Equal(800L, settled.Outputs);
        Assert.NotEqual(484L, settled.Inputs); // the stale-snapshot value is rejected by construction
        _output.WriteLine($"settled-witness baseline={settled.Inputs}/{settled.Outputs} early-snapshot=484/300 rejected");
    }

    [Fact]
    public async Task WaitTokenCountersSettled_NeverRepeats_ThrowsTheNamedDiagnostic()
    {
        // A meter that keeps moving never settles: the helper must time out with the
        // caller's diagnostic, not return a stale or a made-up pair.
        var n = 0;
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            LiveHosts.WaitTokenCountersSettled(
                () => (++n, ++n),
                5,
                1,
                () => "settled-witness-never-settled"));
        Assert.Contains("settled-witness-never-settled", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WaitTokenCountersSettled_ConstantNoBatchPair_ThrowsInsteadOfSettling()
    {
        // A stream that only ever answers (-1,-1) — no batch yet, forever — is
        // PAIRED-EQUAL but not a baseline: equality alone would "settle" on -1 and
        // hand the caller a -1 vs -1 comparison, the exact vacuous shape the fold
        // rule refuses. The non-zero guard must keep timing out with the diagnostic.
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            LiveHosts.WaitTokenCountersSettled(
                () => (-1L, -1L),
                5,
                1,
                () => "settled-witness-no-batch"));
        Assert.Contains("settled-witness-no-batch", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TwoCells_OneCollection_EachCountsOnlyItsOwnDocsRequest()
    {
        // The order-independence witness: one fixture, two back-to-back "cells".
        // Each takes its delta before its own call and sees +1; the absolute count
        // is 2 by the end — which is exactly the value that false-REDed the old
        // Assert.Equal(1, ...) shape when the billable cell ran first.
        _fixture.StartStandIn();
        using var client = new HttpClient { BaseAddress = new Uri(AgentTokensFixture.StandInUrl) };

        var beforeFirst = _fixture.DocsRequestCount;
        using (var first = await client.GetAsync("/docs/readme"))
        {
            Assert.True(first.IsSuccessStatusCode, "the stand-in did not answer the first docs request");
            Assert.Contains(AgentTokensFixture.StandInMarker, await first.Content.ReadAsStringAsync());
        }
        Assert.Equal(beforeFirst + 1, _fixture.DocsRequestCount);

        var beforeSecond = _fixture.DocsRequestCount;
        using (var second = await client.GetAsync("/docs/readme"))
        {
            Assert.True(second.IsSuccessStatusCode, "the stand-in did not answer the second docs request");
        }
        Assert.Equal(beforeSecond + 1, _fixture.DocsRequestCount);

        Assert.Equal(2, _fixture.DocsRequestCount - beforeFirst);
        Assert.False(
            _fixture.SawBearerToken,
            "a bearer reached the docs stand-in — this flag is collection-wide and sticky: when a live " +
            "cell ran before this one it names THAT cell's leak, not these headerless offline requests");
        _output.WriteLine("order-witness: deltas 1 and 1 on absolute 2 — cell order cannot matter");
    }
}
