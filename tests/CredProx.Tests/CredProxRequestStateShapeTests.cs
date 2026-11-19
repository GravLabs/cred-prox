using System.Reflection;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// Structural pin for the attach-arm allocation drift (docs/benchmarks.md, "The
/// carried allocation found and removed"). <c>160460d</c> gave every CredProx-routed
/// request a delegate — a display class plus an <see cref="Action{T}"/> stored on the
/// request state — and the three attach arms each paid about 113 bytes a request
/// through 0.12.0. A numeric budget in the battery cannot gate a signal that small:
/// the measured level moves by hundreds of bytes with the harness and the parallel
/// sibling load, so an absolute that catches 113 B false-REDs elsewhere. This guard
/// instead fails while any delegate-typed instance field rides <see cref="CredProxRequestState"/>
/// again — the shape that regression installed — and every attach arm routes through
/// that state, so one structural check stands in for all three arms. A per-request
/// closure created and invoked inline elsewhere on the transform path is invisible
/// here; the out-of-process bench gate, with its per-arm allowances, is the numeric
/// net for those. Static fields are exempt by design: a shared delegate costs
/// nothing per request.
/// </summary>
public sealed class CredProxRequestStateShapeTests
{
    [Fact]
    public void RequestStateCarriesNoDelegateTypedInstanceField()
    {
        var offenders = typeof(CredProxRequestState)
            .GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            .Where(field => typeof(Delegate).IsAssignableFrom(field.FieldType))
            .Select(field => $"{field.FieldType.Name} {field.Name}")
            .ToList();

        Assert.True(
            offenders.Count == 0,
            $"CredProxRequestState carries delegate-typed instance field(s): {string.Join(", ", offenders)}. "
            + "A delegate stored on the per-request state is allocated or captured for every CredProx "
            + "request; 160460d's measured-body hand-off did exactly that and the attach arms paid "
            + "~113 B/req through 0.12.0. Carry the shape as a flag or an enum on the state instead "
            + "(see 7341816), and keep numeric per-request costs with the bench gate.");
    }
}
