using Xunit;

namespace CredProx.SampleSmokes;

// Cross-sample guard, not a sample smoke: every port a sample claims on the host —
// a compose host mapping, a localhost URL in its appsettings (sample host and stubs),
// or a localhost URL in its test fixture — must belong to exactly one sample. The
// battery losses this prevents are silent: a double-booked port makes the later
// sample's fixture fail in the environment, not in the code under test.
public sealed class PortUniquenessTests
{
    [Fact]
    [Trait("Sample", "PortUniqueness")]
    public void EveryHostPortBelongsToExactlyOneSample()
    {
        var ownersByPort = SmokePorts.AllClaims()
            .GroupBy(c => c.Port)
            .ToDictionary(
                g => g.Key,
                g => g.Select(c => c.Sample).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(s => s, StringComparer.Ordinal).ToList());

        var clashes = ownersByPort
            .Where(kvp => kvp.Value.Count > 1)
            .OrderBy(kvp => kvp.Key)
            .Select(kvp => $"port {kvp.Key}: {string.Join(" vs ", kvp.Value)}");

        Assert.True(!clashes.Any(),
            "host ports double-booked across samples — give the mover its own free port:\n  " +
            string.Join("\n  ", clashes));
    }
}
