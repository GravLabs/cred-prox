using CredProx;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// Pins the shared retried-body cap: refresh-on-401 and the resilience retry path document
/// one rule (<see cref="RefreshOn401Options.MaxRetriedBodyBytes"/> names
/// <see cref="ResilienceOptions.MaxRetriedBodyBytes"/> and the docs page states the default),
/// so the two defaults must stay equal — and equal to the value the 0.14.0 alignment moved
/// them to. The initializer is the mutant target: either one drifting kills this cell.
/// </summary>
public sealed class RetryBodyCapDefaultsTests
{
    [Fact]
    public void BothRetryBags_DefaultToOneMiB_TheSharedRule()
    {
        Assert.Equal(1024 * 1024, new RefreshOn401Options().MaxRetriedBodyBytes);
        Assert.Equal(1024 * 1024, new ResilienceOptions().MaxRetriedBodyBytes);
        Assert.Equal(
            new ResilienceOptions().MaxRetriedBodyBytes,
            new RefreshOn401Options().MaxRetriedBodyBytes);
    }
}
