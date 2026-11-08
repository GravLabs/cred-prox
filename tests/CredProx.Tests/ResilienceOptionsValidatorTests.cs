using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage for <see cref="ResilienceOptionsValidator"/>: the sweep found the
/// whole validator untested except through host wiring that only ever passed defaults.
/// Every boundary is pinned here in both directions — the accepted edge (kills
/// inclusive/exclusive mutants, which is what decides whether 10ms timeouts, zero retries
/// or a 500ms window can be configured at all) and the rejected edge with the exact
/// operator message, including the cluster-path interpolation and the exclusive-minimum
/// "greater than" clause.
/// </summary>
public sealed class ResilienceOptionsValidatorTests
{
    private static readonly TimeSpan MinTimeout = TimeSpan.FromMilliseconds(10);
    private static readonly TimeSpan MinWindow = TimeSpan.FromMilliseconds(500);
    private static readonly TimeSpan MaxWindow = TimeSpan.FromHours(24);

    private static ResilienceOptionsValidator Validator() => new();

    private static void AssertAccepted(ResilienceOptions options) =>
        Assert.True(Validator().Validate(null, options).Succeeded);

    private static void AssertFailure(ResilienceOptions options, string expectedMessage)
    {
        var result = Validator().Validate(null, options);
        Assert.False(result.Succeeded);
        Assert.Equal(expectedMessage, Assert.Single(result.Failures!));
    }

    [Fact]
    public void Defaults_AreAccepted() => AssertAccepted(new ResilienceOptions());

    [Fact]
    public void NullOptions_Throws()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => Validator().Validate(null, null!));

        Assert.Equal("options", ex.ParamName);
    }

    // --- top-level boundaries, both directions ------------------------------------------

    [Fact]
    public void AttemptTimeout_AtMinimum_IsAccepted() =>
        AssertAccepted(new ResilienceOptions { AttemptTimeout = MinTimeout });

    [Fact]
    public void AttemptTimeout_BelowMinimum_Fails() =>
        AssertFailure(
            new ResilienceOptions { AttemptTimeout = TimeSpan.FromMilliseconds(9) },
            "CredProx:Resilience:AttemptTimeout must be at least 00:00:00.0100000.");

    [Fact]
    public void AttemptTimeout_AtMaximum_IsAccepted() =>
        AssertAccepted(new ResilienceOptions { AttemptTimeout = MaxWindow });

    [Fact]
    public void AttemptTimeout_AboveMaximum_Fails() =>
        AssertFailure(
            new ResilienceOptions { AttemptTimeout = MaxWindow + TimeSpan.FromMilliseconds(1) },
            "CredProx:Resilience:AttemptTimeout must be at most 1.00:00:00.");

    [Fact]
    public void MaxRetries_Zero_IsAccepted() =>
        AssertAccepted(new ResilienceOptions { MaxRetries = 0 });

    [Fact]
    public void MaxRetries_Negative_Fails() =>
        AssertFailure(
            new ResilienceOptions { MaxRetries = -1 },
            "CredProx:Resilience:MaxRetries must be >= 0 (0 disables retries).");

    [Fact]
    public void RetryBaseDelay_Zero_Fails_NamingItExclusive() =>
        // Exclusive minimum: zero delay would hammer the upstream with no gap at all.
        AssertFailure(
            new ResilienceOptions { RetryBaseDelay = TimeSpan.Zero },
            "CredProx:Resilience:RetryBaseDelay must be at least greater than 00:00:00.");

    [Fact]
    public void RetryBaseDelay_AboveZero_IsAccepted() =>
        AssertAccepted(new ResilienceOptions { RetryBaseDelay = TimeSpan.FromMilliseconds(1) });

    [Fact]
    public void MaxRetriedBodyBytes_Zero_IsAccepted() =>
        // Zero means 'never retry a body', a supported posture, not nonsense.
        AssertAccepted(new ResilienceOptions { MaxRetriedBodyBytes = 0 });

    [Fact]
    public void MaxRetriedBodyBytes_Negative_Fails() =>
        AssertFailure(
            new ResilienceOptions { MaxRetriedBodyBytes = -1 },
            "CredProx:Resilience:MaxRetriedBodyBytes must be >= 0.");

    [Theory]
    [InlineData(0.0)]
    [InlineData(-0.5)]
    [InlineData(1.5)]
    public void FailureRatio_OutsideOpenInterval_Fails(double ratio) =>
        AssertFailure(
            new ResilienceOptions { FailureRatio = ratio },
            "CredProx:Resilience:FailureRatio must be in (0, 1].");

    [Fact]
    public void FailureRatio_AtOne_IsAccepted() =>
        AssertAccepted(new ResilienceOptions { FailureRatio = 1 });

    [Fact]
    public void MinimumThroughput_Two_IsAccepted() =>
        AssertAccepted(new ResilienceOptions { MinimumThroughput = 2 });

    [Fact]
    public void MinimumThroughput_BelowTwo_Fails() =>
        AssertFailure(
            new ResilienceOptions { MinimumThroughput = 1 },
            "CredProx:Resilience:MinimumThroughput must be >= 2.");

    [Fact]
    public void SamplingDuration_AtMinimum_IsAccepted() =>
        AssertAccepted(new ResilienceOptions { SamplingDuration = MinWindow });

    [Fact]
    public void SamplingDuration_BelowMinimum_Fails() =>
        AssertFailure(
            new ResilienceOptions { SamplingDuration = TimeSpan.FromMilliseconds(499) },
            "CredProx:Resilience:SamplingDuration must be at least 00:00:00.5000000.");

    [Fact]
    public void SamplingDuration_AboveMaximum_Fails() =>
        AssertFailure(
            new ResilienceOptions { SamplingDuration = MaxWindow + TimeSpan.FromMilliseconds(1) },
            "CredProx:Resilience:SamplingDuration must be at most 1.00:00:00.");

    [Fact]
    public void BreakDuration_AtMinimum_IsAccepted() =>
        AssertAccepted(new ResilienceOptions { BreakDuration = MinWindow });

    [Fact]
    public void BreakDuration_BelowMinimum_Fails() =>
        AssertFailure(
            new ResilienceOptions { BreakDuration = TimeSpan.FromMilliseconds(499) },
            "CredProx:Resilience:BreakDuration must be at least 00:00:00.5000000.");

    [Fact]
    public void BreakDuration_AboveMaximum_Fails() =>
        AssertFailure(
            new ResilienceOptions { BreakDuration = MaxWindow + TimeSpan.FromMilliseconds(1) },
            "CredProx:Resilience:BreakDuration must be at most 1.00:00:00.");

    // --- per-cluster overrides: null inherits, boundaries re-checked, path names cluster --

    [Fact]
    public void Cluster_AllNulls_Inherits_AndIsAccepted() =>
        // A cluster entry that overrides nothing must not run any bounds check: the
        // null-pattern guards are what keep default(TimeSpan) from being validated.
        AssertAccepted(new ResilienceOptions { Clusters = { ["c1"] = new() } });

    [Fact]
    public void Cluster_AtEveryMinimum_IsAccepted()
    {
        var options = new ResilienceOptions();
        options.Clusters["c1"] = new ResilienceClusterOptions
        {
            AttemptTimeout = MinTimeout,
            MaxRetries = 0,
            RetryBaseDelay = TimeSpan.FromMilliseconds(1),
            MaxRetriedBodyBytes = 0,
            FailureRatio = 1,
            MinimumThroughput = 2,
            SamplingDuration = MinWindow,
            BreakDuration = MinWindow,
        };

        AssertAccepted(options);
    }

    [Fact]
    public void Cluster_EveryFieldInvalid_FailsEachClusterPath()
    {
        var options = new ResilienceOptions();
        options.Clusters["timeouts"] = new ResilienceClusterOptions { AttemptTimeout = TimeSpan.FromMilliseconds(9) };
        options.Clusters["retries"] = new ResilienceClusterOptions { MaxRetries = -1 };
        options.Clusters["delay"] = new ResilienceClusterOptions { RetryBaseDelay = TimeSpan.Zero };
        options.Clusters["bytes"] = new ResilienceClusterOptions { MaxRetriedBodyBytes = -1 };
        options.Clusters["ratio"] = new ResilienceClusterOptions { FailureRatio = 0 };
        options.Clusters["throughput"] = new ResilienceClusterOptions { MinimumThroughput = 1 };
        options.Clusters["sampling"] = new ResilienceClusterOptions { SamplingDuration = TimeSpan.Zero };
        options.Clusters["break"] = new ResilienceClusterOptions { BreakDuration = MaxWindow + TimeSpan.FromMilliseconds(1) };

        var failures = Validator().Validate(null, options).Failures!.ToList();

        Assert.Equal(8, failures.Count);
        Assert.Contains("CredProx:Resilience:Clusters:timeouts:AttemptTimeout must be at least 00:00:00.0100000.", failures);
        Assert.Contains("CredProx:Resilience:Clusters:retries:MaxRetries must be >= 0.", failures);
        Assert.Contains("CredProx:Resilience:Clusters:delay:RetryBaseDelay must be at least greater than 00:00:00.", failures);
        Assert.Contains("CredProx:Resilience:Clusters:bytes:MaxRetriedBodyBytes must be >= 0.", failures);
        Assert.Contains("CredProx:Resilience:Clusters:ratio:FailureRatio must be in (0, 1].", failures);
        Assert.Contains("CredProx:Resilience:Clusters:throughput:MinimumThroughput must be >= 2.", failures);
        Assert.Contains("CredProx:Resilience:Clusters:sampling:SamplingDuration must be at least 00:00:00.5000000.", failures);
        Assert.Contains("CredProx:Resilience:Clusters:break:BreakDuration must be at most 1.00:00:00.", failures);
    }
}
