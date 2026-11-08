using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage for <see cref="ThrottleOptionsValidator"/>: the zero-means-disabled
/// postures (0 permits, 0 concurrency) and the strictly-positive windows are the throttle
/// startup contract. Every bound pinned in both directions, top level and per cluster,
/// with the exact operator message.
/// </summary>
public sealed class ThrottleOptionsValidatorTests
{
    private static ThrottleOptionsValidator Validator() => new();

    private static void AssertAccepted(ThrottleOptions options) =>
        Assert.True(Validator().Validate(null, options).Succeeded);

    private static void AssertFailure(ThrottleOptions options, string expectedMessage)
    {
        var result = Validator().Validate(null, options);
        Assert.False(result.Succeeded);
        Assert.Equal(expectedMessage, Assert.Single(result.Failures!));
    }

    [Fact]
    public void Defaults_AreAccepted() => AssertAccepted(new ThrottleOptions());

    [Fact]
    public void NullOptions_Throws()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => Validator().Validate(null, null!));

        Assert.Equal("options", ex.ParamName);
    }

    [Fact]
    public void PermitsPerInterval_Zero_IsAccepted() =>
        // 0 disables the rate limit — a supported posture, not nonsense.
        AssertAccepted(new ThrottleOptions { PermitsPerInterval = 0 });

    [Fact]
    public void PermitsPerInterval_Negative_Fails() =>
        AssertFailure(
            new ThrottleOptions { PermitsPerInterval = -1 },
            "CredProx:Throttling:PermitsPerInterval must be >= 0 (0 disables the rate limit).");

    [Fact]
    public void MaxConcurrency_Positive_IsAccepted() =>
        AssertAccepted(new ThrottleOptions { MaxConcurrency = 5 });

    [Fact]
    public void MaxConcurrency_Negative_Fails() =>
        AssertFailure(
            new ThrottleOptions { MaxConcurrency = -1 },
            "CredProx:Throttling:MaxConcurrency must be >= 0 (0 disables the concurrency limit).");

    [Fact]
    public void QueueLimit_Zero_IsAccepted() =>
        // 0 means 'no queueing': reject immediately, a supported posture.
        AssertAccepted(new ThrottleOptions { QueueLimit = 0 });

    [Fact]
    public void QueueLimit_Negative_Fails() =>
        AssertFailure(
            new ThrottleOptions { QueueLimit = -1 },
            "CredProx:Throttling:QueueLimit must be >= 0.");

    [Theory]
    [InlineData("00:00:00")]
    [InlineData("-00:00:01")]
    public void Interval_NotPositive_Fails(string value) =>
        AssertFailure(
            new ThrottleOptions { Interval = TimeSpan.Parse(value) },
            "CredProx:Throttling:Interval must be positive.");

    [Theory]
    [InlineData("00:00:00")]
    [InlineData("-00:00:01")]
    public void MaxQueueWait_NotPositive_Fails(string value) =>
        AssertFailure(
            new ThrottleOptions { MaxQueueWait = TimeSpan.Parse(value) },
            "CredProx:Throttling:MaxQueueWait must be positive.");

    [Theory]
    [InlineData("00:00:00")]
    [InlineData("-00:00:01")]
    public void MaxPause_NotPositive_Fails(string value) =>
        AssertFailure(
            new ThrottleOptions { MaxPause = TimeSpan.Parse(value) },
            "CredProx:Throttling:MaxPause must be positive.");

    // --- per-cluster overrides -----------------------------------------------------------

    [Fact]
    public void Cluster_AllNulls_Inherits_AndIsAccepted() =>
        AssertAccepted(new ThrottleOptions { Clusters = { ["c1"] = new() } });

    [Fact]
    public void Cluster_ZeroIntegersAndPositiveWindows_AreAccepted()
    {
        var options = new ThrottleOptions();
        options.Clusters["c1"] = new ThrottleClusterOptions
        {
            PermitsPerInterval = 0,
            MaxConcurrency = 0,
            QueueLimit = 0,
            Interval = TimeSpan.FromMilliseconds(1),
            MaxQueueWait = TimeSpan.FromMilliseconds(1),
            MaxPause = TimeSpan.FromMilliseconds(1),
        };

        AssertAccepted(options);
    }

    [Fact]
    public void Cluster_EveryFieldInvalid_FailsEachClusterPath()
    {
        var options = new ThrottleOptions();
        options.Clusters["permits"] = new ThrottleClusterOptions { PermitsPerInterval = -1 };
        options.Clusters["concurrency"] = new ThrottleClusterOptions { MaxConcurrency = -1 };
        options.Clusters["queue"] = new ThrottleClusterOptions { QueueLimit = -1 };
        options.Clusters["interval"] = new ThrottleClusterOptions { Interval = TimeSpan.Zero };
        options.Clusters["wait"] = new ThrottleClusterOptions { MaxQueueWait = TimeSpan.Zero };
        options.Clusters["pause"] = new ThrottleClusterOptions { MaxPause = TimeSpan.Zero };

        var failures = Validator().Validate(null, options).Failures!.ToList();

        Assert.Equal(6, failures.Count);
        Assert.Contains("CredProx:Throttling:Clusters:permits:PermitsPerInterval must be >= 0.", failures);
        Assert.Contains("CredProx:Throttling:Clusters:concurrency:MaxConcurrency must be >= 0.", failures);
        Assert.Contains("CredProx:Throttling:Clusters:queue:QueueLimit must be >= 0.", failures);
        Assert.Contains("CredProx:Throttling:Clusters:interval:Interval must be positive.", failures);
        Assert.Contains("CredProx:Throttling:Clusters:wait:MaxQueueWait must be positive.", failures);
        Assert.Contains("CredProx:Throttling:Clusters:pause:MaxPause must be positive.", failures);
    }
}
