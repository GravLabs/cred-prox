using Microsoft.Extensions.Options;

namespace CredProx;

/// <summary>
/// Startup validation for <see cref="ResilienceOptions"/>: nonsense timeouts, retry
/// counts, ratios and windows fail fast at startup. The accepted ranges match what the
/// underlying <c>Http*StrategyOptions</c> validate (attempt timeout ≥ 10ms; sampling and
/// break durations ≥ 0.5s; all ≤ 24h) — a value outside them would otherwise crash the
/// first pipeline build instead of failing startup.
/// </summary>
internal sealed class ResilienceOptionsValidator : IValidateOptions<ResilienceOptions>
{
    private static readonly TimeSpan MinTimeout = TimeSpan.FromMilliseconds(10);
    private static readonly TimeSpan MinWindow = TimeSpan.FromMilliseconds(500);
    private static readonly TimeSpan MaxWindow = TimeSpan.FromHours(24);

    public ValidateOptionsResult Validate(string? name, ResilienceOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        List<string> failures = [];
        CheckWindow(failures, "CredProx:Resilience:AttemptTimeout", options.AttemptTimeout, MinTimeout, exclusiveMin: false);
        if (options.MaxRetries < 0)
        {
            failures.Add("CredProx:Resilience:MaxRetries must be >= 0 (0 disables retries).");
        }

        CheckWindow(failures, "CredProx:Resilience:RetryBaseDelay", options.RetryBaseDelay, TimeSpan.Zero, exclusiveMin: true);
        if (options.MaxRetriedBodyBytes < 0)
        {
            failures.Add("CredProx:Resilience:MaxRetriedBodyBytes must be >= 0.");
        }

        if (options.FailureRatio is <= 0 or > 1)
        {
            failures.Add("CredProx:Resilience:FailureRatio must be in (0, 1].");
        }

        if (options.MinimumThroughput < 2)
        {
            failures.Add("CredProx:Resilience:MinimumThroughput must be >= 2.");
        }

        CheckWindow(failures, "CredProx:Resilience:SamplingDuration", options.SamplingDuration, MinWindow, exclusiveMin: false);
        CheckWindow(failures, "CredProx:Resilience:BreakDuration", options.BreakDuration, MinWindow, exclusiveMin: false);

        foreach (var (cluster, o) in options.Clusters)
        {
            if (o.AttemptTimeout is { } timeout)
            {
                CheckWindow(failures, $"CredProx:Resilience:Clusters:{cluster}:AttemptTimeout", timeout, MinTimeout, exclusiveMin: false);
            }

            if (o.MaxRetries is < 0)
            {
                failures.Add($"CredProx:Resilience:Clusters:{cluster}:MaxRetries must be >= 0.");
            }

            if (o.RetryBaseDelay is { } delay)
            {
                CheckWindow(failures, $"CredProx:Resilience:Clusters:{cluster}:RetryBaseDelay", delay, TimeSpan.Zero, exclusiveMin: true);
            }

            if (o.MaxRetriedBodyBytes is < 0)
            {
                failures.Add($"CredProx:Resilience:Clusters:{cluster}:MaxRetriedBodyBytes must be >= 0.");
            }

            if (o.FailureRatio is { } ratio and (<= 0 or > 1))
            {
                failures.Add($"CredProx:Resilience:Clusters:{cluster}:FailureRatio must be in (0, 1].");
            }

            if (o.MinimumThroughput is < 2)
            {
                failures.Add($"CredProx:Resilience:Clusters:{cluster}:MinimumThroughput must be >= 2.");
            }

            if (o.SamplingDuration is { } sampling)
            {
                CheckWindow(failures, $"CredProx:Resilience:Clusters:{cluster}:SamplingDuration", sampling, MinWindow, exclusiveMin: false);
            }

            if (o.BreakDuration is { } breakDuration)
            {
                CheckWindow(failures, $"CredProx:Resilience:Clusters:{cluster}:BreakDuration", breakDuration, MinWindow, exclusiveMin: false);
            }
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }

    private static void CheckWindow(
        List<string> failures,
        string path,
        TimeSpan value,
        TimeSpan min,
        bool exclusiveMin)
    {
        if (exclusiveMin ? value <= min : value < min)
        {
            failures.Add($"{path} must be at least {(exclusiveMin ? "greater than " : "")}{min}.");
        }
        else if (value > MaxWindow)
        {
            failures.Add($"{path} must be at most {MaxWindow}.");
        }
    }
}
