using Microsoft.Extensions.Options;

namespace CredProx;

/// <summary>
/// Startup validation for <see cref="ThrottleOptions"/>: negative limits and non-positive
/// windows are configuration mistakes and fail fast rather than silently disabling a limit.
/// </summary>
internal sealed class ThrottleOptionsValidator : IValidateOptions<ThrottleOptions>
{
    public ValidateOptionsResult Validate(string? name, ThrottleOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        List<string> failures = [];
        if (options.PermitsPerInterval < 0)
        {
            failures.Add("CredProx:Throttling:PermitsPerInterval must be >= 0 (0 disables the rate limit).");
        }

        if (options.MaxConcurrency < 0)
        {
            failures.Add("CredProx:Throttling:MaxConcurrency must be >= 0 (0 disables the concurrency limit).");
        }

        if (options.QueueLimit < 0)
        {
            failures.Add("CredProx:Throttling:QueueLimit must be >= 0.");
        }

        if (options.Interval <= TimeSpan.Zero)
        {
            failures.Add("CredProx:Throttling:Interval must be positive.");
        }

        if (options.MaxQueueWait <= TimeSpan.Zero)
        {
            failures.Add("CredProx:Throttling:MaxQueueWait must be positive.");
        }

        if (options.MaxPause <= TimeSpan.Zero)
        {
            failures.Add("CredProx:Throttling:MaxPause must be positive.");
        }

        foreach (var (cluster, overrideOptions) in options.Clusters)
        {
            if (overrideOptions.PermitsPerInterval is < 0)
            {
                failures.Add($"CredProx:Throttling:Clusters:{cluster}:PermitsPerInterval must be >= 0.");
            }

            if (overrideOptions.MaxConcurrency is < 0)
            {
                failures.Add($"CredProx:Throttling:Clusters:{cluster}:MaxConcurrency must be >= 0.");
            }

            if (overrideOptions.QueueLimit is < 0)
            {
                failures.Add($"CredProx:Throttling:Clusters:{cluster}:QueueLimit must be >= 0.");
            }

            if (overrideOptions.Interval is { } interval && interval <= TimeSpan.Zero)
            {
                failures.Add($"CredProx:Throttling:Clusters:{cluster}:Interval must be positive.");
            }

            if (overrideOptions.MaxQueueWait is { } queueWait && queueWait <= TimeSpan.Zero)
            {
                failures.Add($"CredProx:Throttling:Clusters:{cluster}:MaxQueueWait must be positive.");
            }

            if (overrideOptions.MaxPause is { } maxPause && maxPause <= TimeSpan.Zero)
            {
                failures.Add($"CredProx:Throttling:Clusters:{cluster}:MaxPause must be positive.");
            }
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }
}
