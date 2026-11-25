using Microsoft.Extensions.Options;

namespace CredProx;

/// <summary>
/// Startup validation for <see cref="CredProxMeteringOptions"/>: a non-positive or absurd
/// parse window is a configuration mistake and fails startup rather than silently
/// disabling (or unbounding) the usage peek.
/// </summary>
internal sealed class CredProxMeteringOptionsValidator : IValidateOptions<CredProxMeteringOptions>
{
    public ValidateOptionsResult Validate(string? name, CredProxMeteringOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        List<string> failures = [];
        if (options.MaxUsageParseBytes <= 0)
        {
            failures.Add("CredProx:Metering:MaxUsageParseBytes must be positive.");
        }
        else if (options.MaxUsageParseBytes > 64L * 1024 * 1024)
        {
            failures.Add("CredProx:Metering:MaxUsageParseBytes must be at most 67108864 (64 MiB).");
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }
}
