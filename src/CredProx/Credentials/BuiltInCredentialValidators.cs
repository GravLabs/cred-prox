using Microsoft.Extensions.Options;

namespace CredProx;

/// <summary>
/// Startup validation for <see cref="StaticKeyOptions"/>: the key and its placement name
/// are required.
/// </summary>
internal sealed class StaticKeyOptionsValidator : IValidateOptions<StaticKeyOptions>
{
    public ValidateOptionsResult Validate(string? name, StaticKeyOptions options)
    {
        var failures = new List<string>();

        if (string.IsNullOrEmpty(options.Secret))
        {
            failures.Add("Secret is required.");
        }

        if (string.IsNullOrEmpty(options.Name))
        {
            failures.Add("Name is required.");
        }

        return failures.Count > 0 ? ValidateOptionsResult.Fail(failures) : ValidateOptionsResult.Success;
    }
}
