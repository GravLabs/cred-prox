using Microsoft.Extensions.Options;

namespace CredProx;

/// <summary>
/// Startup validation for <see cref="JwtAssertionOptions"/>: exactly one signing material,
/// the claim essentials, a coherent exchange mode, and sane lifetimes — so a broken
/// signing config fails at startup, not at the first vendor call.
/// </summary>
internal sealed class JwtAssertionOptionsValidator : IValidateOptions<JwtAssertionOptions>
{
    public ValidateOptionsResult Validate(string? name, JwtAssertionOptions options)
    {
        var failures = new List<string>();

        if (string.IsNullOrEmpty(options.SigningKey) && string.IsNullOrEmpty(options.SigningCertificate))
        {
            failures.Add("SigningKey or SigningCertificate is required.");
        }

        if (!string.IsNullOrEmpty(options.SigningKey) && !string.IsNullOrEmpty(options.SigningCertificate))
        {
            failures.Add("SigningKey and SigningCertificate are mutually exclusive.");
        }

        if (string.IsNullOrEmpty(options.Issuer))
        {
            failures.Add("Issuer is required.");
        }

        if (string.IsNullOrEmpty(options.Audience))
        {
            failures.Add("Audience is required.");
        }

        if (string.IsNullOrEmpty(options.TokenEndpoint))
        {
            failures.Add("TokenEndpoint is required.");
        }
        else if (!Uri.TryCreate(options.TokenEndpoint, UriKind.Absolute, out var uri) ||
                 (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            failures.Add("TokenEndpoint must be an absolute http(s) URL.");
        }

        if (options.Lifetime <= TimeSpan.Zero)
        {
            failures.Add("Lifetime must be positive.");
        }

        if (options.ClockSkew < TimeSpan.Zero)
        {
            failures.Add("ClockSkew must not be negative.");
        }

        if (options.DefaultLifetime <= TimeSpan.Zero)
        {
            failures.Add("DefaultLifetime must be positive.");
        }

        if (string.IsNullOrEmpty(options.TokenField))
        {
            failures.Add("TokenField is required.");
        }

        return failures.Count > 0 ? ValidateOptionsResult.Fail(failures) : ValidateOptionsResult.Success;
    }
}
