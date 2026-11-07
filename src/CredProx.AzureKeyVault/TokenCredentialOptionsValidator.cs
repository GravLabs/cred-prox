using Microsoft.Extensions.Options;

namespace CredProx;

/// <summary>
/// Startup validation for <see cref="TokenCredentialOptions"/>: a scope is required —
/// an empty scope would silently request the wrong resource.
/// </summary>
internal sealed class TokenCredentialOptionsValidator : IValidateOptions<TokenCredentialOptions>
{
    public ValidateOptionsResult Validate(string? name, TokenCredentialOptions options)
    {
        return string.IsNullOrEmpty(options.Scope)
            ? ValidateOptionsResult.Fail("Scope is required.")
            : ValidateOptionsResult.Success;
    }
}
