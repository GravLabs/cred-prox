using Microsoft.Extensions.Options;

namespace CredProx;

/// <summary>
/// Startup validation for <see cref="OAuthClientCredentialsOptions"/>: the token endpoint
/// must be an absolute http(s) URL and a client id must be configured.
/// </summary>
internal sealed class OAuthClientCredentialsOptionsValidator : IValidateOptions<OAuthClientCredentialsOptions>
{
    public ValidateOptionsResult Validate(string? name, OAuthClientCredentialsOptions options)
    {
        var failures = new List<string>();

        if (string.IsNullOrEmpty(options.TokenEndpoint))
        {
            failures.Add("TokenEndpoint is required.");
        }
        else if (!Uri.TryCreate(options.TokenEndpoint, UriKind.Absolute, out var uri) ||
                 (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            failures.Add("TokenEndpoint must be an absolute http(s) URL.");
        }

        if (string.IsNullOrEmpty(options.ClientId))
        {
            failures.Add("ClientId is required.");
        }

        return failures.Count > 0 ? ValidateOptionsResult.Fail(failures) : ValidateOptionsResult.Success;
    }
}
