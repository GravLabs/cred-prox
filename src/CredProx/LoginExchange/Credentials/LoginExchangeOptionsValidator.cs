using Microsoft.Extensions.Options;

namespace CredProx;

/// <summary>
/// Startup validation for <see cref="LoginExchangeOptions"/>: endpoint required, method
/// GET/POST, at most one credential style, ResponseField present whenever the response
/// mode names a field, and a coherent cookie placement.
/// </summary>
internal sealed class LoginExchangeOptionsValidator : IValidateOptions<LoginExchangeOptions>
{
    public ValidateOptionsResult Validate(string? name, LoginExchangeOptions options)
    {
        var failures = new List<string>();

        if (string.IsNullOrEmpty(options.LoginEndpoint))
        {
            failures.Add("LoginEndpoint is required.");
        }

        if (options.Location == CredentialLocation.Query)
        {
            failures.Add("Location Query is not supported for a login exchange; use Header or Cookie.");
        }

        if (options.Location == CredentialLocation.Cookie)
        {
            if (!string.IsNullOrEmpty(options.AttachPrefix))
            {
                failures.Add("AttachPrefix is not supported when Location is Cookie; a cookie carries the raw value.");
            }

            var cookieName = options.Name ?? options.ResponseField;
            if (string.IsNullOrEmpty(cookieName))
            {
                failures.Add("Name or ResponseField is required when Location is Cookie: the cookie to replay must be named.");
            }
            else if (!CredProxCookieNames.IsValid(cookieName))
            {
                failures.Add($"Cookie name '{cookieName}' is not a valid RFC 6265 cookie name.");
            }
        }

        if (options.Method.Trim().ToUpperInvariant() is not ("GET" or "POST"))
        {
            failures.Add($"Method '{options.Method}' is not supported; use GET or POST.");
        }

        if (options.Basic is not null && options.Form is not null)
        {
            failures.Add("Basic and Form are mutually exclusive; configure one credential style.");
        }

        if (options.Response != LoginExchangeResponse.RawBody && string.IsNullOrEmpty(options.ResponseField))
        {
            failures.Add($"ResponseField is required for Response mode '{options.Response}'.");
        }

        return failures.Count > 0 ? ValidateOptionsResult.Fail(failures) : ValidateOptionsResult.Success;
    }
}
