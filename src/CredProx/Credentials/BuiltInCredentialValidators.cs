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

/// <summary>
/// Startup validation for <see cref="LoginExchangeOptions"/>: endpoint required, method
/// GET/POST, at most one credential style, ResponseField present whenever the response
/// mode names a field, and a coherent cookie placement (plan §8.1 session-cookie login).
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
            else if (!CredentialAttacher.IsValidCookieName(cookieName))
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

/// <summary>
/// Startup validation for <see cref="TokenExchangeOptions"/> (§3.6): a validation source
/// (Authority or Issuer+JwksUri), the mandatory inbound Audience, a reachable token endpoint
/// (explicit or discovered), and a client id for the exchange call.
/// </summary>
internal sealed class TokenExchangeOptionsValidator : IValidateOptions<TokenExchangeOptions>
{
    public ValidateOptionsResult Validate(string? name, TokenExchangeOptions options)
    {
        var failures = new List<string>();

        var hasAuthority = !string.IsNullOrEmpty(options.Authority);
        var hasJwks = !string.IsNullOrEmpty(options.JwksUri);
        if (!hasAuthority && !hasJwks)
        {
            failures.Add("Authority or Issuer+JwksUri is required to validate inbound tokens.");
        }

        if (hasAuthority && hasJwks)
        {
            failures.Add("Authority and JwksUri are mutually exclusive; pick one validation source.");
        }

        if (!hasAuthority && !string.IsNullOrEmpty(options.Issuer) && !hasJwks)
        {
            failures.Add("Issuer requires JwksUri (with Authority the issuer is discovered).");
        }

        if (hasJwks && !hasAuthority && string.IsNullOrEmpty(options.Issuer))
        {
            // Nothing discovers the issuer in explicit-JWKS mode; ValidIssuer=null would
            // reject every token at runtime — fail at startup instead (M14 review).
            failures.Add("Issuer is required with JwksUri (with Authority the issuer is discovered).");
        }

        if (string.IsNullOrEmpty(options.Audience))
        {
            // Without a mandatory audience any token the issuer minted for another client
            // becomes exchangeable (token confusion) - never a silent default (§3.6).
            failures.Add("Audience is required: the inbound token must be minted for this proxy's API.");
        }

        if (!hasAuthority && string.IsNullOrEmpty(options.TokenEndpoint))
        {
            failures.Add("TokenEndpoint is required when Authority discovery is not configured.");
        }

        if (string.IsNullOrEmpty(options.ClientId))
        {
            failures.Add("ClientId is required (the exchange is a confidential-client call).");
        }

        if (string.IsNullOrEmpty(options.SubjectClaim))
        {
            failures.Add("SubjectClaim must not be empty.");
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

/// <summary>
/// Startup validation for <see cref="HmacOptions"/>: the key and signature placement, and
/// a canonical-string recipe whose every component the signer can reproduce — plus the
/// buffering rule (§"Body buffering"): <c>bodyHash</c> requires <c>BufferBody</c> and a
/// positive cap, because signing a body the pipeline refuses to buffer would sign a lie.
/// </summary>
internal sealed class HmacOptionsValidator : IValidateOptions<HmacOptions>
{
    public ValidateOptionsResult Validate(string? name, HmacOptions options)
    {
        var failures = new List<string>();

        if (string.IsNullOrEmpty(options.Secret))
        {
            failures.Add("Secret is required.");
        }

        if (string.IsNullOrEmpty(options.SignatureHeader))
        {
            failures.Add("SignatureHeader is required.");
        }

        if (options.Components.Count == 0)
        {
            failures.Add("Components must list at least one canonical-string component.");
        }
        else
        {
            var needsBody = false;
            foreach (var token in options.Components)
            {
                if (!HmacSigner.TryParseComponent(token, out var kind, out _))
                {
                    failures.Add(
                        $"Component '{token}' is not recognized; use method, path, query, timestamp, bodyHash or header:<Name>.");
                }

                needsBody |= kind == HmacComponentKind.BodyHash;
            }

            if (needsBody && !options.BufferBody)
            {
                failures.Add("The bodyHash component requires BufferBody.");
            }
        }

        if (options.BufferBody && options.MaxBodyBytes <= 0)
        {
            failures.Add("MaxBodyBytes must be positive when BufferBody is enabled.");
        }

        return failures.Count > 0 ? ValidateOptionsResult.Fail(failures) : ValidateOptionsResult.Success;
    }
}
