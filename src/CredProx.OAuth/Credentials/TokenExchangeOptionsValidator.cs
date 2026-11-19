using Microsoft.Extensions.Options;

namespace CredProx;

/// <summary>
/// Startup validation for <see cref="TokenExchangeOptions"/>: a validation source
/// (Authority or Issuer+JwksUri), the mandatory inbound Audience, a reachable token endpoint
/// (explicit or discovered), and a client id for the exchange call.
/// </summary>
internal sealed class TokenExchangeOptionsValidator : IValidateOptions<TokenExchangeOptions>
{
    public ValidateOptionsResult Validate(string? name, TokenExchangeOptions options)
    {
        var failures = new List<string>();

        // Per docs/adr/0002: the binder refuses the NAME of a removed enum
        // member but accepts any NUMBER, so Mode: 1 (the old EntraObo value) would bind to
        // the undefined enum and silently run the Rfc8693 exchange. IsDefined - not
        // != Rfc8693 - so a future member would bind and validate cleanly; the failure
        // names the value.
        if (!Enum.IsDefined(options.Mode))
        {
            failures.Add(
                $"Mode is not a defined TokenExchangeMode value: '{(int)options.Mode}'. " +
                "The Entra OBO mode was removed in M27 (docs/adr/0002-remove-entra-obo.md); " +
                "use Mode: Rfc8693 or omit the key.");
        }

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

        // The key material that validates INBOUND tokens is a different risk class from
        // outbound token endpoints (docs/adr/0003): over plain http anyone on the network
        // path can swap the signing keys and forge an inbound token CredProx exchanges.
        // https is the default; a private-network http IdP must opt out explicitly, and
        // the refusal names the option. A template that hides the scheme passes startup;
        // the runtime fetch fails closed on the same rule.
        if (options.RequireHttpsMetadata)
        {
            if (TokenExchangeOptions.IsPlainHttp(options.Authority))
            {
                failures.Add(
                    "Authority uses plain http, but the keys that validate inbound tokens must arrive over https. " +
                    $"Set {nameof(TokenExchangeOptions.RequireHttpsMetadata)} to false to allow a private-network http IdP.");
            }

            if (TokenExchangeOptions.IsPlainHttp(options.JwksUri))
            {
                failures.Add(
                    "JwksUri uses plain http, but the keys that validate inbound tokens must arrive over https. " +
                    $"Set {nameof(TokenExchangeOptions.RequireHttpsMetadata)} to false to allow a private-network http IdP.");
            }
        }

        if (!hasAuthority && !string.IsNullOrEmpty(options.Issuer) && !hasJwks)
        {
            failures.Add("Issuer requires JwksUri (with Authority the issuer is discovered).");
        }

        if (hasJwks && !hasAuthority && string.IsNullOrEmpty(options.Issuer))
        {
            // Nothing discovers the issuer in explicit-JWKS mode; ValidIssuer=null would
            // reject every token at runtime — fail at startup instead.
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
