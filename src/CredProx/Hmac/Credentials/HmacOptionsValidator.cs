using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CredProx;

/// <summary>
/// Startup validation for <see cref="HmacOptions"/>: the key and signature placement, and
/// a canonical-string recipe whose every component the signer can reproduce — plus the
/// buffering rule: <c>bodyHash</c> requires <c>BufferBody</c> and a positive cap, because
/// signing a body the pipeline refuses to buffer would sign a lie.
/// </summary>
internal sealed class HmacOptionsValidator : IValidateOptions<HmacOptions>
{
    private readonly ILogger<HmacOptionsValidator>? _logger;

    public HmacOptionsValidator(ILogger<HmacOptionsValidator>? logger = null) =>
        _logger = logger;

    public ValidateOptionsResult Validate(string? name, HmacOptions options)
    {
        // An empty Separator stays VALID: vendor schemes exist that sign a bare
        // concatenation of components, and refusing to sign would make the library
        // unusable for them. The separator check cannot apply then — every value
        // "contains" the empty string — so the operator must hear that consequence
        // at startup instead; the other ambiguity refusals (a multi-value header
        // whose values contain a comma, a signed name on both header collections)
        // still fire. One warning per validation of the credential, naming it;
        // the binder validates each credential once per bind.
        if (options.Separator.Length == 0)
        {
            _logger?.LogWarning(
                "The HMAC credential '{Credential}' uses an empty Separator: components are concatenated with no boundary byte, so a value ending where the next begins lets two distinct requests sign identically. CredProx keeps signing such requests for vendor compatibility; choose a separator that cannot occur inside component values to keep boundary protection.",
                name ?? "default");
        }

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
