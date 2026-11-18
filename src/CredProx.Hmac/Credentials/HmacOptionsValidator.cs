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
