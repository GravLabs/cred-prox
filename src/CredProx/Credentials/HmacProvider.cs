using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;

namespace CredProx;

/// <summary>
/// The built-in <c>Hmac</c> provider: resolves the shared key through the credential's
/// scoped accessor. Signature-style credential — the attach step places nothing on the
/// request (<c>IHasAttachment</c> is deliberately absent); the
/// <see cref="HmacSignFeature"/> consumes the resolved key at <see cref="Stage.Sign"/>
/// to write the signature header.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class HmacProvider : ICredentialProvider<HmacOptions>
{
    /// <inheritdoc />
    public string Type => "Hmac";

    /// <inheritdoc />
    public async ValueTask<string> GetCredentialAsync(
        HmacOptions options,
        ISecretAccessor secrets,
        CredentialRequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(secrets);
        ArgumentNullException.ThrowIfNull(context);

        if (string.IsNullOrEmpty(options.Secret))
        {
            throw new InvalidOperationException(
                $"The HMAC credential '{context.CredentialName}' has no Secret configured.");
        }

        var key = await SecretValues
            .ResolveIfReferenceAsync(options.Secret, secrets, cancellationToken).ConfigureAwait(false);

        if (string.IsNullOrEmpty(key))
        {
            throw new InvalidOperationException(
                $"The HMAC credential '{context.CredentialName}' does not resolve.");
        }

        return key;
    }
}
