using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;

namespace CredProx;

/// <summary>
/// The built-in <c>StaticKey</c> provider (see <c>docs/credprox-plan.md</c> §4): resolves the
/// configured key reference through the credential's scoped accessor. No caching is needed —
/// resolution is a dictionary read; placement (header or query, overwrite semantics) is
/// declared by <see cref="StaticKeyOptions"/> and applied by the attach step.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class StaticKeyProvider : ICredentialProvider<StaticKeyOptions>
{
    /// <inheritdoc />
    public string Type => "StaticKey";

    /// <inheritdoc />
    public async ValueTask<string> GetCredentialAsync(
        StaticKeyOptions options,
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
                $"The static-key credential '{context.CredentialName}' has no Secret configured.");
        }

        var value = await SecretValues
            .ResolveIfReferenceAsync(options.Secret, secrets, cancellationToken).ConfigureAwait(false);

        if (string.IsNullOrEmpty(value))
        {
            throw new InvalidOperationException(
                $"The static-key credential '{context.CredentialName}' does not resolve.");
        }

        return value;
    }
}
