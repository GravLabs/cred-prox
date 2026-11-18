using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;

namespace CredProx;

/// <summary>
/// Resolution rule for option values that may be a <c>secret:</c> reference or a literal:
/// references resolve through the credential's scoped accessor; literals pass through
/// untouched (a non-secret client id is not a secret lookup). Credential add-ons resolve
/// their configured secret values through this same seam so the reference-vs-literal rule
/// has exactly one home.
/// </summary>
[Experimental("CREDPROX001")]
public static class SecretValues
{
    /// <summary>
    /// Resolves one option value: when it starts with the <c>secret:</c> prefix the value is
    /// a reference and is fetched through <paramref name="secrets"/>; otherwise it is a
    /// literal and passes through unchanged.
    /// </summary>
    /// <param name="value">The configured option value, or <see langword="null"/>.</param>
    /// <param name="secrets">The credential's scoped secret accessor.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>
    /// The secret behind the reference, or the untouched value for a literal or null.
    /// </returns>
    public static async ValueTask<string?> ResolveIfReferenceAsync(
        string? value,
        ISecretAccessor secrets,
        CancellationToken cancellationToken)
    {
        if (value is null || !value.StartsWith(SecretReferences.Prefix, StringComparison.Ordinal))
        {
            return value;
        }

        return await secrets.GetSecretAsync(value, cancellationToken).ConfigureAwait(false);
    }
}
