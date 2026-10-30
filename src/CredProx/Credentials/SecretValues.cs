using CredProx.Abstractions;

namespace CredProx;

/// <summary>
/// Resolution rule for option values that may be a <c>secret:</c> reference or a literal:
/// references resolve through the credential's scoped accessor; literals pass through
/// untouched (a non-secret client id is not a secret lookup).
/// </summary>
internal static class SecretValues
{
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
