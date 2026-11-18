using System.Diagnostics.CodeAnalysis;
using System.Text;
using CredProx.Abstractions;

namespace CredProx;

/// <summary>
/// Expands the template forms: <c>{partition}</c> is
/// substituted first (secret names may contain it), then references are resolved through the
/// credential's scoped accessor — a whole value in the bare <c>secret:name</c> form is one
/// reference, and <c>{secret:...}</c> embeds references inside a larger string. Either way a
/// reference can only name a secret the credential's own configuration declares.
/// Secret values are never re-scanned, so a resolved value cannot inject further
/// expansion. Credential add-ons expand their templates through this same seam so their
/// configured values follow the same rules as the built-in types.
/// </summary>
[Experimental("CREDPROX001")]
public static class TemplateExpander
{
    private const string PartitionPlaceholder = "{partition}";
    private const string SecretPrefix = "{secret:";

    /// <summary>
    /// Expands one template value for one credential request: <c>{partition}</c> first,
    /// then secret references through the credential's own scoped accessor.
    /// </summary>
    /// <param name="template">The configured template value.</param>
    /// <param name="partition">The request's partition, when it carries one.</param>
    /// <param name="secrets">The credential's scoped secret accessor.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The expanded value.</returns>
    public static async ValueTask<string> ExpandAsync(
        string template,
        string? partition,
        ISecretAccessor secrets,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(template);
        ArgumentNullException.ThrowIfNull(secrets);

        var withPartition = ExpandPartition(template, partition);

        // The bare reference form (secret:name, possibly with {partition} already
        // expanded into the name) means "this whole value is a reference"; the braced
        // form embeds references inside a larger string.
        if (withPartition.StartsWith(SecretReferences.Prefix, StringComparison.Ordinal) &&
            !withPartition.Contains(SecretPrefix, StringComparison.Ordinal))
        {
            return await secrets.GetSecretAsync(withPartition, cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidOperationException(
                    $"The secret reference '{withPartition}' does not resolve.");
        }

        return await ExpandSecretsAsync(withPartition, secrets, cancellationToken).ConfigureAwait(false);
    }

    private static string ExpandPartition(string template, string? partition)
    {
        if (!template.Contains(PartitionPlaceholder, StringComparison.Ordinal))
        {
            return template;
        }

        if (partition is null)
        {
            throw new InvalidOperationException(
                "The credential configuration uses {partition} but this request carries no partition value.");
        }

        return template.Replace(PartitionPlaceholder, partition, StringComparison.Ordinal);
    }

    private static async ValueTask<string> ExpandSecretsAsync(
        string template,
        ISecretAccessor secrets,
        CancellationToken cancellationToken)
    {
        if (!template.Contains(SecretPrefix, StringComparison.Ordinal))
        {
            return template;
        }

        var result = new StringBuilder(template.Length);
        for (var i = 0; i < template.Length; i++)
        {
            if (template[i] != '{' || !template.AsSpan(i).StartsWith(SecretPrefix.AsSpan(), StringComparison.Ordinal))
            {
                result.Append(template[i]);
                continue;
            }

            // Match the closing brace by depth, mirroring SecretReferences.FindInValue.
            var depth = 1;
            var end = i + SecretPrefix.Length;
            while (end < template.Length && depth > 0)
            {
                if (template[end] == '{')
                {
                    depth++;
                }
                else if (template[end] == '}')
                {
                    depth--;
                }

                end++;
            }

            if (depth != 0)
            {
                // Unterminated reference: leave the text as-is; resolution will fail loudly
                // where the value is used, never silently drop the reference.
                result.Append(template, i, template.Length - i);
                return result.ToString();
            }

            var name = template[(i + SecretPrefix.Length)..(end - 1)];
            result.Append(await secrets.GetSecretAsync(name, cancellationToken).ConfigureAwait(false));
            i = end - 1;
        }

        return result.ToString();
    }
}
