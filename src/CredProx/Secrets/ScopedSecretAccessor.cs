using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.RegularExpressions;
using CredProx.Abstractions;

namespace CredProx;

/// <summary>
/// The <see cref="ISecretAccessor"/> a plugin receives: it resolves only the <c>secret:</c>
/// references named in that plugin's own configuration, never anything else
/// (see <c>docs/credprox-plan.md</c> §3.5 rule 4). Error messages name the reference, never
/// a secret value.
/// </summary>
/// <remarks>
/// <para>
/// A declared name may itself contain <c>{placeholder}</c> segments — the plan's cayuse
/// example declares <c>secret:cayuse-{partition}-user</c> (§3.2). Such a declaration admits
/// any name matching the declared shape, where each placeholder matches any brace-free
/// text; the plugin's scope is the shape it declares, so placeholders should stay narrow
/// (a declaration of <c>secret:{partition}</c> would admit every name). Caller-controlled
/// partition values are additionally bounded by the destination partition allow-list
/// (§3.4), so the effective set stays config-bounded.
/// </para>
/// <para>
/// The allow-list is a snapshot taken at construction: a configuration reload that adds a
/// reference to the plugin's section takes effect when the accessor is recreated — the M4
/// plugin wiring recreates accessors on the secret source's change token. Secret values
/// themselves are read live and reload immediately.
/// </para>
/// </remarks>
[Experimental("CREDPROX001")]
public sealed class ScopedSecretAccessor : ISecretAccessor
{
    private readonly ISecretSource _source;
    private readonly HashSet<string> _exactNames;
    private readonly List<Regex> _shapes;

    /// <summary>
    /// Creates an accessor for one plugin instance.
    /// </summary>
    /// <param name="source">The secret source that holds the values.</param>
    /// <param name="allowedNames">
    /// The reference names (without the <c>secret:</c> prefix) this plugin may resolve —
    /// normally extracted from the plugin's own configuration section. A name containing
    /// <c>{placeholder}</c> segments admits every name matching its declared shape.
    /// </param>
    public ScopedSecretAccessor(ISecretSource source, IReadOnlySet<string> allowedNames)
    {
        _source = source ?? throw new ArgumentNullException(nameof(source));
        ArgumentNullException.ThrowIfNull(allowedNames);

        var exactNames = new HashSet<string>(StringComparer.Ordinal);
        var shapes = new List<Regex>();
        foreach (var name in allowedNames)
        {
            if (name.Contains('{', StringComparison.Ordinal))
            {
                shapes.Add(BuildShape(name));
            }
            else
            {
                exactNames.Add(name);
            }
        }

        _exactNames = exactNames;
        _shapes = shapes;
    }

    /// <inheritdoc />
    public async ValueTask<string> GetSecretAsync(string name, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(name);

        var reference = name.StartsWith(SecretReferences.Prefix, StringComparison.Ordinal)
            ? name[SecretReferences.Prefix.Length..]
            : name;

        if (!IsAllowed(reference))
        {
            throw new InvalidOperationException(
                $"The secret reference '{SecretReferences.Prefix}{reference}' is outside this plugin's configuration.");
        }

        var value = await _source.GetSecretAsync(reference, cancellationToken).ConfigureAwait(false);
        if (value is null)
        {
            throw new InvalidOperationException(
                $"The secret reference '{SecretReferences.Prefix}{reference}' does not resolve.");
        }

        return value;
    }

    private bool IsAllowed(string reference)
    {
        if (_exactNames.Contains(reference))
        {
            return true;
        }

        foreach (var shape in _shapes)
        {
            if (shape.IsMatch(reference))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Compiles a declared name into an anchored pattern: literal text matches exactly and
    /// each <c>{placeholder}</c> segment matches any brace-free text. An unterminated
    /// placeholder is treated as literal text (fails closed for expanded names).
    /// </summary>
    private static Regex BuildShape(string name)
    {
        var pattern = new StringBuilder(name.Length + 8);
        var literalStart = 0;
        var i = 0;
        while (i < name.Length)
        {
            if (name[i] == '{')
            {
                var end = name.IndexOf('}', i);
                if (end < 0)
                {
                    break;
                }

                pattern.Append(Regex.Escape(name[literalStart..i])).Append("[^{}]*");
                i = end + 1;
                literalStart = i;
            }
            else
            {
                i++;
            }
        }

        pattern.Append(Regex.Escape(name[literalStart..]));
        pattern.Insert(0, '^').Append('$');
        return new Regex(pattern.ToString(), RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    }
}
