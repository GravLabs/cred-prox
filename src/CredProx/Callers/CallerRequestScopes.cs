using System.Diagnostics.CodeAnalysis;

namespace CredProx;

/// <summary>
/// The per-request scope set published by an authenticating layer (ADR-0004):
/// the caller-token path sets it from the token's <c>roles</c>/<c>scp</c> claim, and
/// the operation allow-list stage intersects the caller's rules with it — a named rule
/// only runs when its <see cref="CallerOperationRule.Name"/> is in this set. An unnamed
/// rule admits no token and a caller without named rules admits none — the mere
/// presence of this feature denies both. The set
/// never widens what the caller's own rules admit, and the caller-key path sets no
/// feature at all, so keyed requests are unaffected. Any authentication layer that
/// sets this feature (a custom handler, a future introspection scheme) narrows the
/// same way without touching the allow-list stage.
/// </summary>
/// <param name="Scopes">The scope values of this request; never <see langword="null"/>,
/// empty when the credential carries none.</param>
[Experimental("CREDPROX001")]
public sealed record CallerRequestScopes(IReadOnlySet<string> Scopes)
{
    /// <summary>The scope values of this request.</summary>
    public IReadOnlySet<string> Scopes { get; } = Scopes ?? throw new ArgumentNullException(nameof(Scopes));

    /// <inheritdoc />
    public override string ToString() => $"CallerRequestScopes({Scopes.Count})";
}
