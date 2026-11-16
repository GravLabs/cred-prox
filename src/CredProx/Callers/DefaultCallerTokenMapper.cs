using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Claims;
using CredProx.Abstractions;

namespace CredProx;

/// <summary>
/// The built-in <see cref="ICallerTokenMapper"/> (ADR-0004): the client id is the first
/// non-empty claim among <see cref="CallerTokenOptions.ClientClaimNames"/> (<c>azp</c>
/// then <c>appid</c>), matched case-insensitively against every caller's configured
/// <see cref="CallerDefinition.TokenClientIds"/>; the token's key id is
/// <c>token:&lt;uti&gt;</c> (<c>jti</c> second, <c>token:unknown</c> when the token
/// carries neither id claim); scopes are all values of the first present claim type
/// among <see cref="CallerTokenOptions.ScopeClaimNames"/> (<c>roles</c> then
/// <c>scp</c>). No client claim, an unlisted client id, or no caller listing it maps to
/// nothing: a valid token from an app nobody configured is not a caller. Token freshness
/// (<see cref="CallerTokenOptions.MaxTokenAge"/>) is enforced by the caller-authentication
/// stage <em>before</em> this mapper runs (M39, ADR-0004), so replacing the mapper cannot
/// drop the bound; that limit is read at startup and changing it requires a restart.
/// The live registry is read per call, so adding a caller's token client takes effect on
/// config reload like everything else here. Caller tokens require named rules: a token
/// gets exactly the operations its roles name; a caller without named rules admits no
/// token.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class DefaultCallerTokenMapper : ICallerTokenMapper
{
    private const string UnknownKeyId = "token:unknown";

    private readonly CallerRegistryProvider _registryProvider;
    private readonly CallerTokenOptions _options;

    /// <summary>Creates the mapper.</summary>
    /// <param name="registryProvider">The live caller registry to match client ids against.</param>
    /// <param name="options">The CredProx-side token options (claim-name lists).</param>
    public DefaultCallerTokenMapper(CallerRegistryProvider registryProvider, CallerTokenOptions options)
    {
        ArgumentNullException.ThrowIfNull(registryProvider);
        ArgumentNullException.ThrowIfNull(options);
        _registryProvider = registryProvider;
        _options = options;
    }

    /// <inheritdoc />
    public CallerTokenMapping? MapToken(ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        var clientId = FirstClaimValue(principal, _options.ClientClaimNames);
        if (clientId is null)
        {
            return null;
        }

        var registry = _registryProvider.Current;
        foreach (var callerId in registry.CallerIds)
        {
            if (!registry.TryGet(callerId, out var definition))
            {
                continue;
            }

            if (!definition.TokenClientIds.Any(id => string.Equals(id, clientId, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            var tokenId = FirstClaimValue(principal, ["uti", "jti"]);
            var keyId = tokenId is null ? UnknownKeyId : "token:" + tokenId;
            // The matched client id rides on the identity so audit records caller id,
            // client id and token id (ADR-0004) — never the token itself.
            return new CallerTokenMapping(
                new CallerIdentity(definition.CallerId, keyId, clientId),
                ReadScopes(principal));
        }

        return null;
    }

    // First claim among the configured names with a non-empty value; a present-but-empty
    // claim never matches (a client id of "" must not map to whoever lists "").
    private static string? FirstClaimValue(ClaimsPrincipal principal, IReadOnlyList<string> claimNames)
    {
        foreach (var name in claimNames)
        {
            var value = principal.FindFirst(name)?.Value;
            if (!string.IsNullOrEmpty(value))
            {
                return value;
            }
        }

        return null;
    }

    // The first PRESENT scope claim type contributes all of its values; later names are
    // never consulted (a token carrying both roles and scp is a v1/v2 mix nobody issues).
    private IReadOnlySet<string> ReadScopes(ClaimsPrincipal principal)
    {
        var scopes = new HashSet<string>(StringComparer.Ordinal);
        foreach (var name in _options.ScopeClaimNames)
        {
            if (!principal.HasClaim(c => c.Type == name))
            {
                continue;
            }

            foreach (var claim in principal.FindAll(name))
            {
                scopes.Add(claim.Value);
            }

            break;
        }

        return scopes;
    }
}
