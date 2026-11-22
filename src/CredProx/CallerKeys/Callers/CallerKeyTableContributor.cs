using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;

namespace CredProx;

/// <summary>
/// Builds the caller-key table eagerly, inside the bind that produced the registry — at
/// host start and on every accepted rebind — so the table is committed as the same
/// accepted unit the registry is (see <see cref="ICallerRegistryContributor"/>). A key
/// whose <c>secret:</c> reference cannot be resolved here refuses the whole bind, exactly
/// like a refused shape: the previous registry and the previous table keep serving
/// together, startup is refused for the initial bind, and one error line names caller and
/// key. The request path never rebuilds and never resolves a secret: lookups read the
/// table committed in the live generation, so derived data can never drift from (or be
/// poisoned by configuration) the registry it was built against.
/// </summary>
/// <remarks>
/// Key entry shape was validated in the same bind (by <see cref="CallerKeyRules"/>) before
/// this runs; a failure here means a <c>secret:</c> reference went unresolvable between
/// validation and the table build, or the entry disappeared under the accepted registry.
/// Exceptions name caller and key id — never a key value or hash.
/// </remarks>
[Experimental("CREDPROX001")]
internal sealed class CallerKeyTableContributor(
    IConfiguration configuration,
    SecretAccessorFactory accessorFactory) : ICallerRegistryContributor
{
    private const string SecretReferencePrefix = "secret:";

    public object Contribute(CallerRegistry registry)
    {
        var entries = new List<CallerKeyEntry>();
        var callersSection = configuration.GetSection("CredProx:Callers");

        foreach (var callerId in registry.CallerIds)
        {
            var callerSection = callersSection.GetSection(callerId);
            var secrets = accessorFactory.CreateAccessor(callerSection);

            foreach (var keySection in callerSection.GetSection("Keys").GetChildren())
            {
                var keyId = keySection["KeyId"]
                    ?? throw new InvalidOperationException($"Caller '{callerId}' declares a key with no KeyId.");

                var hashDeclaration = keySection["KeyHash"]
                    ?? throw new InvalidOperationException($"Caller '{callerId}' key '{keyId}' has no KeyHash.");

                var hash = ResolveHash(secrets, hashDeclaration, callerId, keyId);

                DateTimeOffset? expiresAt = null;
                var expiry = keySection["ExpiresAt"];
                if (!string.IsNullOrWhiteSpace(expiry))
                {
                    if (!DateTimeOffset.TryParse(expiry, CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed))
                    {
                        throw new InvalidOperationException($"Caller '{callerId}' key '{keyId}' has an unparseable ExpiresAt.");
                    }

                    expiresAt = parsed;
                }

                entries.Add(new CallerKeyEntry(callerId, keyId, hash, expiresAt));
            }
        }

        return new CallerKeyTable(entries);
    }

    // The one place a bind resolves a secret (CallerKeyRules checks the declaration's
    // shape only, so each declared secret is read through the caller's own accessor
    // exactly once per bind), and the resolved value must parse as sha256:<hex>. A
    // failure throws — the provider treats it as a refused bind; nothing about the value
    // or the secret enters the exception: it names caller, key and the source exception's
    // type, never its message.
    private static byte[] ResolveHash(ScopedSecretAccessor secrets, string declaration, string callerId, string keyId)
    {
        var value = declaration;
        if (declaration.StartsWith(SecretReferencePrefix, StringComparison.Ordinal))
        {
            var name = declaration[SecretReferencePrefix.Length..];
            try
            {
                value = secrets.GetSecretAsync(name, CancellationToken.None).AsTask().GetAwaiter().GetResult();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                throw new InvalidOperationException(
                    $"Caller '{callerId}' key '{keyId}' could not resolve its KeyHash secret (source exception {ex.GetType().Name}).", ex);
            }

            if (string.IsNullOrWhiteSpace(value))
            {
                throw new InvalidOperationException($"Caller '{callerId}' key '{keyId}' resolved an empty KeyHash secret.");
            }
        }

        if (!CallerKeyRules.TryParseHash(value!, out var hash))
        {
            throw new InvalidOperationException(
                $"Caller '{callerId}' key '{keyId}' has a KeyHash that is not 'sha256:<64 hex digits>'.");
        }

        return hash;
    }
}

/// <summary>The key table committed with one generation.</summary>
/// <param name="Entries">Every accepted key, across all callers.</param>
internal sealed record CallerKeyTable(IReadOnlyList<CallerKeyEntry> Entries);

/// <summary>
/// One committed key entry: who it belongs to and its constant-time comparison material.
/// The presented key value never appears here — only its stored hash.
/// </summary>
internal sealed record CallerKeyEntry(string CallerId, string KeyId, byte[] Hash, DateTimeOffset? ExpiresAt);
