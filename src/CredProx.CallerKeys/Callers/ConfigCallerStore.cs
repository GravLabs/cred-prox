using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using CredProx.Abstractions;
using CredProx.CallerKeys;

namespace CredProx;

/// <summary>
/// The built-in <see cref="ICallerStore"/>: resolves presented key values against the key
/// table committed in the live <see cref="CallerRegistryGeneration"/>. The
/// table is built eagerly inside every bind that produced the registry — at host start and
/// on every accepted rebind (see <see cref="CallerKeyTableContributor"/>) — so this reader
/// takes the registry and its table as one atomic snapshot: a refused edit leaves the
/// previous generation serving in full, a configuration reload never re-keys a lookup
/// mid-request, and the request path never touches configuration or resolves a secret.
/// The key value is hashed with SHA-256 and compared to every stored hash with
/// <see cref="CryptographicOperations.FixedTimeEquals"/> — every entry is visited even
/// after a match, so neither the key value nor its position in the set leaks through
/// timing. Expired keys fail like unknown ones.
/// The key value never leaves this method: it is not stored, logged or carried in any
/// result.
/// </summary>
/// <remarks>
/// A generation without the committed table means the feature registration was assembled
/// without its contributor — a wiring error, not a runtime condition. It throws rather
/// than serving an empty table, which would silently authenticate nobody.
/// </remarks>
[Experimental("CREDPROX001")]
public sealed class ConfigCallerStore(
    CallerRegistryProvider registryProvider,
    TimeProvider timeProvider) : ICallerStore
{
    /// <inheritdoc />
    public ValueTask<CallerKeyMatch?> ResolveKeyAsync(string keyValue, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(keyValue);

        var presented = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(keyValue));
        CallerKeyMatch? match = null;

        // One snapshot for the whole loop: the provider swaps the live generation
        // atomically, so the table enumerated here is exactly the table built against the
        // registry this generation committed.
        var generation = registryProvider.CurrentGeneration;
        if (!generation.TryGetContributed<CallerKeyTableContributor>(out var data))
        {
            throw new InvalidOperationException(
                "The live caller registry generation carries no caller-key table; " +
                "the caller-keys feature is registered without its registry contributor.");
        }

        var table = (CallerKeyTable)data;

        // Visit every key of every caller: FixedTimeEquals per entry, no early exit, so
        // the loop's duration depends on the size of the key set, never on the value.
        foreach (var entry in table.Entries)
        {
            var equals = CryptographicOperations.FixedTimeEquals(presented, entry.Hash);
            if (equals && match is null)
            {
                var expired = entry.ExpiresAt is { } at && timeProvider.GetUtcNow() >= at;
                if (!expired)
                {
                    match = new CallerKeyMatch(new CallerIdentity(entry.CallerId, entry.KeyId));
                }
            }

            cancellationToken.ThrowIfCancellationRequested();
        }

        CryptographicOperations.ZeroMemory(presented);
        return new(match);
    }
}
