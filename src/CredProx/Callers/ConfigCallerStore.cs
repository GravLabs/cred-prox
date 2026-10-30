using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using CredProx.Abstractions;

namespace CredProx;

/// <summary>
/// The built-in <see cref="ICallerStore"/>: resolves presented key values against the
/// hashed keys of one snapshot of the live <see cref="CallerRegistry"/> (§4 Phase B) — a
/// configuration reload arriving mid-resolution never makes the lookup throw. The key value is
/// hashed with SHA-256 and compared to every stored hash with
/// <see cref="CryptographicOperations.FixedTimeEquals"/> — every entry is visited even
/// after a match, so neither the key value nor its position in the set leaks through
/// timing (§5.2 "keys compared in constant time"). Expired keys fail like unknown ones;
/// revoked keys are gone from the registry after the reload that removed them. The key
/// value never leaves this method: it is not stored, logged or carried in any result.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class ConfigCallerStore(CallerRegistryProvider registryProvider, TimeProvider timeProvider) : ICallerStore
{
    /// <inheritdoc />
    public ValueTask<CallerKeyMatch?> ResolveKeyAsync(string keyValue, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(keyValue);

        var presented = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(keyValue));
        CallerKeyMatch? match = null;

        // One snapshot for the whole loop: the provider swaps Current atomically on
        // rebind, so reading it twice would let a reload between the reads make a caller
        // id enumerated from the old registry throw KeyNotFoundException against the new
        // one — a transient 500 on an unrelated caller's request.
        var registry = registryProvider.Current;

        // Visit every key of every caller: FixedTimeEquals per entry, no early exit, so
        // the loop's duration depends on the size of the key set, never on the value.
        foreach (var callerId in registry.CallerIds)
        {
            var caller = registry.Get(callerId);
            foreach (var key in caller.Keys)
            {
                var equals = CryptographicOperations.FixedTimeEquals(presented, key.Hash);
                if (equals && match is null)
                {
                    var expired = key.ExpiresAt is { } at && timeProvider.GetUtcNow() >= at;
                    if (!expired)
                    {
                        match = new CallerKeyMatch(new CallerIdentity(caller.CallerId, key.KeyId));
                    }
                }
            }

            cancellationToken.ThrowIfCancellationRequested();
        }

        CryptographicOperations.ZeroMemory(presented);
        return new(match);
    }
}
