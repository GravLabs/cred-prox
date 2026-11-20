using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;

namespace CredProx.CallerKeys;

/// <summary>
/// The result of a successful key lookup: who the key belongs to. Deliberately carries no
/// key material and no hash — a store leak cannot reveal credentials.
/// </summary>
/// <param name="Identity">The authenticated caller and key.</param>
[Experimental("CREDPROX001")]
public sealed record CallerKeyMatch(CallerIdentity Identity);

/// <summary>
/// The caller-authentication plugin point: maps a
/// presented inbound API key value to a caller. The built-in store reads hashed keys from
/// the <c>CredProx:Callers</c> configuration section; third-party stores (databases,
/// identity providers) implement the same contract.
/// </summary>
/// <remarks>
/// Implementations must treat the presented key value as a secret: never log it, never
/// include it in exception messages, and compare it against stored material in constant
/// time.
/// </remarks>
[Experimental("CREDPROX001")]
public interface ICallerStore
{
    /// <summary>
    /// Resolves a presented key value to its caller, or <see langword="null"/> when the
    /// key is unknown, expired or revoked. The distinction between those three is
    /// intentionally not exposed: the caller learns only that authentication failed.
    /// </summary>
    /// <param name="keyValue">The raw inbound key value; treat as a secret.</param>
    /// <param name="cancellationToken">Cancels the lookup.</param>
    ValueTask<CallerKeyMatch?> ResolveKeyAsync(string keyValue, CancellationToken cancellationToken);
}
