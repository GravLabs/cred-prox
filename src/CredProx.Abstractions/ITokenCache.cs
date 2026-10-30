using System.Diagnostics.CodeAnalysis;

namespace CredProx.Abstractions;

/// <summary>
/// Caches tokens keyed by <c>(credential, partition)</c>. The built-in implementation is
/// single-flight per key (concurrent requests share one fetch), refreshes before expiry,
/// caches failures only for a short negative TTL, and is safe to use as the backend for
/// refresh-on-401 via <see cref="Invalidate"/>.
/// </summary>
[Experimental("CREDPROX001")]
public interface ITokenCache
{
    /// <summary>
    /// Returns a cached token for <c>(credential, partition)</c>, or calls
    /// <paramref name="acquire"/> exactly once — even under concurrent requests — and
    /// caches the result until it expires.
    /// </summary>
    /// <param name="credential">The credential name from configuration.</param>
    /// <param name="partition">The partition value, or <see langword="null"/> for unpartitioned credentials.</param>
    /// <param name="acquire">
    /// Fetches a fresh token. Returns the token value and its absolute expiry. Called at
    /// most once per concurrent batch; cancellation of one waiter does not cancel the
    /// shared fetch.
    /// </param>
    /// <param name="cancellationToken">Cancels waiting for the token.</param>
    ValueTask<string> GetTokenAsync(
        string credential,
        string? partition,
        Func<CancellationToken, ValueTask<(string Value, DateTimeOffset ExpiresAt)>> acquire,
        CancellationToken cancellationToken);

    /// <summary>
    /// Drops the cached token for <c>(credential, partition)</c>, for example after the
    /// upstream rejected it with a 401, so the next request refetches.
    /// </summary>
    /// <param name="credential">The credential name from configuration.</param>
    /// <param name="partition">The partition value, or <see langword="null"/> for unpartitioned credentials.</param>
    void Invalidate(string credential, string? partition);
}
