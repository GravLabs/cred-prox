using System.Diagnostics.CodeAnalysis;
using System.Net.Http;

namespace CredProx;

/// <summary>
/// The per-request acquire/invalidate/attach triple a <see cref="TokenRefreshHandler"/>
/// acts on. The credential-attach request feature builds one and stashes it on the
/// outbound <see cref="HttpRequestMessage"/>; the cluster-level handler resolves it from
/// the message, so a shared cluster client can serve routes with different credentials.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class TokenRefreshTargets
{
    /// <summary>Creates the triple.</summary>
    /// <param name="acquire">Obtains the current credential value (typically through the token cache).</param>
    /// <param name="invalidate">Drops the cached value so the next acquire refetches.</param>
    /// <param name="attach">Places a value on a request message.</param>
    public TokenRefreshTargets(
        Func<CancellationToken, ValueTask<string>> acquire,
        Action invalidate,
        Action<HttpRequestMessage, string> attach)
    {
        Acquire = acquire ?? throw new ArgumentNullException(nameof(acquire));
        Invalidate = invalidate ?? throw new ArgumentNullException(nameof(invalidate));
        Attach = attach ?? throw new ArgumentNullException(nameof(attach));
    }

    /// <summary>Obtains the current credential value (typically through the token cache).</summary>
    public Func<CancellationToken, ValueTask<string>> Acquire { get; }

    /// <summary>Drops the cached value so the next acquire refetches.</summary>
    public Action Invalidate { get; }

    /// <summary>Places a value on a request message.</summary>
    public Action<HttpRequestMessage, string> Attach { get; }
}
