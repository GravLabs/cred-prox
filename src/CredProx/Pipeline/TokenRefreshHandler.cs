using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http;
using CredProx.Abstractions;

namespace CredProx;

/// <summary>
/// Refresh-on-401 as an outbound <see cref="DelegatingHandler"/> (see
/// <c>docs/credprox-plan.md</c> §3.4): on a 401 the cached token is invalidated, a fresh one
/// is obtained, and the request is sent once more. A second 401 is returned to the caller —
/// never a loop. Idempotent methods retry by default; non-idempotent ones only when
/// <see cref="RefreshOn401Options.RetryNonIdempotent"/> is enabled and the body fits the
/// buffer limit — a body of unknown length (streamed, unbuffered) is never retried and
/// never buffered.
/// </summary>
/// <remarks>
/// <para>
/// Two composition modes. The fixed constructor owns the credential: it acquires and
/// attaches before the first send (standalone use). The resolver constructor is for the
/// per-cluster composition in <c>CredProxForwarderHttpClientFactory</c>: the credential
/// attach feature has already acquired and attached, the handler only resolves the
/// <see cref="TokenRefreshTargets"/> from each request to act on a 401, and requests
/// without targets pass through untouched.
/// </para>
/// <para>
/// The retried clone re-applies <c>Version</c>, <c>VersionPolicy</c> and the message
/// <c>Options</c> (preserving each option key's value type), so a retry behaves like the
/// original on the wire and downstream handlers still see their options.
/// </para>
/// </remarks>
[Experimental("CREDPROX001")]
public sealed class TokenRefreshHandler : DelegatingHandler
{
    private readonly Func<HttpRequestMessage, TokenRefreshTargets?> _resolveTargets;
    private readonly bool _acquireOnSend;
    private readonly RefreshOn401Options _options;

    /// <summary>
    /// Creates the handler over one credential's fixed acquire/invalidate/attach steps; the
    /// handler acquires and attaches before the first send.
    /// </summary>
    /// <param name="acquire">Obtains the current credential value (typically through the token cache).</param>
    /// <param name="invalidate">Drops the cached value so the next acquire refetches.</param>
    /// <param name="attach">Places a value on a request message.</param>
    /// <param name="options">Retry policy.</param>
    public TokenRefreshHandler(
        Func<CancellationToken, ValueTask<string>> acquire,
        Action invalidate,
        Action<HttpRequestMessage, string> attach,
        RefreshOn401Options options)
    {
        var targets = new TokenRefreshTargets(acquire, invalidate, attach);
        _resolveTargets = _ => targets;
        _acquireOnSend = true;
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <summary>
    /// Creates the handler for per-cluster composition: the credential was already acquired
    /// and attached upstream of this handler, and each request carries its own
    /// <see cref="TokenRefreshTargets"/> as resolved by <paramref name="targetResolver"/>.
    /// A request without targets is sent through untouched.
    /// </summary>
    /// <param name="targetResolver">Resolves the per-request targets, or <see langword="null"/>.</param>
    /// <param name="options">Retry policy.</param>
    public TokenRefreshHandler(
        Func<HttpRequestMessage, TokenRefreshTargets?> targetResolver,
        RefreshOn401Options options)
    {
        _resolveTargets = targetResolver ?? throw new ArgumentNullException(nameof(targetResolver));
        _acquireOnSend = false;
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var targets = _resolveTargets(request);
        if (targets is null)
        {
            return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }

        if (_acquireOnSend)
        {
            var initial = await targets.Acquire(cancellationToken).ConfigureAwait(false);
            targets.Attach(request, initial);
        }

        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.Unauthorized || !ShouldRetry(request))
        {
            return response;
        }

        byte[]? body = null;
        if (request.Content is { } content)
        {
            // An unknown length means a streamed, unbuffered body: never retried (§5.2)
            // and never buffered — a 401-triggered POST must not amplify an
            // attacker-sized stream into memory. A known length over the cap is likewise
            // refused before reading.
            if (content.Headers.ContentLength is null ||
                content.Headers.ContentLength > _options.MaxRetriedBodyBytes)
            {
                return response;
            }

            // The declared length can lie; the actual size is checked again after reading.
            body = await content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
            if (body.LongLength > _options.MaxRetriedBodyBytes)
            {
                return response;
            }
        }

        targets.Invalidate();
        string fresh;
        try
        {
            fresh = await targets.Acquire(cancellationToken).ConfigureAwait(false);
        }
        catch (ConsentRequiredException)
        {
            // Consent is an interactive step, not a transient failure (§8.3): a retry
            // cannot help, and letting this escape would turn the upstream 401 into a 500
            // on the proxy path. The caller receives the upstream's own 401 — the same
            // answer a second 401 gets.
            return response;
        }
        catch
        {
            response.Dispose(); // any other failure discards the response, as before
            throw;
        }

        response.Dispose();

        var retry = ProxyRequestCloner.Clone(request, body);
        targets.Attach(retry, fresh);
        return await base.SendAsync(retry, cancellationToken).ConfigureAwait(false);
    }

    private bool ShouldRetry(HttpRequestMessage request) =>
        IsIdempotent(request.Method) || _options.RetryNonIdempotent;

    private static bool IsIdempotent(HttpMethod method) =>
        HttpMethod.Get.Equals(method) ||
        HttpMethod.Head.Equals(method) ||
        HttpMethod.Options.Equals(method) ||
        HttpMethod.Trace.Equals(method);
}
