using System.Net.Http;

namespace CredProx;

/// <summary>
/// Refuses a followed redirect on the <c>credprox-token</c> clients (M45 security finding
/// F-1): a mint must never believe the response of a host nobody configured. Registered
/// with the named-client configuration by <c>AddCredProxLoginExchange</c>, mirroring the
/// guard in the OAuth add-on — the packages are separate assemblies with no shared
/// internals, and either may register the client alone. The BCL rewrites the request's
/// <see cref="HttpRequestMessage.RequestUri"/> in place when it follows (measured on
/// net10; the same pins run on net8.0 in CI), so a URI change across the send is the
/// signal. A transport that performs the redirect itself over its own inner client
/// never rewrites the caller's request, so the guard also refuses any response that
/// stamps its effective request URI as another address (M45 security finding R-1).
/// Three terms are enforced: the in-place rewrite is refused; any 3xx on a credential
/// client is refused; a response with no stamp is accepted on that term alone — the
/// decision recorded 14:21Z on row qitem-20261119134802-1c0ffce3: every shipped
/// transport stamps, and refusing an absent stamp would break host test suites on a
/// patch release. Two evasion shapes are documented limits, not blocked behavior: a
/// transport that stamps the ORIGINAL configured request on another host's response,
/// and a transport that clears the stamp; both are host-supplied primary-handler
/// behavior beyond this handler's view. Internal — no new public surface. The refusal names no
/// URL and no body.
/// </summary>
internal sealed class CredProxRedirectGuard : DelegatingHandler
{
    /// <summary>True when the send ended at a different address than the one requested.</summary>
    internal static bool WasRedirected(HttpRequestMessage request, Uri? configured) =>
        configured is not null && request.RequestUri is { } effective && !effective.Equals(configured);

    /// <summary>True when the response stamps an effective request URI that differs
    /// from the configured address (scheme, host, port and path — a differing query
    /// is ordinary): the signal by which a transport that redirects over its own inner
    /// client admits where it ended. A transport that stamps the ORIGINAL configured
    /// request, or that clears the stamp, produces no such signal — documented limits
    /// of stamp detection (M45 security finding R-1). A response with no stamp is
    /// accepted on this term alone — the shipped transports always stamp, and absence
    /// is not worth breaking hosts on a patch; the 3xx refusal is a separate term and
    /// applies regardless.</summary>
    internal static bool EndsElsewhere(HttpResponseMessage response, Uri? configured) =>
        configured is not null
        && response.RequestMessage?.RequestUri is { } effective
        && !SameAddress(effective, configured);

    private static bool SameAddress(Uri a, Uri b) =>
        string.Equals(a.Scheme, b.Scheme, StringComparison.OrdinalIgnoreCase)
        && string.Equals(a.Host, b.Host, StringComparison.OrdinalIgnoreCase)
        && a.Port == b.Port
        && string.Equals(a.AbsolutePath, b.AbsolutePath, StringComparison.Ordinal);

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var configured = request.RequestUri;
        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (WasRedirected(request, configured) || EndsElsewhere(response, configured))
        {
            response.Dispose();
            throw new InvalidOperationException(
                "The credential endpoint redirected to another address; CredProx never follows "
                + "redirects for credential acquisition.");
        }

        return response;
    }
}
