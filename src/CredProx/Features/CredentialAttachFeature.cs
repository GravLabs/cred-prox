using System.Diagnostics.CodeAnalysis;
using System.Net.Http;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Yarp.ReverseProxy.Model;

namespace CredProx;

/// <summary>
/// The per-request stash key under which the attach feature leaves the
/// <see cref="TokenRefreshTargets"/> for the cluster's
/// <see cref="TokenRefreshHandler"/>. Internal: the factory and the feature are the only
/// parties in the contract.
/// </summary>
internal static class CredProxRequestOptions
{
    public static readonly HttpRequestOptionsKey<TokenRefreshTargets> TokenRefresh =
        new("CredProx.TokenRefreshTargets");

    /// <summary>
    /// The per-request <see cref="CredProxRequestState"/>, stashed by the transform
    /// provider so the response dispatcher at the end of the outbound pipeline reaches
    /// this request's features (M20, plan §8.2).
    /// </summary>
    public static readonly HttpRequestOptionsKey<CredProxRequestState> RequestState =
        new("CredProx.RequestState");
}

/// <summary>
/// The built-in <see cref="Stage.AttachCredential"/> feature
/// (see <c>docs/credprox-plan.md</c> §3.2/§3.4): resolves the route's
/// <c>CredProx.Credential</c> binding, admits the partition (the credential's own
/// allow-list gates its endpoint, secrets and cache key; otherwise the destination's
/// admitted value is reused), obtains the value through the token cache, and attaches it
/// to the outbound request — replacing, never merging, a caller-supplied
/// <c>Authorization</c>. A credential that cannot be obtained answers
/// <c>502 credprox.credential_unavailable</c> and the request is not forwarded.
/// </summary>
/// <remarks>
/// On success the acquire/invalidate/attach triple is stashed on the outbound message so
/// the cluster-level refresh-on-401 handler can act on a 401 without knowing credentials.
/// </remarks>
[Experimental("CREDPROX001")]
public sealed class CredentialAttachFeature : IRequestFeature
{
    private readonly CredentialRegistryProvider _registryProvider;
    private readonly ITokenCache _cache;
    private readonly ILogger<CredentialAttachFeature> _logger;

    /// <summary>Creates the feature.</summary>
    /// <param name="registryProvider">The reload-aware credential registry.</param>
    /// <param name="cache">The token cache the invalidate step drops keys from.</param>
    /// <param name="logger">Logs acquisition failures (messages never contain values).</param>
    public CredentialAttachFeature(
        CredentialRegistryProvider registryProvider,
        ITokenCache cache,
        ILogger<CredentialAttachFeature> logger)
    {
        _registryProvider = registryProvider ?? throw new ArgumentNullException(nameof(registryProvider));
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public Stage Stage => Stage.AttachCredential;

    /// <inheritdoc />
    public async ValueTask ApplyAsync(HttpContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.Features.Get<CredProxRequestState>() is not { } state)
        {
            return;
        }

        if (CredProxMetadata.GetRouteMetadata(context) is not { } metadata
            || !metadata.TryGetValue(CredProxMetadata.Credential, out var name)
            || string.IsNullOrEmpty(name))
        {
            return; // route attaches no credential
        }

        var binding = _registryProvider.Current.Get(name);

        var partition = state.Partition;
        if (binding.PartitionSource is { } partitionSource)
        {
            try
            {
                partition = await partitionSource.ResolveAsync(context, cancellationToken).ConfigureAwait(false);
            }
            catch (PartitionNotAllowedException ex)
            {
                await state
                    .AbortAsync(ex.StatusCode, ex.Code, ex.Title)
                    .ConfigureAwait(false);
                return;
            }

            state.Partition = partition;
        }

        // Delegated credentials (§3.6): the inbound bearer token rides the context, but
        // only to options that declare the need (secret scoping, §3.5 rule 4). No token on
        // the request is the caller's problem — 401 before the provider or the IdP runs.
        string? inboundToken = null;
        if (binding.Options is IRequiresInboundToken)
        {
            inboundToken = TryReadBearerToken(context);
            if (inboundToken is null)
            {
                await state
                    .AbortAsync(StatusCodes.Status401Unauthorized, "credprox.inbound_token_missing",
                        "This route requires an inbound bearer token.")
                    .ConfigureAwait(false);
                return;
            }
        }

        var credentialContext = new CredentialRequestContext
        {
            CredentialName = name,
            Partition = partition,
            InboundToken = inboundToken,
        };

        string value;
        try
        {
            value = await binding.GetCredential(credentialContext, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (ConsentRequiredException ex)
        {
            // The user has not authorized this application yet — a precise 401 with the
            // consent entry point, not the generic 502 (§8.3). The URL reaches the body
            // only when it is safe to hand to a browser; the problem lands either way,
            // and the exception message never does (§3.4).
            var authorizeUrl = SanitizeAuthorizeUrl(ex.AuthorizeUrl);
            if (authorizeUrl is null)
            {
                _logger.LogWarning(
                    "The credential '{Credential}' requires user consent, but the provider's authorize URL is not an absolute http(s) URL without credentials; the response omits it.",
                    name);

                await state
                    .AbortAsync(StatusCodes.Status401Unauthorized, "credprox.consent_required",
                        "The user has not yet authorized this application.")
                    .ConfigureAwait(false);
            }
            else
            {
                _logger.LogWarning(
                    "The credential '{Credential}' requires user consent.", name);

                await state
                    .AbortAsync(StatusCodes.Status401Unauthorized, "credprox.consent_required",
                        "The user has not yet authorized this application.",
                        new Dictionary<string, object?> { ["authorize_url"] = authorizeUrl })
                    .ConfigureAwait(false);
            }

            return;
        }
        catch (InboundTokenRejectedException ex)
        {
            // The caller's token failed validation — 401, not the generic 502 (§3.4/§3.6).
            // The message names the credential and the failure kind, never the token.
            _logger.LogWarning(
                "The inbound token for credential '{Credential}' was rejected: {Reason}",
                name, ex.Reason);

            await state
                .AbortAsync(StatusCodes.Status401Unauthorized, "credprox.inbound_token_invalid",
                    $"The inbound token was rejected ({ex.Reason}).")
                .ConfigureAwait(false);
            return;
        }
        catch (Exception ex)
        {
            // Provider messages name the credential and the failure kind, never values;
            // the caller sees only the static problem response (§3.4).
            _logger.LogWarning(
                "The credential '{Credential}' could not be obtained for this request: {Error}",
                name, ex.Message);

            await state
                .AbortAsync(StatusCodes.Status502BadGateway, "credprox.credential_unavailable",
                    "The outbound credential could not be obtained.")
                .ConfigureAwait(false);
            return;
        }

        if (binding.Attach is not { } attach)
        {
            return; // signature-style credential: nothing to place on the request
        }

        try
        {
            // On the live pipeline YARP assembles RequestUri only after every transform
            // completes, so it is null while features run. A query placement needs the
            // final URI now; a RequestUri assigned during transforms survives YARP's
            // final assembly unchanged (host-proven by QueryPlacement_LivePipeline_*
            // below), so building it from the state's final parts is exact, not a guess.
            // Inside the try: a malformed prefix that survives startup validation must
            // answer the credential problem, not the catch-all 500 (M9 review nit).
            if (state.ProxyRequest.RequestUri is null
                && binding.Options is IHasAttachment { Location: CredentialLocation.Query })
            {
                state.ProxyRequest.RequestUri = BuildOutboundUri(state, context);
            }

            attach(state.ProxyRequest, value);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Placement failed (e.g. no URI could be built for a query credential); the
            // caller gets the static credential problem, not the catch-all 500 (§3.4).
            _logger.LogWarning(
                "The credential '{Credential}' could not be placed on the outbound request: {Error}",
                name, ex.Message);

            await state
                .AbortAsync(StatusCodes.Status502BadGateway, "credprox.credential_unavailable",
                    "The outbound credential could not be obtained.")
                .ConfigureAwait(false);
            return;
        }

        // M20 (§8.2): whatever just went on the wire is recorded for the response
        // scrubber — if the upstream reflects it back, the caller must not see it.
        var injected = CredProxInjectedSecrets.GetOrCreate(context);
        injected.Register(value);

        // A delegated provider records its effective cache partition (per-user, §3.6) on
        // the context; the 401 invalidation must drop that entry, not the plain one.
        var cachePartition = credentialContext.CachePartition ?? partition;
        state.ProxyRequest.Options.Set(
            CredProxRequestOptions.TokenRefresh,
            new TokenRefreshTargets(
                acquireToken => binding.GetCredential(credentialContext, acquireToken),
                invalidate: () => _cache.Invalidate(name, cachePartition),
                // The refresh-on-401 replacement goes on the wire too; a reflecting
                // response must not carry it either (M20).
                attach: (request, replacement) =>
                {
                    injected.Register(replacement);
                    attach(request, replacement);
                }));
    }

    /// <summary>
    /// M19 URL hygiene (§8.3): a provider-supplied authorize URL is surfaced to the caller
    /// only as an absolute http(s) URL without embedded credentials — a browser-safe entry
    /// point for the consent flow. Anything else (relative references, <c>javascript:</c>
    /// or other non-browser schemes, userinfo such as <c>https://user:***@idp/</c>) is
    /// dropped so a provider cannot smuggle credentials or script URLs into a response
    /// body; the consent problem itself is returned either way.
    /// </summary>
    private static string? SanitizeAuthorizeUrl(string authorizeUrl) =>
        Uri.TryCreate(authorizeUrl, UriKind.Absolute, out var uri)
        && uri.Scheme is "https" or "http"
        && string.IsNullOrEmpty(uri.UserInfo)
            ? authorizeUrl
            : null;

    /// <summary>
    /// Reads the inbound bearer token (scheme stripped). A present-but-non-Bearer
    /// <c>Authorization</c> header counts as no token: delegated routes take bearer
    /// credentials and nothing else (§3.6).
    /// </summary>
    private static string? TryReadBearerToken(HttpContext context)
    {
        var header = context.Request.Headers.Authorization.ToString();
        const string bearerPrefix = "Bearer ";
        return header.StartsWith(bearerPrefix, StringComparison.OrdinalIgnoreCase)
            && header[bearerPrefix.Length..].Trim() is { Length: > 0 } token
                ? token
                : null;
    }

    /// <summary>
    /// Rebuilds the outbound URI exactly as YARP would assemble it after the last
    /// transform: destination prefix (the admitted destination's, else the selected
    /// cluster destination's) + final path + final query, all carried on the state.
    /// <see langword="null"/> when no prefix is known — the placement then fails into
    /// the 502 path instead of a bare 500.
    /// </summary>
    private static Uri? BuildOutboundUri(CredProxRequestState state, HttpContext context)
    {
        var prefix = state.DestinationPrefix
            ?? context.Features.Get<IReverseProxyFeature>()?.ProxiedDestination?.Model?.Config?.Address;
        if (string.IsNullOrEmpty(prefix))
        {
            return null;
        }

        var path = state.OutboundPath ?? "/";
        var query = state.OutboundQuery ?? string.Empty;
        return new Uri(
            prefix.TrimEnd('/') + (path.StartsWith("/", StringComparison.Ordinal) ? path : "/" + path) + query,
            UriKind.Absolute);
    }
}
