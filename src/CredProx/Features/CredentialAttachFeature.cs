using System.Diagnostics.CodeAnalysis;
using System.Net.Http;
using System.Reflection;
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
    /// this request's features.
    /// </summary>
    public static readonly HttpRequestOptionsKey<CredProxRequestState> RequestState =
        new("CredProx.RequestState");
}

/// <summary>
/// The built-in <see cref="Stage.AttachCredential"/> feature
/// : resolves the route's
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
            var authorizeUrl = SanitizeAuthorizeUrl(context, binding.Options, ex.AuthorizeUrl, out var secretParams);
            if (authorizeUrl is null)
            {
                if (secretParams is { Length: > 0 })
                {
                    // M47 F-9: the operator hears what carried a secret — escaped
                    // parameter names (or the path/fragment marker), never values.
                    _logger.LogWarning(
                        "The credential '{Credential}' requires user consent, but the provider's authorize URL carries secret-bearing content ('{SecretBearing}'); the response omits the URL.",
                        name, secretParams);
                }
                else
                {
                    _logger.LogWarning(
                        "The credential '{Credential}' requires user consent, but the provider's authorize URL is not an absolute http(s) URL without credentials; the response omits it.",
                        name);
                }

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
            // M45 security finding F-5: a provider here may be a third party, and its
            // message is its own — the log names the exception type, not the text; the
            // caller sees only the static problem response (§3.4).
            _logger.LogWarning(
                "The credential '{Credential}' could not be obtained for this request ({ErrorType}).",
                name, ex.GetType().Name);

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
            // answer the credential problem, not the catch-all 500.
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
            // M45 security finding F-5: type, not text.
            _logger.LogWarning(
                "The credential '{Credential}' could not be placed on the outbound request ({ErrorType}).",
                name, ex.GetType().Name);

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
    /// URL hygiene: a provider-supplied authorize URL is surfaced to the caller
    /// only as an absolute http(s) URL without embedded credentials — a browser-safe entry
    /// point for the consent flow. Anything else (relative references, <c>javascript:</c>
    /// or other non-browser schemes, userinfo such as <c>https://user:***@idp/</c>) is
    /// dropped so a provider cannot smuggle credentials or script URLs into a response
    /// body; the consent problem itself is returned either way.
    /// M45 finding F-9 (widened in M47): the whole URL — path, query and fragment — is
    /// scanned, raw and percent-decoded (with '+' read as a space, both directions), for
    /// two value sources: secrets this pipeline already injected for the request, and
    /// the credential's OWN configured secret members (on a first-attempt consent the
    /// injected registry is still empty, so the configured values are what the check can
    /// know — see <see cref="CollectConfiguredSecrets"/>; that member match is BY NAME
    /// over arbitrary plugin option shapes and its honest limit — only custom providers
    /// reach the consent path — is stated there). Independently, a top-level
    /// query or fragment parameter NAME containing <c>secret</c>, <c>assertion</c> or
    /// <c>password</c> (case-insensitive), or named exactly <c>access_token</c> or
    /// <c>refresh_token</c>, marks a leak whatever its value — while a URL that merely
    /// contains those words in a path or inside another parameter's value relays,
    /// because over-refusal breaks sign-in. ';' separates parameters as well as '&amp;'.
    /// <paramref name="secretBearingParameters"/> comes back with the offending markers
    /// on a secret drop — percent-escaped names, or <c>path-or-fragment</c> when the
    /// value sat outside any parameter value, in the path, the fragment, or a parameter
    /// name — never values. A secret sitting inside a parameter NAME of an otherwise
    /// parseable query also lands under this marker: the per-pair arms read values,
    /// so the whole-URL containment is what catches it.
    /// </summary>
    private static string? SanitizeAuthorizeUrl(
        HttpContext context,
        object options,
        string authorizeUrl,
        out string? secretBearingParameters)
    {
        secretBearingParameters = null;
        if (!Uri.TryCreate(authorizeUrl, UriKind.Absolute, out var uri)
            || uri.Scheme is not ("https" or "http")
            || !string.IsNullOrEmpty(uri.UserInfo))
        {
            return null; // the browser-safety drop, unchanged
        }

        var injected = CredProxInjectedSecrets.GetOrCreate(context);
        var values = new List<string>(injected.Values);
        values.AddRange(CollectConfiguredSecrets(options));

        List<string>? flagged = null;

        void ScanParameters(string parameterString)
        {
            foreach (var pair in parameterString.Split(['&', ';'], StringSplitOptions.RemoveEmptyEntries))
            {
                var equals = pair.IndexOf('=');
                var rawName = equals < 0 ? pair : pair[..equals];
                var rawValue = equals < 0 ? string.Empty : pair[(equals + 1)..];
                var name = Uri.UnescapeDataString(rawName.Replace('+', ' '));
                // The per-parameter percent-decode is the ATTRIBUTION arm: a value that
                // carries the secret only once decoded is named in the log by its own
                // parameter. The whole-URL fallback after the scan is the leak guard —
                // the same URL is dropped even if this arm never fires — so removing the
                // decode here would degrade the operator's log to 'path-or-fragment',
                // not widen a leak. Deliberate; pinned by
                // ConsentProblem_LogsTheParameterName_WhenOnlyTheDecodedValueCarriesTheSecret.
                var value = Uri.UnescapeDataString(rawValue.Replace('+', ' '));

                var carriesSecret = NameMarksSecret(name);
                if (!carriesSecret && values.Count > 0)
                {
                    carriesSecret = values.Any(known =>
                        rawValue.Contains(known, StringComparison.Ordinal)
                        || value.Contains(known, StringComparison.Ordinal));
                }

                if (carriesSecret)
                {
                    // The name is provider-chosen text: it may only reach the log escaped.
                    (flagged ??= []).Add(Uri.EscapeDataString(name));
                }
            }
        }

        if (uri.Query.Length > 1)
        {
            ScanParameters(uri.Query[1..]);
        }

        if (uri.Fragment.Length > 1)
        {
            ScanParameters(uri.Fragment[1..]);
        }

        if (flagged is null && values.Count > 0)
        {
            // A secret in the path — or anywhere the parameter scan cannot reach — is
            // the same leak; the whole string is the value's scope.
            var decodedUrl = Uri.UnescapeDataString(authorizeUrl.Replace('+', ' '));
            if (values.Any(known =>
                    authorizeUrl.Contains(known, StringComparison.Ordinal)
                    || decodedUrl.Contains(known, StringComparison.Ordinal)))
            {
                flagged = ["path-or-fragment"];
            }
        }

        if (flagged is not null)
        {
            secretBearingParameters = string.Join(", ", flagged);
            return null;
        }

        return authorizeUrl;
    }

    /// <summary>
    /// A parameter name is a leak marker by containment of the secret words the
    /// credential providers send on the wire (<c>secret</c>, <c>assertion</c>,
    /// <c>password</c>) or by exact name for the token names that live in URLs
    /// (<c>access_token</c>, <c>refresh_token</c>). A bare <c>token</c> is NOT a marker:
    /// OIDC legitimately carries <c>id_token_hint</c> and opaque token values through
    /// authorize URLs.
    /// </summary>
    private static bool NameMarksSecret(string decodedName) =>
        decodedName.Contains("secret", StringComparison.OrdinalIgnoreCase)
        || decodedName.Contains("assertion", StringComparison.OrdinalIgnoreCase)
        || decodedName.Contains("password", StringComparison.OrdinalIgnoreCase)
        || decodedName.Equals("access_token", StringComparison.OrdinalIgnoreCase)
        || decodedName.Equals("refresh_token", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The option member names that hold a credential's own secret, across the built-in
    /// credential types: <c>ClientSecret</c> (OAuth client credentials, token exchange),
    /// <c>SigningKey</c> (JWT assertion, signing material held as a string),
    /// <c>Password</c> (login exchange, nested one level in its user/password members),
    /// <c>Secret</c> (static key, HMAC). Membership is BY NAME: <c>client_id</c> is
    /// public and never a member, and the raw configuration subtree is never walked —
    /// only readable string members of the bound options carry a value here. A member
    /// held as a <c>secret:</c> reference or template is matched in that configured form
    /// only; the guard never resolves references (the provider's own accessor is the
    /// resolver, and reaching it here would mean registering the value — see
    /// <see cref="SanitizeAuthorizeUrl"/>). The consent path is reached only by a
    /// custom credential provider raising <see cref="ConsentRequiredException"/> — the
    /// plugin contract; no built-in provider throws it — so this name list is
    /// best-effort over plugin option shapes: a plugin that names its member otherwise
    /// (<c>ApiKey</c>, <c>Token</c>, <c>ClientAssertion</c>) is NOT matched here. The
    /// parameter-NAME rule in <see cref="NameMarksSecret"/> is the general guard, and a
    /// plugin must never put its secret into an authorize URL.
    /// Empty and whitespace-only members are SKIPPED: a whitespace member is no real
    /// configured secret, and containment on it fires only where the URL carries the
    /// SAME run of whitespace (measured — a registered "   " relays a value holding one
    /// space and refuses a padded run). The skip remains a deliberate divergence from
    /// the scrubber, which would register a whitespace-only value and scrub it. Value LENGTH is at parity instead: the scrubber has no
    /// minimum length, so this list has none either — a configured two-character secret
    /// can contain-match and refuse an ordinary consent URL, which is intended
    /// fail-closed behaviour and operator-visible because the refusal warning names the
    /// credential. The two rules are deliberately asymmetric; do not normalise them.
    /// </summary>
    private static List<string> CollectConfiguredSecrets(object options)
    {
        var secrets = new List<string>();
        foreach (var member in ReadSecretMembers(options))
        {
            secrets.Add(member);
        }

        return secrets;
    }

    private static IEnumerable<string> ReadSecretMembers(object options)
    {
        foreach (var property in options.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            object? value;
            try
            {
                value = property.GetValue(options);
            }
            catch (TargetInvocationException)
            {
                continue; // an options getter that throws is not a secret source
            }

            if (IsSecretNamedMember(property.Name, value))
            {
                yield return (string)value!;
            }
            else if (value is not null and not string)
            {
                // One level deep, by name: the login options nest their password.
                foreach (var inner in value.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance))
                {
                    object? innerValue;
                    try
                    {
                        innerValue = inner.GetValue(value);
                    }
                    catch (TargetInvocationException)
                    {
                        continue;
                    }

                    if (IsSecretNamedMember(inner.Name, innerValue))
                    {
                        yield return (string)innerValue!;
                    }
                }
            }
        }
    }

    private static bool IsSecretNamedMember(string memberName, object? value) =>
        value is string secret
        && !string.IsNullOrWhiteSpace(secret)
        && memberName is "ClientSecret" or "SigningKey" or "Secret" or "Password";

    /// <summary>
    /// Reads the inbound bearer token (scheme stripped). A present-but-non-Bearer
    /// <c>Authorization</c> header counts as no token: delegated routes take bearer
    /// credentials and nothing else.
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
