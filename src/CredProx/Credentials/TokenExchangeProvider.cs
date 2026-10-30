using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using CredProx.Abstractions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace CredProx;

/// <summary>
/// The built-in <c>TokenExchange</c> provider (see <c>docs/credprox-plan.md</c> §3.6):
/// validates the caller's inbound user token (signature, issuer, audience, lifetime) through
/// OIDC discovery or an explicit JWKS, derives the user subject from the <em>validated</em>
/// claims, and exchanges the token at the configured endpoint — RFC 8693 or Entra
/// on-behalf-of shape. The exchanged token is cached per <c>(credential, partition +
/// subject)</c> (the combined value is recorded on the context so refresh-on-401 drops the
/// right per-user entry) and attached to the request; the inbound token is never cached,
/// logged, or forwarded.
/// </summary>
/// <remarks>
/// Validation runs on every request (the subject must be non-forgeable before it keys the
/// cache); the discovery/JWKS documents are fetched lazily and cached with key rotation,
/// the JwtBearer way. A rejected inbound token fails as
/// <see cref="InboundTokenRejectedException"/> (401); an exchange-endpoint failure fails as
/// <see cref="InvalidOperationException"/> (502, negative-cached). Messages never contain
/// token values or response bodies.
/// </remarks>
[Experimental("CREDPROX001")]
public sealed class TokenExchangeProvider : ICredentialProvider<TokenExchangeOptions>
{
    private const string Rfc8693Grant = "urn:ietf:params:oauth:grant-type:token-exchange";
    private const string EntraOboGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    private const string AccessTokenTokenType = "urn:ietf:params:oauth:token-type:access_token";

    private readonly ITokenCache _cache;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly TimeProvider _time;
    private readonly JsonWebTokenHandler _handler = new();

    // One configuration manager per Authority; each caches its discovery document and
    // refreshes on key rotation. Explicit-JwksUri mode fetches the set directly (the
    // IdentityModel library ships no JWKS ConfigurationManager retriever in 8.x).
    private readonly ConcurrentDictionary<string, IConfigurationManager<OpenIdConnectConfiguration>> _oidcConfigs = new();
    private readonly ConcurrentDictionary<string, CachedKeys> _directJwks = new();

    // Direct-JWKS refresh window; a key-not-found rejection also evicts the entry so the
    // next request refetches (rotation self-heals within one request).
    private static readonly TimeSpan JwksRefreshInterval = TimeSpan.FromMinutes(15);

    private sealed record CachedKeys(IList<SecurityKey> Keys, DateTimeOffset FetchedAt);

    /// <summary>Creates the provider.</summary>
    /// <param name="cache">The token cache; the delegated key is <c>(credential, partition + subject)</c>.</param>
    /// <param name="httpClientFactory">The factory for token-endpoint clients.</param>
    /// <param name="time">The time source for expiry and token-clock decisions.</param>
    public TokenExchangeProvider(
        ITokenCache cache,
        IHttpClientFactory httpClientFactory,
        TimeProvider time)
    {
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
        _time = time ?? throw new ArgumentNullException(nameof(time));
    }

    /// <inheritdoc />
    public string Type => "TokenExchange";

    /// <inheritdoc />
    public async ValueTask<string> GetCredentialAsync(
        TokenExchangeOptions options,
        ISecretAccessor secrets,
        CredentialRequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(secrets);
        ArgumentNullException.ThrowIfNull(context);

        // The core refuses the request before the provider when the options declare
        // IRequiresInboundToken and no token arrived; a null here is a wiring bug.
        var inbound = context.InboundToken
            ?? throw new InvalidOperationException(
                $"Credential '{context.CredentialName}' requires an inbound token the core did not deliver.");

        var subject = await ValidateAndGetSubjectAsync(options, secrets, context, inbound, cancellationToken)
            .ConfigureAwait(false);

        // Per-user cache key (§3.6): the subject is an identifier, not a secret; the raw
        // inbound token never enters the key. Record it so refresh-on-401 invalidates this
        // exact entry.
        var cachePartition = context.Partition is null
            ? "u:" + subject
            : "p:" + context.Partition + "|u:" + subject;
        context.CachePartition = cachePartition;

        return await _cache
            .GetTokenAsync(
                context.CredentialName,
                cachePartition,
                ct => ExchangeAsync(context.CredentialName, context.Partition, options, secrets, inbound, ct),
                cancellationToken)
            .ConfigureAwait(false);
    }

    private async ValueTask<string> ValidateAndGetSubjectAsync(
        TokenExchangeOptions options,
        ISecretAccessor secrets,
        CredentialRequestContext context,
        string inbound,
        CancellationToken cancellationToken)
    {
        var audience = await ExpandRequired(options.Audience!, context.Partition, secrets, cancellationToken)
            .ConfigureAwait(false);

        IEnumerable<SecurityKey>? signingKeys;
        string? issuer = options.Issuer;
        string? directJwksUri = null;
        if (!string.IsNullOrEmpty(options.Authority))
        {
            var authority = await ExpandRequired(options.Authority!, context.Partition, secrets, cancellationToken)
                .ConfigureAwait(false);
            var manager = _oidcConfigs.GetOrAdd(authority, static a =>
                new ConfigurationManager<OpenIdConnectConfiguration>(
                    a.TrimEnd('/') + "/.well-known/openid-configuration",
                    new OpenIdConnectConfigurationRetriever()));
            var oidc = await GetConfigurationAsync(manager, "authority", cancellationToken).ConfigureAwait(false);
            signingKeys = oidc.SigningKeys;
            issuer ??= oidc.Issuer;
        }
        else
        {
            directJwksUri = await ExpandRequired(options.JwksUri!, context.Partition, secrets, cancellationToken)
                .ConfigureAwait(false);
            signingKeys = await GetDirectKeysAsync(directJwksUri, options, forceRefresh: false, cancellationToken)
                .ConfigureAwait(false);
        }

        var parameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            RequireSignedTokens = true,
            ClockSkew = options.ClockSkew,
            IssuerSigningKeys = signingKeys,
        };

        var result = await _handler.ValidateTokenAsync(inbound, parameters).ConfigureAwait(false);
        if (!result.IsValid)
        {
            // A key-not-found in direct-JWKS mode is usually rotation: evict so the next
            // request refetches. The reported kind is still "signature" for this request.
            if (directJwksUri is not null && result.Exception is SecurityTokenSignatureKeyNotFoundException)
            {
                _directJwks.TryRemove(directJwksUri, out _);
            }

            // The kind only — never the token, its header, or its claims.
            var reason = MapReason(result.Exception);
            throw new InboundTokenRejectedException(
                reason,
                $"The inbound token for credential '{context.CredentialName}' failed validation ({reason}).");
        }

        var subject = result.ClaimsIdentity?.FindFirst(options.SubjectClaim)?.Value;
        if (string.IsNullOrEmpty(subject))
        {
            throw new InboundTokenRejectedException(
                "missing-subject",
                $"The inbound token for credential '{context.CredentialName}' carries no '{options.SubjectClaim}' claim.");
        }

        return subject;
    }

    private static string MapReason(Exception? exception) => exception switch
    {
        SecurityTokenExpiredException => "expired",
        SecurityTokenNotYetValidException => "not-yet-valid",
        // JsonWebTokenHandler reports lifetime failures as the base lifetime exception.
        SecurityTokenInvalidLifetimeException => "expired",
        SecurityTokenInvalidIssuerException => "issuer",
        SecurityTokenInvalidAudienceException => "audience",
        SecurityTokenSignatureKeyNotFoundException => "signature",
        SecurityTokenInvalidSignatureException => "signature",
        _ => "malformed",
    };

    private async ValueTask<IList<SecurityKey>> GetDirectKeysAsync(
        string jwksUri,
        TokenExchangeOptions options,
        bool forceRefresh,
        CancellationToken cancellationToken)
    {
        if (!forceRefresh
            && _directJwks.TryGetValue(jwksUri, out var cached)
            && _time.GetUtcNow() - cached.FetchedAt < JwksRefreshInterval)
        {
            return cached.Keys;
        }

        string json;
        try
        {
            var client = _httpClientFactory.CreateClient(CredProxHttpClientNames.ForConnection(options.Connection));
            json = await client.GetStringAsync(jwksUri, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new InvalidOperationException(
                $"The token-exchange JWKS '{jwksUri}' could not be retrieved: {ex.Message}", ex);
        }

        IList<SecurityKey> keys;
        try
        {
            keys = JsonWebKeySet.Create(json).Keys.Select(static key => (SecurityKey)key).ToList();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new InvalidOperationException(
                $"The token-exchange JWKS '{jwksUri}' is malformed.", ex);
        }

        _directJwks[jwksUri] = new CachedKeys(keys, _time.GetUtcNow());
        return keys;
    }

    private async ValueTask<(string Value, DateTimeOffset ExpiresAt)> ExchangeAsync(
        string credentialName,
        string? partition,
        TokenExchangeOptions options,
        ISecretAccessor secrets,
        string inbound,
        CancellationToken cancellationToken)
    {
        var tokenEndpoint = await ResolveTokenEndpointAsync(options, partition, secrets, cancellationToken)
            .ConfigureAwait(false);

        var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint);
        var form = new List<KeyValuePair<string, string>>();

        if (options.Mode == TokenExchangeMode.EntraObo)
        {
            form.Add(new KeyValuePair<string, string>("grant_type", EntraOboGrant));
            form.Add(new KeyValuePair<string, string>("assertion", inbound));
            form.Add(new KeyValuePair<string, string>("requested_token_use", "on_behalf_of"));
        }
        else
        {
            form.Add(new KeyValuePair<string, string>("grant_type", Rfc8693Grant));
            form.Add(new KeyValuePair<string, string>("subject_token", inbound));
            form.Add(new KeyValuePair<string, string>(
                "subject_token_type", options.SubjectTokenType ?? AccessTokenTokenType));

            if (!string.IsNullOrEmpty(options.RequestedTokenType))
            {
                form.Add(new KeyValuePair<string, string>("requested_token_type", options.RequestedTokenType));
            }

            if (!string.IsNullOrEmpty(options.IssuedTokenType))
            {
                form.Add(new KeyValuePair<string, string>("issued_token_type", options.IssuedTokenType));
            }

            if (options.RequestedAudience is { Length: > 0 })
            {
                var requestedAudience = await ExpandRequired(options.RequestedAudience, partition, secrets, cancellationToken)
                    .ConfigureAwait(false);
                // RFC 8693 §2.1 names this parameter `audience` (Keycloak rejects `aud`).
                form.Add(new KeyValuePair<string, string>("audience", requestedAudience));
            }

            if (!string.IsNullOrEmpty(options.Act))
            {
                form.Add(new KeyValuePair<string, string>("act", options.Act));
            }
        }

        if (options.Scope is { Length: > 0 })
        {
            var scope = await ExpandRequired(options.Scope, partition, secrets, cancellationToken).ConfigureAwait(false);
            form.Add(new KeyValuePair<string, string>("scope", scope));
        }

        var clientId = await ExpandRequired(options.ClientId!, partition, secrets, cancellationToken).ConfigureAwait(false);
        var clientSecret = await Expand(options.ClientSecret, partition, secrets, cancellationToken)
            .ConfigureAwait(false);

        if (options.ClientAuthentication == OAuthClientAuthentication.BasicHeader)
        {
            var pair = Encoding.UTF8.GetBytes($"{clientId}:{clientSecret}");
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(pair));
        }
        else
        {
            if (clientId is not null)
            {
                form.Add(new KeyValuePair<string, string>("client_id", clientId));
            }

            if (clientSecret is not null)
            {
                form.Add(new KeyValuePair<string, string>("client_secret", clientSecret));
            }
        }

        request.Content = new FormUrlEncodedContent(form);

        var client = _httpClientFactory.CreateClient(CredProxHttpClientNames.ForConnection(options.Connection));
        using var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            // The IdP error body may echo request fragments (including the assertion);
            // never include it. The kind of failure is the status code alone.
            throw new InvalidOperationException(
                $"The token-exchange endpoint for credential '{credentialName}' failed with HTTP {(int)response.StatusCode}.");
        }

        var json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        string accessToken;
        TimeSpan lifetime;
        try
        {
            using var document = JsonDocument.Parse(json);
            accessToken = ReadRequiredString(document.RootElement, options.TokenField);

            lifetime = options.DefaultLifetime;
            if (options.ExpiresInField is not null &&
                document.RootElement.TryGetProperty(options.ExpiresInField, out var expiresIn))
            {
                lifetime = ReadLifetime(expiresIn, options.DefaultLifetime);
            }
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException or OverflowException)
        {
            throw new InvalidOperationException(
                $"The token-exchange endpoint for credential '{credentialName}' returned a malformed token response.", ex);
        }

        return (accessToken, _time.GetUtcNow() + lifetime);
    }

    private async ValueTask<string> ResolveTokenEndpointAsync(
        TokenExchangeOptions options,
        string? partition,
        ISecretAccessor secrets,
        CancellationToken cancellationToken)
    {
        if (!string.IsNullOrEmpty(options.TokenEndpoint))
        {
            return await ExpandRequired(options.TokenEndpoint, partition, secrets, cancellationToken).ConfigureAwait(false);
        }

        // Authority mode: the discovered token_endpoint.
        var authority = await ExpandRequired(options.Authority!, partition, secrets, cancellationToken)
            .ConfigureAwait(false);
        var manager = _oidcConfigs.GetOrAdd(authority, static a =>
            new ConfigurationManager<OpenIdConnectConfiguration>(
                a.TrimEnd('/') + "/.well-known/openid-configuration",
                new OpenIdConnectConfigurationRetriever()));
        var oidc = await GetConfigurationAsync(manager, "authority", cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrEmpty(oidc.TokenEndpoint))
        {
            throw new InvalidOperationException(
                "The authority's discovery document carries no token_endpoint; set TokenEndpoint explicitly.");
        }

        return oidc.TokenEndpoint;
    }

    private static async ValueTask<T> GetConfigurationAsync<T>(
        IConfigurationManager<T> manager, string what, CancellationToken cancellationToken)
        where T : class
    {
        try
        {
            return await manager.GetConfigurationAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Unreachable/malformed IdP metadata is a credential failure (502), not a
            // caller rejection; the message names the source, never a token.
            throw new InvalidOperationException($"The token-exchange {what} could not be retrieved: {ex.Message}", ex);
        }
    }

    private static async ValueTask<string?> Expand(
        string? template,
        string? partition,
        ISecretAccessor secrets,
        CancellationToken cancellationToken)
        => template is null
            ? null
            : await TemplateExpander.ExpandAsync(template, partition, secrets, cancellationToken).ConfigureAwait(false);

    // For fields the startup validator guarantees non-empty; the expander itself never
    // returns null for a non-null template.
    private static async ValueTask<string> ExpandRequired(
        string template,
        string? partition,
        ISecretAccessor secrets,
        CancellationToken cancellationToken)
        => await TemplateExpander.ExpandAsync(template, partition, secrets, cancellationToken).ConfigureAwait(false);

    private static string ReadRequiredString(JsonElement root, string property)
    {
        if (!root.TryGetProperty(property, out var element) ||
            element.ValueKind != JsonValueKind.String ||
            element.GetString() is not { Length: > 0 } value)
        {
            throw new InvalidOperationException($"The token response is missing the '{property}' value.");
        }

        return value;
    }

    private static TimeSpan ReadLifetime(JsonElement expiresIn, TimeSpan defaultLifetime)
    {
        var seconds = expiresIn.ValueKind switch
        {
            JsonValueKind.Number => expiresIn.GetDouble(),
            JsonValueKind.String when double.TryParse(expiresIn.GetString(), out var parsed) => parsed,
            _ => double.NaN,
        };

        return double.IsFinite(seconds) && seconds > 0
            ? TimeSpan.FromSeconds(seconds)
            : defaultLifetime;
    }
}
