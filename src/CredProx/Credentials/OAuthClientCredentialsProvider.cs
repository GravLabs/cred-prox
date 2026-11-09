using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using CredProx.Abstractions;
using Microsoft.Extensions.Logging;

namespace CredProx;

/// <summary>
/// The built-in <c>OAuthClientCredentials</c> provider (see <c>docs/credprox-plan.md</c> §4):
/// client credentials grant against the configured token endpoint, with Basic-header or
/// form-body client authentication, optional scope and audience, and the token cached per
/// <c>(credential, partition)</c> through <see cref="ITokenCache"/>. A non-2xx response or a
/// malformed token body fails as <see cref="InvalidOperationException"/> — the core turns
/// that into <c>credprox.credential_unavailable</c> (502) without forwarding. A negative
/// <c>expires_in</c> is treated the same way (protocol violation, nothing cached); an absent,
/// non-numeric or zero <c>expires_in</c> falls back to <see cref="OAuthClientCredentialsOptions.DefaultLifetime"/>
/// (zero logs one warning per credential). Error messages
/// never contain secret values or response bodies. <c>TokenEndpoint</c>, <c>ClientId</c>
/// and <c>ClientSecret</c> accept the §3.2 template forms (<c>{partition}</c> and secret
/// references), so one credential can serve per-partition vendor accounts.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class OAuthClientCredentialsProvider : ICredentialProvider<OAuthClientCredentialsOptions>
{
    /// <summary>The name of the HttpClient used for token calls.</summary>
    public const string HttpClientName = "credprox-token";

    private readonly ITokenCache _cache;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly TimeProvider _time;
    private readonly ILogger<OAuthClientCredentialsProvider>? _logger;
    private readonly ConcurrentDictionary<string, byte> _zeroLifetimeLogged = new();

    /// <summary>Creates the provider.</summary>
    /// <param name="cache">The token cache keyed by <c>(credential, partition)</c>.</param>
    /// <param name="httpClientFactory">The factory for token-endpoint clients.</param>
    /// <param name="time">The time source for expiry decisions.</param>
    public OAuthClientCredentialsProvider(
        ITokenCache cache,
        IHttpClientFactory httpClientFactory,
        TimeProvider time)
        : this(cache, httpClientFactory, time, logger: null)
    {
    }

    /// <summary>Creates the provider with logging for the <c>expires_in: 0</c> fallback.</summary>
    /// <param name="cache">The token cache keyed by <c>(credential, partition)</c>.</param>
    /// <param name="httpClientFactory">The factory for token-endpoint clients.</param>
    /// <param name="time">The time source for expiry decisions.</param>
    /// <param name="logger">Logs the zero-lifetime fallback once per credential.</param>
    public OAuthClientCredentialsProvider(
        ITokenCache cache,
        IHttpClientFactory httpClientFactory,
        TimeProvider time,
        ILogger<OAuthClientCredentialsProvider>? logger)
    {
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
        _time = time ?? throw new ArgumentNullException(nameof(time));
        _logger = logger;
    }

    /// <inheritdoc />
    public string Type => "OAuthClientCredentials";

    /// <inheritdoc />
    public ValueTask<string> GetCredentialAsync(
        OAuthClientCredentialsOptions options,
        ISecretAccessor secrets,
        CredentialRequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(secrets);
        ArgumentNullException.ThrowIfNull(context);

        return _cache.GetTokenAsync(
            context.CredentialName,
            context.Partition,
            ct => FetchAsync(context.CredentialName, context.Partition, options, secrets, ct),
            cancellationToken);
    }

    private async ValueTask<(string Value, DateTimeOffset ExpiresAt)> FetchAsync(
        string credentialName,
        string? partition,
        OAuthClientCredentialsOptions options,
        ISecretAccessor secrets,
        CancellationToken cancellationToken)
    {
        // The §3.2 template forms, same expansion as LoginExchange: {partition} first,
        // then secret references — so one credential can serve per-partition vendor
        // accounts (E7: two callers, two vendor accounts, one route). The cache key
        // already includes the partition, so each account's token caches separately.
        var tokenEndpoint = options.TokenEndpoint is null
            ? null
            : await TemplateExpander.ExpandAsync(options.TokenEndpoint, partition, secrets, cancellationToken)
                .ConfigureAwait(false);
        var clientId = options.ClientId is null
            ? null
            : await TemplateExpander.ExpandAsync(options.ClientId, partition, secrets, cancellationToken)
                .ConfigureAwait(false);
        var clientSecret = options.ClientSecret is null
            ? null
            : await TemplateExpander.ExpandAsync(options.ClientSecret, partition, secrets, cancellationToken)
                .ConfigureAwait(false);

        var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint);

        var form = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "client_credentials"),
        };

        if (!string.IsNullOrEmpty(options.Scope))
        {
            form.Add(new KeyValuePair<string, string>("scope", options.Scope));
        }

        if (!string.IsNullOrEmpty(options.Audience))
        {
            form.Add(new KeyValuePair<string, string>("audience", options.Audience));
        }

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
            throw new InvalidOperationException(
                $"The OAuth token endpoint for credential '{credentialName}' failed with HTTP {(int)response.StatusCode}.");
        }

        var json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        string accessToken;
        TimeSpan lifetime;
        try
        {
            using var document = JsonDocument.Parse(json);
            accessToken = ReadRequiredString(document.RootElement, "access_token");

            lifetime = options.DefaultLifetime;
            if (document.RootElement.TryGetProperty("expires_in", out var expiresIn))
            {
                lifetime = ReadLifetime(expiresIn, options.DefaultLifetime, credentialName, this);
            }
        }
        catch (Exception ex) when (ex is JsonException or FormatException or OverflowException
            or (InvalidOperationException and not NegativeExpiresInRejectedException))
        {
            // The body may echo request fragments; never include it in the error.
            throw new InvalidOperationException(
                $"The OAuth token endpoint for credential '{credentialName}' returned a malformed token response.", ex);
        }

        return (accessToken, _time.GetUtcNow() + lifetime);
    }

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

    private static TimeSpan ReadLifetime(
        JsonElement expiresIn,
        TimeSpan defaultLifetime,
        string credentialName,
        OAuthClientCredentialsProvider provider)
    {
        double? seconds = expiresIn.ValueKind switch
        {
            JsonValueKind.Number => expiresIn.GetDouble(),
            JsonValueKind.String when double.TryParse(expiresIn.GetString(), out var parsed) => parsed,
            _ => null,
        };

        if (seconds is double finite)
        {
            if (double.IsFinite(finite) && finite < 0)
            {
                // RFC 6749 defines expires_in as a lifetime in seconds: a negative value is a
                // protocol violation, and caching the token it stamps serves a guaranteed
                // vendor 401 (M33 fault 7, 0.9.0: it silently degraded to DefaultLifetime).
                // Reject the response through the documented IdP-failure path - callers get
                // credential_unavailable (502) and nothing is cached. The message names the
                // field and the credential id, never the value and never the token.
                throw new NegativeExpiresInRejectedException(
                    $"The OAuth token endpoint for credential '{credentialName}' returned a negative 'expires_in' value; the token response was rejected.");
            }

            if (finite == 0)
            {
                provider.LogZeroLifetime(credentialName);
            }
        }

        return seconds is double positive && double.IsFinite(positive) && positive > 0
            ? TimeSpan.FromSeconds(positive)
            : defaultLifetime;
    }

    private void LogZeroLifetime(string credentialName)
    {
        // Some IdPs send 0 to mean "no stated expiry" - serving DefaultLifetime is intended
        // (rejecting would break them), but the credential deserves one loud notice.
        if (_logger is null || !_zeroLifetimeLogged.TryAdd(credentialName, 0))
        {
            return;
        }

        _logger.LogWarning(
            "The OAuth token endpoint for credential '{Credential}' returned 'expires_in' 0; the token is cached for the configured DefaultLifetime.",
            credentialName);
    }

    /// <summary>
    /// Signals a token response rejected for a negative <c>expires_in</c>. Flows through the
    /// same IdP-failure path as any unusable response (<c>credprox.credential_unavailable</c>,
    /// nothing cached); kept distinct only so the malformed-body re-wrap below does not erase
    /// the field name from the warning.
    /// </summary>
    internal sealed class NegativeExpiresInRejectedException : InvalidOperationException
    {
        public NegativeExpiresInRejectedException(string message)
            : base(message)
        {
        }
    }
}
