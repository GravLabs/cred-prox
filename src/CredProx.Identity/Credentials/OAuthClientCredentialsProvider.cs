using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using CredProx.Abstractions;
using Microsoft.Extensions.Logging;

namespace CredProx;

/// <summary>
/// The built-in <c>OAuthClientCredentials</c> provider:
/// client credentials grant against the configured token endpoint, with Basic-header or
/// form-body client authentication, optional scope and audience, and the token cached per
/// <c>(credential, partition)</c> through <see cref="ITokenCache"/>. A non-2xx response or a
/// malformed token body fails as <see cref="InvalidOperationException"/> — the core turns
/// that into <c>credprox.credential_unavailable</c> (502) without forwarding. A negative
/// <c>expires_in</c>, a non-finite one (the names <c>Infinity</c>, <c>-Infinity</c>, <c>NaN</c>
/// in a string) or a thousands-grouped one are treated the same way (protocol
/// violations, nothing cached); an absent, non-numeric or zero <c>expires_in</c> falls back to
/// <see cref="OAuthClientCredentialsOptions.DefaultLifetime"/>
/// (zero logs one warning per credential). String <c>expires_in</c> parses with the canonical
/// JSON-number grammar (<see cref="NumberStyles.Float"/>, <see cref="CultureInfo.InvariantCulture"/>)
/// so the cached lifetime never depends on the machine's current culture. Error messages
/// never contain secret values or response bodies. <c>TokenEndpoint</c>, <c>ClientId</c>
/// and <c>ClientSecret</c> accept the template forms (<c>{partition}</c> and secret
/// references), so one credential can serve per-partition vendor accounts.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class OAuthClientCredentialsProvider : ICredentialProvider<OAuthClientCredentialsOptions>
{
    /// <summary>
    /// The name of the HttpClient used for token calls — the shared
    /// <see cref="CredProxHttpClientNames.TokenClient"/> name, kept as this provider's
    /// own constant for callers that register the client alongside it.
    /// </summary>
    public const string HttpClientName = CredProxHttpClientNames.TokenClient;

    // M38 C: the upper cap on any vendor-stated lifetime. An early refresh only re-mints, so
    // caching less than the vendor asked for is safe; caching more (a days-long "expires_in")
    // keeps a token CredProx cannot bound. Not a new option - one fixed rule for all providers.
    private static readonly TimeSpan MaxLifetime = TimeSpan.FromHours(24);

    private readonly ITokenCache _cache;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly TimeProvider _time;
    private readonly ILogger<OAuthClientCredentialsProvider>? _logger;
    private readonly ConcurrentDictionary<string, byte> _zeroLifetimeLogged = new();
    private readonly ConcurrentDictionary<string, byte> _emptyLifetimeLogged = new();
    private readonly ConcurrentDictionary<string, byte> _cappedLifetimeLogged = new();

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
        var configured = request.RequestUri;
        using var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);

        if ((int)response.StatusCode is >= 300 and < 400 || IdentityRedirectGuard.WasRedirected(request, configured))
        {
            // M45 security finding F-1: a redirect off the configured token endpoint is a
            // refusal — the status is named, never a target URL or the response body.
            throw new InvalidOperationException(
                $"The OAuth token endpoint for credential '{credentialName}' answered with a redirect "
                + $"(HTTP {(int)response.StatusCode}); CredProx never follows redirects for credential acquisition.");
        }

        if (IdentityRedirectGuard.EndsElsewhere(response, configured))
        {
            // M45 security finding R-1: the response stamps an effective request URI
            // at another address than the configured endpoint — the status is named,
            // never a target URL or body.
            throw new InvalidOperationException(
                $"The OAuth token endpoint for credential '{credentialName}' did not end at its configured address "
                + $"(HTTP {(int)response.StatusCode}); CredProx never accepts a credential response from another address.");
        }

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
            or (InvalidOperationException
                and not NegativeExpiresInRejectedException
                and not InvalidExpiresInRejectedException))
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
        // The string arm parses with the canonical JSON-number grammar only. The
        // old double.TryParse(string, out _) overload was CurrentCulture with AllowThousands:
        // "1,000" parsed or not depending on the machine, and the non-finite names arrived
        // host-dependently - "Infinity"/"-Infinity" parse only under the invariant culture (an
        // InvariantGlobalization host), while ICU cultures render the symbol as ∞ and reject
        // the names ("NaN" parses under en-US/de-DE/sv-SE, not ar-EG); exponent overflow
        // ("1e400" = +∞) is the culture-independent route.
        // Before the IsFinite guard at the return all of these became a silent
        // DefaultLifetime - a full-hour token lifetime minted from a nonsense expiry.
        // M38 B: the empty string is the one string that is absent, not a violation - it falls
        // back WITH one warning per credential (the zero-lifetime rule mirrored).
        if (expiresIn.ValueKind == JsonValueKind.String && string.IsNullOrEmpty(expiresIn.GetString()))
        {
            provider.LogEmptyLifetime(credentialName);
            return defaultLifetime;
        }

        var text = expiresIn.ValueKind == JsonValueKind.String ? expiresIn.GetString() : null;
        double? seconds = expiresIn.ValueKind switch
        {
            JsonValueKind.Number => expiresIn.GetDouble(),
            JsonValueKind.String when double.TryParse(
                text, NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed) => parsed,
            // Unmistakably meant as a number, parseable only via thousands grouping; accepting
            // it would make the cached lifetime culture-dependent. Reject (rationale
            // in the CHANGELOG).
            JsonValueKind.String when IsGroupedNumber(text) => throw new InvalidExpiresInRejectedException(
                $"The OAuth token endpoint for credential '{credentialName}' returned a thousands-grouped 'expires_in' value; the token response was rejected."),
            // A non-empty string that is not a JSON number in any culture ("abc", "0x10",
            // non-ASCII digits) is a protocol violation, not a silent DefaultLifetime. This was
            // the last silent-fallback hole in the string arm.
            JsonValueKind.String => throw new InvalidExpiresInRejectedException(
                $"The OAuth token endpoint for credential '{credentialName}' returned an unusable 'expires_in' string; the token response was rejected."),
            _ => null,
        };

        if (seconds is double value)
        {
            if (!double.IsFinite(value))
            {
                // RFC 6749 counts seconds: Infinity/NaN are not lifetimes. Reject through the
                // documented IdP-failure path like the negative case - nothing cached, and the
                // message names the field and credential id, never the value or the token.
                throw new InvalidExpiresInRejectedException(
                    $"The OAuth token endpoint for credential '{credentialName}' returned a non-finite 'expires_in' value; the token response was rejected.");
            }

            if (value < 0)
            {
                // RFC 6749 defines expires_in as a lifetime in seconds: a negative value is a
                // protocol violation, and caching the token it stamps serves a guaranteed
                // vendor 401 (in 0.9.0 it silently degraded to DefaultLifetime).
                // Reject the response through the documented IdP-failure path - callers get
                // credential_unavailable (502) and nothing is cached. The message names the
                // field and the credential id, never the value and never the token.
                throw new NegativeExpiresInRejectedException(
                    $"The OAuth token endpoint for credential '{credentialName}' returned a negative 'expires_in' value; the token response was rejected.");
            }

            if (value == 0)
            {
                provider.LogZeroLifetime(credentialName);
            }
        }

        // Finite and positive by here (negatives threw, zero falls back); NaN/Infinity
        // cannot reach the return. M38 C: above 24 h the lifetime is capped - the seconds
        // comparison also takes the TimeSpan-overflow values (1e12, 1e300) out of
        // TimeSpan.FromSeconds, where they used to throw into the malformed-response re-wrap.
        return seconds is double positive && positive > 0
            ? provider.CapLifetime(positive, credentialName)
            : defaultLifetime;
    }

    private TimeSpan CapLifetime(double seconds, string credentialName)
    {
        // M38 C: early refresh only re-mints, so caching below the vendor's request is safe;
        // caching above a day is unbounded. One loud notice per credential, the zero-lifetime
        // rule mirrored.
        if (seconds <= MaxLifetime.TotalSeconds)
        {
            return TimeSpan.FromSeconds(seconds);
        }

        if (_logger is not null && _cappedLifetimeLogged.TryAdd(credentialName, 0))
        {
            _logger.LogWarning(
                "The OAuth token endpoint for credential '{Credential}' returned an 'expires_in' longer than 24 hours; the token is cached for 24 hours.",
                credentialName);
        }

        return MaxLifetime;
    }

    private static bool IsGroupedNumber(string? text) =>
        double.TryParse(text, NumberStyles.Float | NumberStyles.AllowThousands, CultureInfo.InvariantCulture, out _);

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

    private void LogEmptyLifetime(string credentialName)
    {
        // Present-but-empty is how some gateways render "no stated expiry": it means
        // absent - DefaultLifetime - but the credential deserves one loud notice, the
        // zero-lifetime rule beside it mirrored.
        if (_logger is null || !_emptyLifetimeLogged.TryAdd(credentialName, 0))
        {
            return;
        }

        _logger.LogWarning(
            "The OAuth token endpoint for credential '{Credential}' returned an empty 'expires_in' value; the token is cached for the configured DefaultLifetime.",
            credentialName);
    }

    /// <summary>
    /// Signals a token response rejected for a negative <c>expires_in</c>. Flows through the
    /// same IdP-failure path as any unusable response (<c>credprox.credential_unavailable</c>,
    /// nothing cached); kept distinct only so the malformed-body re-wrap does not erase the
    /// field name from the warning. Thrown by all three providers that parse a vendor
    /// <c>expires_in</c> from a response body - this one, <c>TokenExchangeProvider</c> and
    /// <c>JwtAssertionProvider</c>; one internal type because the contract is identical.
    /// </summary>
    internal sealed class NegativeExpiresInRejectedException : InvalidOperationException
    {
        public NegativeExpiresInRejectedException(string message)
            : base(message)
        {
        }
    }

    /// <summary>
    /// Signals a token response rejected for a non-finite, thousands-grouped or otherwise
    /// non-numeric <c>expires_in</c>. Same IdP-failure path as
    /// <see cref="NegativeExpiresInRejectedException"/>:
    /// credential_unavailable, nothing cached, the message names the field and credential id,
    /// never the value or the token.
    /// </summary>
    internal sealed class InvalidExpiresInRejectedException : InvalidOperationException
    {
        public InvalidExpiresInRejectedException(string message)
            : base(message)
        {
        }
    }
}
