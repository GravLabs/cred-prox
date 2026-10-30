using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using CredProx.Abstractions;

namespace CredProx;

/// <summary>
/// The built-in <c>OAuthClientCredentials</c> provider (see <c>docs/credprox-plan.md</c> §4):
/// client credentials grant against the configured token endpoint, with Basic-header or
/// form-body client authentication, optional scope and audience, and the token cached per
/// <c>(credential, partition)</c> through <see cref="ITokenCache"/>. A non-2xx response or a
/// malformed token body fails as <see cref="InvalidOperationException"/> — the core turns
/// that into <c>credprox.credential_unavailable</c> (502) without forwarding. Error messages
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

    /// <summary>Creates the provider.</summary>
    /// <param name="cache">The token cache keyed by <c>(credential, partition)</c>.</param>
    /// <param name="httpClientFactory">The factory for token-endpoint clients.</param>
    /// <param name="time">The time source for expiry decisions.</param>
    public OAuthClientCredentialsProvider(
        ITokenCache cache,
        IHttpClientFactory httpClientFactory,
        TimeProvider time)
    {
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
        _time = time ?? throw new ArgumentNullException(nameof(time));
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
                lifetime = ReadLifetime(expiresIn, options.DefaultLifetime);
            }
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException or OverflowException)
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
