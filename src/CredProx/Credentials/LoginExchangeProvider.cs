using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using CredProx.Abstractions;

namespace CredProx;

/// <summary>
/// The built-in <c>LoginExchange</c> provider (see <c>docs/credprox-plan.md</c> §3.2 cayuse
/// and §4): calls a login endpoint and reads the credential from the raw body, a JSON path,
/// a response header or a cookie. Endpoint and credentials are templates expanded per
/// request — <c>{partition}</c> first, then <c>{secret:...}</c> through the credential's
/// scoped accessor — so per-partition secrets resolve correctly and the token is cached per
/// <c>(credential, partition)</c>. Failures surface as <see cref="InvalidOperationException"/>
/// (core: 502, no forward); error messages never contain secret values or response bodies.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class LoginExchangeProvider : ICredentialProvider<LoginExchangeOptions>
{
    private readonly ITokenCache _cache;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly TimeProvider _time;

    /// <summary>Creates the provider.</summary>
    /// <param name="cache">The token cache keyed by <c>(credential, partition)</c>.</param>
    /// <param name="httpClientFactory">The factory for login-endpoint clients.</param>
    /// <param name="time">The time source for expiry decisions.</param>
    public LoginExchangeProvider(
        ITokenCache cache,
        IHttpClientFactory httpClientFactory,
        TimeProvider time)
    {
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
        _time = time ?? throw new ArgumentNullException(nameof(time));
    }

    /// <inheritdoc />
    public string Type => "LoginExchange";

    /// <inheritdoc />
    public ValueTask<string> GetCredentialAsync(
        LoginExchangeOptions options,
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
            ct => ExchangeAsync(context.CredentialName, context.Partition, options, secrets, ct),
            cancellationToken);
    }

    private async ValueTask<(string Value, DateTimeOffset ExpiresAt)> ExchangeAsync(
        string credentialName,
        string? partition,
        LoginExchangeOptions options,
        ISecretAccessor secrets,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(options.LoginEndpoint))
        {
            throw new InvalidOperationException(
                $"The login-exchange credential '{credentialName}' has no LoginEndpoint configured.");
        }

        var endpoint = await ExpandAsync(options.LoginEndpoint, partition, secrets, cancellationToken)
            .ConfigureAwait(false);

        var request = new HttpRequestMessage(ResolveMethod(options.Method), endpoint);

        if (options.Basic is { } basic)
        {
            var user = await ExpandAsync(basic.User, partition, secrets, cancellationToken).ConfigureAwait(false);
            var password = await ExpandAsync(basic.Password, partition, secrets, cancellationToken).ConfigureAwait(false);
            var pair = Encoding.UTF8.GetBytes($"{user}:{password}");
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(pair));
        }
        else if (options.Form is { } form)
        {
            var user = await ExpandAsync(form.User, partition, secrets, cancellationToken).ConfigureAwait(false);
            var password = await ExpandAsync(form.Password, partition, secrets, cancellationToken).ConfigureAwait(false);
            request.Content = new FormUrlEncodedContent([
                new KeyValuePair<string, string>("user", user),
                new KeyValuePair<string, string>("password", password),
            ]);
        }

        var client = _httpClientFactory.CreateClient(CredProxHttpClientNames.ForConnection(options.Connection));
        using var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(
                $"The login endpoint for credential '{credentialName}' failed with HTTP {(int)response.StatusCode}.");
        }

        var token = await ReadTokenAsync(credentialName, options, response, cancellationToken).ConfigureAwait(false);
        return (token, _time.GetUtcNow() + options.Lifetime);
    }

    private static async ValueTask<string> ExpandAsync(
        string? template,
        string? partition,
        ISecretAccessor secrets,
        CancellationToken cancellationToken)
    {
        if (template is null)
        {
            return string.Empty;
        }

        return await TemplateExpander
            .ExpandAsync(template, partition, secrets, cancellationToken)
            .ConfigureAwait(false);
    }

    private static HttpMethod ResolveMethod(string method) => method.Trim().ToUpperInvariant() switch
    {
        "GET" => HttpMethod.Get,
        "POST" => HttpMethod.Post,
        _ => throw new InvalidOperationException($"The login-exchange Method '{method}' is not supported; use GET or POST."),
    };

    private static async ValueTask<string> ReadTokenAsync(
        string credentialName,
        LoginExchangeOptions options,
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        switch (options.Response)
        {
            case LoginExchangeResponse.RawBody:
            {
                var body = (await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false)).Trim();
                return NonEmpty(body, credentialName, "response body");
            }

            case LoginExchangeResponse.JsonPath:
            {
                var path = RequireField(options, credentialName);
                var json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    using var document = JsonDocument.Parse(json);
                    var current = document.RootElement;
                    foreach (var segment in path.Split('.', StringSplitOptions.RemoveEmptyEntries))
                    {
                        if (current.ValueKind != JsonValueKind.Object ||
                            !current.TryGetProperty(segment, out var next))
                        {
                            throw new InvalidOperationException(
                                $"The login response for credential '{credentialName}' has no JSON path '{path}'.");
                        }

                        current = next;
                    }

                    if (current.ValueKind != JsonValueKind.String || current.GetString() is not { Length: > 0 } value)
                    {
                        throw new InvalidOperationException(
                            $"The login response JSON path '{path}' for credential '{credentialName}' is not a token string.");
                    }

                    return value;
                }
                catch (JsonException ex)
                {
                    throw new InvalidOperationException(
                        $"The login endpoint for credential '{credentialName}' returned malformed JSON.", ex);
                }
            }

            case LoginExchangeResponse.Header:
            {
                var headerName = RequireField(options, credentialName);
                if (response.Headers.TryGetValues(headerName, out var values) &&
                    values.FirstOrDefault() is { Length: > 0 } headerValue)
                {
                    return headerValue;
                }

                throw new InvalidOperationException(
                    $"The login response for credential '{credentialName}' has no header '{headerName}'.");
            }

            case LoginExchangeResponse.Cookie:
            {
                var cookieName = RequireField(options, credentialName);
                var setCookies = response.Headers.TryGetValues("Set-Cookie", out var cookies) ? cookies : [];
                foreach (var setCookie in setCookies)
                {
                    var pair = setCookie.Split(';')[0];
                    var separator = pair.IndexOf('=');
                    if (separator > 0 &&
                        string.Equals(pair[..separator].Trim(), cookieName, StringComparison.Ordinal) &&
                        pair[(separator + 1)..].Trim() is { Length: > 0 } cookieValue)
                    {
                        return cookieValue;
                    }
                }

                throw new InvalidOperationException(
                    $"The login response for credential '{credentialName}' has no cookie '{cookieName}'.");
            }

            default:
                throw new InvalidOperationException(
                    $"The login-exchange Response mode '{options.Response}' is not supported.");
        }
    }

    private static string RequireField(LoginExchangeOptions options, string credentialName)
    {
        if (string.IsNullOrEmpty(options.ResponseField))
        {
            throw new InvalidOperationException(
                $"The login-exchange credential '{credentialName}' needs ResponseField for Response mode '{options.Response}'.");
            }

        return options.ResponseField;
    }

    private static string NonEmpty(string value, string credentialName, string what)
    {
        if (string.IsNullOrEmpty(value))
        {
            throw new InvalidOperationException(
                $"The login response for credential '{credentialName}' has an empty {what}.");
        }

        return value;
    }
}
