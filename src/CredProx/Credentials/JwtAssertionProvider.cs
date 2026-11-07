using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using CredProx.Abstractions;

namespace CredProx;

/// <summary>
/// The built-in <c>JwtAssertion</c> provider (see <c>docs/credprox-plan.md</c> §4 Phase C):
/// mints a signed assertion (RS256/ES256/PS256 with <c>iss</c>/<c>sub</c>/<c>aud</c>/
/// <c>exp</c>/<c>iat</c>/<c>jti</c>, a fresh <c>jti</c> per assertion, clock skew applied
/// through <see cref="TimeProvider"/>) and exchanges it for an access token in one of three
/// modes (<c>client_assertion</c>, RFC 7523 jwt-bearer grant, or GitHub-App-style bearer
/// exchange). The exchanged token is cached per <c>(credential, partition)</c> through
/// <see cref="ITokenCache"/>; the assertion itself is never cached because every assertion
/// must carry a unique <c>jti</c>. Error messages never contain key material or response
/// bodies (§3.4 hygiene).
/// </summary>
[Experimental("CREDPROX001")]
public sealed class JwtAssertionProvider : ICredentialProvider<JwtAssertionOptions>
{
    private readonly ITokenCache _cache;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly TimeProvider _time;

    /// <summary>Creates the provider.</summary>
    /// <param name="cache">The token cache keyed by <c>(credential, partition)</c>.</param>
    /// <param name="httpClientFactory">The factory for exchange-endpoint clients.</param>
    /// <param name="time">The time source for claim timestamps and expiry decisions.</param>
    public JwtAssertionProvider(
        ITokenCache cache,
        IHttpClientFactory httpClientFactory,
        TimeProvider time)
    {
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
        _time = time ?? throw new ArgumentNullException(nameof(time));
    }

    /// <inheritdoc />
    public string Type => "JwtAssertion";

    /// <inheritdoc />
    public ValueTask<string> GetCredentialAsync(
        JwtAssertionOptions options,
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
        JwtAssertionOptions options,
        ISecretAccessor secrets,
        CancellationToken cancellationToken)
    {
        var tokenEndpoint = await ExpandRequiredAsync(options.TokenEndpoint, partition, secrets, cancellationToken)
            .ConfigureAwait(false);
        var issuer = await ExpandRequiredAsync(options.Issuer, partition, secrets, cancellationToken)
            .ConfigureAwait(false);
        var audience = await ExpandRequiredAsync(options.Audience, partition, secrets, cancellationToken)
            .ConfigureAwait(false);
        var subject = options.Subject is null
            ? null
            : await TemplateExpander.ExpandAsync(options.Subject, partition, secrets, cancellationToken)
                .ConfigureAwait(false);
        var clientId = options.ClientId is null
            ? null
            : await TemplateExpander.ExpandAsync(options.ClientId, partition, secrets, cancellationToken)
                .ConfigureAwait(false);

        var assertion = await MintAssertionAsync(options, secrets, issuer, subject, audience, cancellationToken)
            .ConfigureAwait(false);

        var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint);

        switch (options.Exchange)
        {
            case JwtAssertionExchange.ClientAssertion:
            {
                var form = new List<KeyValuePair<string, string>>
                {
                    new("grant_type", "client_credentials"),
                    new("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                    new("client_assertion", assertion),
                };
                if (clientId is not null)
                {
                    form.Add(new KeyValuePair<string, string>("client_id", clientId));
                }

                if (!string.IsNullOrEmpty(options.Scope))
                {
                    form.Add(new KeyValuePair<string, string>("scope", options.Scope));
                }

                request.Content = new FormUrlEncodedContent(form);
                break;
            }

            case JwtAssertionExchange.JwtBearerGrant:
            {
                var form = new List<KeyValuePair<string, string>>
                {
                    new("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                    new("assertion", assertion),
                };
                if (!string.IsNullOrEmpty(options.Scope))
                {
                    form.Add(new KeyValuePair<string, string>("scope", options.Scope));
                }

                request.Content = new FormUrlEncodedContent(form);
                break;
            }

            case JwtAssertionExchange.BearerExchange:
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", assertion);
                break;
            }
        }

        var client = _httpClientFactory.CreateClient(CredProxHttpClientNames.ForConnection(options.Connection));
        using var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(
                $"The JWT assertion exchange endpoint for credential '{credentialName}' failed with HTTP {(int)response.StatusCode}.");
        }

        var json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        string accessToken;
        DateTimeOffset expiresAt;
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            accessToken = ReadRequiredString(root, options.TokenField);

            expiresAt = _time.GetUtcNow() + options.DefaultLifetime;
            if (options.ExpiresInField is { } expiresInField &&
                root.TryGetProperty(expiresInField, out var expiresIn) &&
                TryReadSeconds(expiresIn, out var seconds))
            {
                expiresAt = _time.GetUtcNow() + TimeSpan.FromSeconds(seconds);
            }
            else if (options.ExpiresAtField is { } expiresAtField &&
                     root.TryGetProperty(expiresAtField, out var expiresAtElement) &&
                     expiresAtElement.ValueKind == JsonValueKind.String &&
                     DateTimeOffset.TryParse(expiresAtElement.GetString(), out var absolute))
            {
                expiresAt = absolute;
            }
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException or OverflowException)
        {
            // The body may echo request fragments; never include it in the error.
            throw new InvalidOperationException(
                $"The JWT assertion exchange endpoint for credential '{credentialName}' returned a malformed response.", ex);
        }

        return (accessToken, expiresAt);
    }

    private async Task<string> MintAssertionAsync(
        JwtAssertionOptions options,
        ISecretAccessor secrets,
        string issuer,
        string? subject,
        string audience,
        CancellationToken cancellationToken)
    {
        var keyMaterial = options.SigningKey is not null
            ? await SecretValues.ResolveIfReferenceAsync(options.SigningKey, secrets, cancellationToken)
                .ConfigureAwait(false)
            : await SecretValues.ResolveIfReferenceAsync(
                    options.SigningCertificate!, secrets, cancellationToken)
                .ConfigureAwait(false);

        if (string.IsNullOrEmpty(keyMaterial))
        {
            throw new InvalidOperationException("The JWT assertion signing key does not resolve.");
        }

        var now = _time.GetUtcNow();
        var payload = new Dictionary<string, object>
        {
            ["iss"] = issuer,
            ["aud"] = audience,
            ["iat"] = now.ToUnixTimeSeconds() - (long)options.ClockSkew.TotalSeconds,
            ["exp"] = now.ToUnixTimeSeconds() + (long)options.Lifetime.TotalSeconds + (long)options.ClockSkew.TotalSeconds,
            ["jti"] = Guid.NewGuid().ToString("N"),
        };
        if (subject is not null)
        {
            payload["sub"] = subject;
        }

        return JwtSigner.Sign(
            options.Algorithm,
            keyMaterial,
            useCertificate: options.SigningKey is null,
            payload,
            _time);
    }

    private static async Task<string> ExpandRequiredAsync(
        string? value,
        string? partition,
        ISecretAccessor secrets,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(value))
        {
            throw new InvalidOperationException("The JWT assertion credential is missing a required value.");
        }

        return await TemplateExpander.ExpandAsync(value, partition, secrets, cancellationToken)
            .ConfigureAwait(false);
    }

    private static string ReadRequiredString(JsonElement root, string property)
    {
        if (!root.TryGetProperty(property, out var element) ||
            element.ValueKind != JsonValueKind.String ||
            element.GetString() is not { Length: > 0 } value)
        {
            throw new InvalidOperationException($"The exchange response is missing the '{property}' value.");
        }

        return value;
    }

    private static bool TryReadSeconds(JsonElement element, out double seconds)
    {
        seconds = element.ValueKind switch
        {
            JsonValueKind.Number => element.GetDouble(),
            JsonValueKind.String when double.TryParse(element.GetString(), out var parsed) => parsed,
            _ => double.NaN,
        };

        return double.IsFinite(seconds) && seconds > 0;
    }
}

/// <summary>
/// A minimal JWT writer for assertion minting: base64url header and payload, signed with
/// RSA (PKCS#1 or PSS) or ECDSA P-256. Deliberately not a general JWT library — the
/// assertion shape is fixed by <see cref="JwtAssertionOptions"/> and the dependency stays
/// inside <c>System.Security.Cryptography</c>.
/// </summary>
internal static class JwtSigner
{
    public static string Sign(
        JwtAssertionAlgorithm algorithm,
        string keyMaterial,
        bool useCertificate,
        IReadOnlyDictionary<string, object> payload,
        TimeProvider time)
    {
        var header = JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, string>
        {
            ["alg"] = algorithm.ToString(),
            ["typ"] = "JWT",
        });

        var claims = JsonSerializer.SerializeToUtf8Bytes(payload);
        var signingInput = ConvertToBase64Url(header) + "." + ConvertToBase64Url(claims);
        var inputBytes = Encoding.ASCII.GetBytes(signingInput);

        byte[] signature = algorithm switch
        {
            JwtAssertionAlgorithm.RS256 => SignRsa(keyMaterial, useCertificate, inputBytes, RSASignaturePadding.Pkcs1),
            JwtAssertionAlgorithm.PS256 => SignRsa(keyMaterial, useCertificate, inputBytes, RSASignaturePadding.Pss),
            JwtAssertionAlgorithm.ES256 => SignEcdsa(keyMaterial, useCertificate, inputBytes),
            _ => throw new InvalidOperationException($"Unsupported JWT assertion algorithm '{algorithm}'."),
        };

        return signingInput + "." + ConvertToBase64Url(signature);
    }

    private static byte[] SignRsa(
        string keyMaterial,
        bool useCertificate,
        byte[] input,
        RSASignaturePadding padding)
    {
        using var rsa = useCertificate
            ? LoadCertificate(keyMaterial).GetRSAPrivateKey() ?? throw new InvalidOperationException(
                "The signing certificate has no RSA private key.")
            : ImportRsa(keyMaterial);
        return rsa.SignData(input, HashAlgorithmName.SHA256, padding);
    }

    private static byte[] SignEcdsa(string keyMaterial, bool useCertificate, byte[] input)
    {
        using var ecdsa = useCertificate
            ? LoadCertificate(keyMaterial).GetECDsaPrivateKey() ?? throw new InvalidOperationException(
                "The signing certificate has no ECDSA private key.")
            : ImportEcdsa(keyMaterial);
        return ecdsa.SignData(input, HashAlgorithmName.SHA256);
    }

    private static RSA ImportRsa(string pem)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return rsa;
    }

    private static ECDsa ImportEcdsa(string pem)
    {
        var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(pem);
        return ecdsa;
    }

    private static X509Certificate2 LoadCertificate(string base64Pkcs12)
    {
        try
        {
            return X509CertificateLoader.LoadPkcs12(Convert.FromBase64String(base64Pkcs12), password: null);
        }
        catch (CryptographicException ex)
        {
            throw new InvalidOperationException("The signing certificate could not be loaded.", ex);
        }
    }

    private static string ConvertToBase64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
