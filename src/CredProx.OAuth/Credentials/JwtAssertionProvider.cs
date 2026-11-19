using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Collections.Concurrent;
using System.Text.Json;
using CredProx.Abstractions;
using Microsoft.Extensions.Logging;

namespace CredProx;

/// <summary>
/// The built-in <c>JwtAssertion</c> provider:
/// mints a signed assertion (RS256/ES256/PS256 with <c>iss</c>/<c>sub</c>/<c>aud</c>/
/// <c>exp</c>/<c>iat</c>/<c>jti</c>, a fresh <c>jti</c> per assertion, clock skew applied
/// through <see cref="TimeProvider"/>) and exchanges it for an access token in one of three
/// modes (<c>client_assertion</c>, RFC 7523 jwt-bearer grant, or GitHub-App-style bearer
/// exchange). The exchanged token is cached per <c>(credential, partition)</c> through
/// <see cref="ITokenCache"/>; the assertion itself is never cached because every assertion
/// must carry a unique <c>jti</c>. Error messages never contain key material or response
/// bodies.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class JwtAssertionProvider : ICredentialProvider<JwtAssertionOptions>
{
    // M38 C: the upper cap on any vendor-stated lifetime (same fixed rule as the OAuth and
    // TokenExchange providers). It rides AFTER the M37 precedence: the
    // expires_in seconds AND the expires_at-derived lifetime are both capped at 24 h.
    private static readonly TimeSpan MaxLifetime = TimeSpan.FromHours(24);

    private readonly ITokenCache _cache;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly TimeProvider _time;
    private readonly ILogger<JwtAssertionProvider>? _logger;

    // M38 B: an empty 'expires_in' means "no stated expiry" (absent), but the credential deserves
    // one loud notice — the OAuth zero-lifetime rule (LogZeroLifetime) mirrored. One dictionary
    // per notice kind, so two different notices on one credential both land.
    private readonly ConcurrentDictionary<string, byte> _emptyExpiresInLogged = new();
    private readonly ConcurrentDictionary<string, byte> _cappedLifetimeLogged = new();
    private readonly ConcurrentDictionary<string, byte> _unparseableExpiresAtLogged = new();

    /// <summary>Creates the provider.</summary>
    /// <param name="cache">The token cache keyed by <c>(credential, partition)</c>.</param>
    /// <param name="httpClientFactory">The factory for exchange-endpoint clients.</param>
    /// <param name="time">The time source for claim timestamps and expiry decisions.</param>
    public JwtAssertionProvider(
        ITokenCache cache,
        IHttpClientFactory httpClientFactory,
        TimeProvider time)
        : this(cache, httpClientFactory, time, logger: null)
    {
    }

    /// <summary>Creates the provider with an operator log for lifetime notices.</summary>
    /// <param name="cache">The token cache keyed by <c>(credential, partition)</c>.</param>
    /// <param name="httpClientFactory">The factory for exchange-endpoint clients.</param>
    /// <param name="time">The time source for claim timestamps and expiry decisions.</param>
    /// <param name="logger">
    /// Optional log for per-credential lifetime notices (the empty-<c>expires_in</c> and
    /// unparseable-<c>expires_at</c> warnings); <c>null</c> stays silent.
    /// </param>
    public JwtAssertionProvider(
        ITokenCache cache,
        IHttpClientFactory httpClientFactory,
        TimeProvider time,
        ILogger<JwtAssertionProvider>? logger)
    {
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
        _time = time ?? throw new ArgumentNullException(nameof(time));
        _logger = logger;
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
        DateTimeOffset expiresAt = default;
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            accessToken = ReadRequiredString(root, options.TokenField);

            // ExpiresAtField is consulted when ExpiresInField is absent OR unusable
            // (zero, negative, non-finite, unparseable) - the documented precedence. A
            // negative expires_in is UNUSABLE, not an instant throw: it still gives way
            // to a valid expires_at, and only rejects - nothing cached - when nothing
            // usable remains, because the only path left would cache on DefaultLifetime
            // with nothing in the response supporting that lifetime. The same
            // defer-then-reject treatment covers every unusable expires_in: non-finite,
            // thousands-grouped, and any other non-empty non-numeric string
            // (InvalidExpiresInRejectedException).
            // Zero and the empty string are the two branches that never reject: zero falls to a
            // valid expires_at, else DefaultLifetime (JwtAssertionProviderTests pins both); "" is
            // absent-with-notice - the same fallback plus one warning per credential.
            var resolvedExpiry = false;
            var negativeExpiresIn = false;
            var invalidExpiresIn = false;
            var emptyExpiresIn = false;
            var pastExpiresAt = false;
            if (options.ExpiresInField is { } expiresInField &&
                root.TryGetProperty(expiresInField, out var expiresIn))
            {
                emptyExpiresIn = expiresIn.ValueKind == JsonValueKind.String
                    && expiresIn.GetString() is { Length: 0 };
                if (TryReadSeconds(expiresIn, out var seconds, out negativeExpiresIn, out invalidExpiresIn))
                {
                    // positive by contract; M38 C caps the seconds before FromSeconds (so the
                    // 1e12/1e300 overflow values clamp instead of throwing into the re-wrap).
                    expiresAt = _time.GetUtcNow() + CapLifetime(seconds, credentialName);
                    resolvedExpiry = true;
                }
            }

            // The M37 precedence: expires_at is consulted whenever expires_in did not resolve -
            // absent OR unusable - so this arm must stay flat against the outer if: nesting it
            // would let a present-but-unusable expires_in steal the precedence from a valid
            // expires_at (the three KeepsPrecedence/UsesAbsoluteExpiry pins here are the guard).
            if (!resolvedExpiry &&
                options.ExpiresAtField is { } expiresAtField &&
                root.TryGetProperty(expiresAtField, out var expiresAtElement))
            {
                // M38 D: the absolute expiry is read culture-invariantly with AssumeUniversal -
                // an offset-less value is UTC, never host-local (the base read it in CurrentCulture,
                // so a de-DE host parsed "15.11.2026" and an EST host read "07:00:00" as noon).
                // A JSON number is epoch seconds (some GitHub-App-style stubs emit it). Present
                // but unparseable falls back WITH one notice per credential; JSON null and other
                // kinds stay silent-absent, exactly like expires_in.
                var kind = expiresAtElement.ValueKind;
                DateTimeOffset? parsed = null;
                if (kind == JsonValueKind.String && DateTimeOffset.TryParse(
                        expiresAtElement.GetString(),
                        CultureInfo.InvariantCulture,
                        DateTimeStyles.AssumeUniversal | DateTimeStyles.RoundtripKind,
                        out var textAbsolute))
                {
                    parsed = textAbsolute;
                }
                else if (kind == JsonValueKind.Number && double.IsFinite(expiresAtElement.GetDouble()))
                {
                    // Bound the epoch to the DateTimeOffset range: a value outside it (or a
                    // fractional/overflow double) is treated as unparseable and falls back with
                    // the notice below, never as an OverflowException into the malformed re-wrap.
                    var epoch = expiresAtElement.GetDouble();
                    if (epoch is >= -62135596800 and <= 253402300799)
                    {
                        parsed = DateTimeOffset.FromUnixTimeSeconds((long)epoch);
                    }
                }

                if (parsed is { } absolute)
                {
                    var now = _time.GetUtcNow();
                    if (absolute <= now)
                    {
                        // An absolute expiry already at or before now is UNUSABLE
                        // — the same class as a negative expires_in: never act on a
                        // token whose stated expiry is already dead. Defer like the unusable
                        // expires_in values: a usable one upstream already won the precedence,
                        // and if nothing else resolves below this faults the response.
                        pastExpiresAt = true;
                    }
                    else
                    {
                        // M38 C: the cap rides after the precedence, so a far-future absolute
                        // expiry is clamped to now + 24 h too (one notice, same as the seconds cap).
                        expiresAt = absolute - now > MaxLifetime ? CapAbsolute(now, credentialName) : absolute;
                        resolvedExpiry = true;
                    }
                }
                else if (kind is JsonValueKind.String or JsonValueKind.Number)
                {
                    LogUnparseableExpiresAt(credentialName);
                }
            }
            if (!resolvedExpiry && negativeExpiresIn)
            {
                throw new OAuthClientCredentialsProvider.NegativeExpiresInRejectedException(
                    $"The JWT assertion exchange endpoint for credential '{credentialName}' returned a negative 'expires_in' value; the token response was rejected.");
            }
            if (!resolvedExpiry && invalidExpiresIn)
            {
                // A non-finite, thousands-grouped or non-numeric
                // expires_in is a protocol violation like the negative case, but the
                // precedence above stands - it only rejects once no usable expires_at resolved the
                // expiry. Nothing cached; the message names the field and the credential id,
                // never the value or the token.
                throw new OAuthClientCredentialsProvider.InvalidExpiresInRejectedException(
                    $"The JWT assertion exchange endpoint for credential '{credentialName}' returned an invalid 'expires_in' value; the token response was rejected.");
            }
            if (!resolvedExpiry && pastExpiresAt)
            {
                // M38: the response's only remaining stated expiry was already dead —
                // reject exactly like the unusable expires_in cases. Nothing cached; the
                // message names the field and the credential id, never the value.
                throw new OAuthClientCredentialsProvider.InvalidExpiresInRejectedException(
                    $"The JWT assertion exchange endpoint for credential '{credentialName}' returned an 'expires_at' that is already past; the token response was rejected.");
            }
            if (!resolvedExpiry)
            {
                if (emptyExpiresIn)
                {
                    LogEmptyExpiresIn(credentialName);
                }

                expiresAt = _time.GetUtcNow() + options.DefaultLifetime;
            }
        }
        catch (Exception ex) when (ex is (JsonException or InvalidOperationException or FormatException or OverflowException)
            and not OAuthClientCredentialsProvider.NegativeExpiresInRejectedException
            and not OAuthClientCredentialsProvider.InvalidExpiresInRejectedException)
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

    /// <summary>
    /// Reads a vendor lifetime in seconds with the canonical JSON-number grammar - invariant
    /// culture, no thousands grouping (the old overload was CurrentCulture +
    /// AllowThousands, so a de-DE host read "3600.9" as 36 009 s and "1,000" as 1 s).
    /// Returns true only for a finite POSITIVE value. A parseable NEGATIVE value sets
    /// <paramref name="negative"/>, and a non-finite value or ANY non-empty string outside the
    /// JSON-number grammar - grouped or not ("1,000", "abc", "0x10", non-ASCII digits) - sets
    /// <paramref name="invalid"/> (OAuth's rejection rule: expires_at first, rejection only
    /// when nothing usable remains; both flags reject when they
    /// win). JSON null and other non-number kinds set neither and stay the documented silent
    /// fallback; so does the EMPTY string, which the caller treats as absent-with-one-warning,
    /// not as invalid.
    /// </summary>
    private static bool TryReadSeconds(JsonElement element, out double seconds, out bool negative, out bool invalid)
    {
        var text = element.ValueKind == JsonValueKind.String ? element.GetString() : null;
        double? value = element.ValueKind switch
        {
            JsonValueKind.Number => element.GetDouble(),
            JsonValueKind.String when double.TryParse(
                text, NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed) => parsed,
            _ => null,
        };

        // A String kind whose invariant parse failed has value == null and non-null text; the only
        // string exempt from invalid is the empty one (absent-with-warning, handled by the caller).
        negative = value is double v && double.IsFinite(v) && v < 0;
        invalid = value is double n && !double.IsFinite(n)
            || (value is null && text is { Length: > 0 });
        seconds = value ?? double.NaN;
        return value is double p && double.IsFinite(p) && p > 0;
    }

    private void LogEmptyExpiresIn(string credentialName)
    {
        // Some vendors send "" to mean "no stated expiry" - serving the fallback is intended
        // (M38 B: "" is absent), but an empty lifetime field deserves one loud notice per
        // credential, exactly like the OAuth zero-lifetime rule it mirrors.
        if (_logger is null || !_emptyExpiresInLogged.TryAdd(credentialName, 0))
        {
            return;
        }

        _logger.LogWarning(
            "The JWT assertion exchange endpoint for credential '{Credential}' returned an empty 'expires_in' value; the token expiry fell back to the configured fields.",
            credentialName);
    }

    private TimeSpan CapLifetime(double seconds, string credentialName)
    {
        // M38 C: the comparison is on the SECONDS so TimeSpan-overflow values (1e12 s = 1e19
        // ticks > MaxTicks, 1e300) are capped before FromSeconds instead of throwing into the
        // generic malformed-response re-wrap. Early refresh only re-mints, so caching below the
        // vendor's request is safe.
        if (seconds <= MaxLifetime.TotalSeconds)
        {
            return TimeSpan.FromSeconds(seconds);
        }

        LogLifetimeCapped(credentialName);
        return MaxLifetime;
    }

    private DateTimeOffset CapAbsolute(DateTimeOffset now, string credentialName)
    {
        // M38 C: a far-future absolute expiry capped to now + 24 h (early refresh re-mints).
        LogLifetimeCapped(credentialName);
        return now + MaxLifetime;
    }

    private void LogLifetimeCapped(string credentialName)
    {
        // One loud notice per credential for either cap path (seconds or absolute).
        if (_logger is not null && _cappedLifetimeLogged.TryAdd(credentialName, 0))
        {
            _logger.LogWarning(
                "The JWT assertion exchange endpoint for credential '{Credential}' returned an expiry more than 24 hours out; the token is cached for 24 hours.",
                credentialName);
        }
    }

    private void LogUnparseableExpiresAt(string credentialName)
    {
        // M38 D: a present-but-unreadable absolute expiry falls back to the configured
        // default with one notice per credential - the message never quotes the vendor's
        // value (it may echo request fragments, same hygiene as every other notice here).
        if (_logger is not null && _unparseableExpiresAtLogged.TryAdd(credentialName, 0))
        {
            _logger.LogWarning(
                "The JWT assertion exchange endpoint for credential '{Credential}' returned an unparseable 'expires_at' value; the token expiry fell back to the configured default.",
                credentialName);
        }
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
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            // FormatException (material is not Base-64 at all) must not reach the
            // operator raw while a loadable-shape failure is wrapped (M31 triage):
            // both mean 'the configured certificate material cannot be used'.
            throw new InvalidOperationException("The signing certificate could not be loaded.", ex);
        }
    }

    private static string ConvertToBase64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
