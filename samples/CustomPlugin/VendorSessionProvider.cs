using System.Text.Json;
using CredProx;
using CredProx.Abstractions;

// The whole plugin: a credential type CredProx does not ship. This legacy-vendor shape —
// POST appId+secret as JSON, get a session id back, send it as a custom header — is the
// kind of thing a community plugin exists for. Everything the provider needs from the
// core arrives through the constructor (cache, client factory, clock) and the per-call
// arguments (bound options, scoped secret accessor, request context).
public sealed class VendorSessionOptions : IHasAttachment
{
    /// <summary>The vendor's login endpoint.</summary>
    public string? LoginEndpoint { get; set; }

    /// <summary>The vendor app id; a literal or a <c>secret:</c> reference.</summary>
    public string? AppId { get; set; }

    /// <summary>The vendor secret as a <c>secret:</c> reference.</summary>
    public string? Secret { get; set; }

    /// <summary>Header the session id is attached to.</summary>
    public string Name { get; set; } = "X-Session-Id";

    /// <summary>Attached as a header, raw value, no scheme prefix.</summary>
    public CredentialLocation Location => CredentialLocation.Header;

    /// <inheritdoc />
    public string? Prefix => null;

    /// <summary>Lifetime assumed when the vendor response carries no expiry.</summary>
    public TimeSpan DefaultLifetime { get; set; } = TimeSpan.FromMinutes(30);
}

public sealed class VendorSessionProvider : ICredentialProvider<VendorSessionOptions>
{
    private readonly ITokenCache _cache;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly TimeProvider _time;

    public VendorSessionProvider(ITokenCache cache, IHttpClientFactory httpClientFactory, TimeProvider time)
    {
        _cache = cache;
        _httpClientFactory = httpClientFactory;
        _time = time;
    }

    /// <summary>The name this type carries in configuration (<c>"Type": "VendorSession"</c>).</summary>
    public string Type => "VendorSession";

    // Caching through ITokenCache is the contract the core's single-flight, refresh-on-401
    // and per-partition isolation behavior is built on — the conformance suite checks it.
    public ValueTask<string> GetCredentialAsync(
        VendorSessionOptions options,
        ISecretAccessor secrets,
        CredentialRequestContext context,
        CancellationToken cancellationToken) =>
        _cache.GetTokenAsync(
            context.CredentialName,
            context.Partition,
            ct => FetchAsync(options, secrets, context.CredentialName, ct),
            cancellationToken);

    private async ValueTask<(string Value, DateTimeOffset ExpiresAt)> FetchAsync(
        VendorSessionOptions options,
        ISecretAccessor secrets,
        string credentialName,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(options.LoginEndpoint))
        {
            throw new InvalidOperationException(
                $"Credential '{credentialName}' of type VendorSession requires a LoginEndpoint.");
        }

        var request = new
        {
            appId = await ResolveAsync(options.AppId, secrets, cancellationToken).ConfigureAwait(false) ?? "",
            secret = await ResolveAsync(options.Secret, secrets, cancellationToken).ConfigureAwait(false) ?? "",
        };

        var client = _httpClientFactory.CreateClient("credprox-token");
        using var response = await client
            .PostAsJsonAsync(options.LoginEndpoint, request, cancellationToken)
            .ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            // Names the status, never the request or response bodies — they carry secrets.
            throw new InvalidOperationException(
                $"The vendor login endpoint for credential '{credentialName}' failed with HTTP {(int)response.StatusCode}.");
        }

        string sessionId;
        TimeSpan lifetime;
        try
        {
            using var document = JsonDocument.Parse(await response.Content
                .ReadAsStringAsync(cancellationToken).ConfigureAwait(false));

            // M19 (§8.3): the vendor can tell "this app user has not consented" apart
            // from "the credential is broken". The typed signal makes the proxy answer
            // 401 credprox.consent_required with the authorize URL for the caller to
            // open — where a plain exception would only get the generic 502.
            if (document.RootElement.TryGetProperty("error", out var error)
                && error.ValueKind == JsonValueKind.String
                && error.GetString() == "consent_required"
                && document.RootElement.TryGetProperty("authorize_url", out var authorize)
                && authorize.ValueKind == JsonValueKind.String
                && authorize.GetString() is { Length: > 0 } authorizeUrl)
            {
                throw new ConsentRequiredException(
                    authorizeUrl,
                    $"Credential '{credentialName}' needs the user to consent at the vendor.");
            }

            sessionId = document.RootElement.GetProperty("access_token").GetString()
                ?? throw new InvalidOperationException("The vendor response has no session id.");
            lifetime = document.RootElement.TryGetProperty("expires_in", out var expiresIn)
                && expiresIn.TryGetInt32(out var seconds) && seconds > 0
                ? TimeSpan.FromSeconds(seconds)
                : options.DefaultLifetime;
        }
        catch (Exception ex)
            when (ex is not ConsentRequiredException // a typed signal, not a malformed answer
                && ex is JsonException or InvalidOperationException or FormatException)
        {
            throw new InvalidOperationException(
                $"The vendor login endpoint for credential '{credentialName}' returned a malformed response.", ex);
        }

        return (sessionId, _time.GetUtcNow() + lifetime);
    }

    // The scoped accessor (plan §3.5 rule 4) resolves only this credential's own
    // secret: references; plain values pass through untouched.
    private static async ValueTask<string?> ResolveAsync(
        string? value, ISecretAccessor secrets, CancellationToken cancellationToken) =>
        value is { Length: > 0 } && value.StartsWith("secret:", StringComparison.Ordinal)
            ? await secrets.GetSecretAsync(value, cancellationToken).ConfigureAwait(false)
            : value;
}
