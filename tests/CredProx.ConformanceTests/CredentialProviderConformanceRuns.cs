using System.Net;
using System.Security.Cryptography;
using CredProx;
using CredProx.Abstractions;
using CredProx.Testing;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace CredProx.ConformanceTests;

/// <summary>
/// §5.2 "Conformance": every built-in credential type runs through the same
/// <c>CredProx.Testing</c> conformance suites plugin authors use — the suites are honest
/// about the built-ins before they are demanded of plugins.
/// </summary>
public sealed class OAuthClientCredentialsConformance
    : CachingCredentialProviderConformanceTests<OAuthClientCredentialsProvider, OAuthClientCredentialsOptions>
{
    private const string ClientIdValue = "conformance-client-id";
    private const string ClientSecretValue = "conformance-client-secret";

    protected override string CredentialTypeName => "OAuthClientCredentials";

    protected override IReadOnlyDictionary<string, string?> CredentialConfig { get; } =
        new Dictionary<string, string?>
        {
            ["Type"] = "OAuthClientCredentials",
            ["TokenEndpoint"] = "https://vendor.example/token",
            ["ClientId"] = "secret:cid",
            ["ClientSecret"] = "secret:csec",
        };

    protected override IReadOnlyDictionary<string, string?> SecretConfig { get; } =
        new Dictionary<string, string?>
        {
            ["cid"] = ClientIdValue,
            ["csec"] = ClientSecretValue,
        };

    protected override IReadOnlyList<string> SecretValues { get; } = [ClientIdValue, ClientSecretValue];
}

public sealed class LoginExchangeConformance
    : CachingCredentialProviderConformanceTests<LoginExchangeProvider, LoginExchangeOptions>
{
    private const string UserValue = "conformance-user";
    private const string PasswordValue = "conformance-password";

    protected override string CredentialTypeName => "LoginExchange";

    protected override IReadOnlyDictionary<string, string?> CredentialConfig { get; } =
        new Dictionary<string, string?>
        {
            ["Type"] = "LoginExchange",
            ["LoginEndpoint"] = "https://vendor.example/login",
            ["Method"] = "POST",
            ["Form:User"] = "secret:user",
            ["Form:Password"] = "secret:pass",
            ["Response"] = "JsonPath",
            ["ResponseField"] = "access_token",
        };

    protected override IReadOnlyDictionary<string, string?> SecretConfig { get; } =
        new Dictionary<string, string?>
        {
            ["user"] = UserValue,
            ["pass"] = PasswordValue,
        };

    protected override IReadOnlyList<string> SecretValues { get; } = [UserValue, PasswordValue];
}

public sealed class JwtAssertionConformance
    : CachingCredentialProviderConformanceTests<JwtAssertionProvider, JwtAssertionOptions>
{
    // A real RS256 key: the provider signs with it, so the suite exercises the full
    // sign-and-exchange path against the fake token server.
    private static readonly string SigningKeyPem = GenerateKey();

    protected override string CredentialTypeName => "JwtAssertion";

    protected override IReadOnlyDictionary<string, string?> CredentialConfig { get; } =
        new Dictionary<string, string?>
        {
            ["Type"] = "JwtAssertion",
            ["SigningKey"] = "secret:signing-key",
            ["Issuer"] = "conformance-issuer",
            ["Audience"] = "https://vendor.example",
            ["TokenEndpoint"] = "https://vendor.example/token",
        };

    protected override IReadOnlyDictionary<string, string?> SecretConfig { get; } =
        new Dictionary<string, string?>
        {
            ["signing-key"] = SigningKeyPem,
        };

    protected override IReadOnlyList<string> SecretValues { get; } = [SigningKeyPem];

    private static string GenerateKey()
    {
        using var rsa = RSA.Create(2048);
        return rsa.ExportPkcs8PrivateKeyPem();
    }
}

public sealed class StaticKeyConformance
    : CredentialProviderConformanceTests<StaticKeyProvider, StaticKeyOptions>
{
    private const string KeyValue = "conformance-static-key-value";

    protected override string CredentialTypeName => "StaticKey";

    protected override IReadOnlyDictionary<string, string?> CredentialConfig { get; } =
        new Dictionary<string, string?>
        {
            ["Type"] = "StaticKey",
            ["Secret"] = "secret:api-key",
            ["Name"] = "X-Api-Key",
        };

    protected override IReadOnlyDictionary<string, string?> SecretConfig { get; } =
        new Dictionary<string, string?>
        {
            ["api-key"] = KeyValue,
        };

    protected override IReadOnlyList<string> SecretValues { get; } = [KeyValue];

    /// <summary>
    /// A static key never touches HTTP, so the failure shape is the unresolvable
    /// reference itself: the error must name the reference, never a value.
    /// </summary>
    [Fact]
    public override async Task Failure_DoesNotLeakSecretValues()
    {
        await using var host = BuildHost(configureConfig: keys => keys.Remove("CredProx:Secrets:api-key"));

        var failure = await Assert.ThrowsAnyAsync<Exception>(() => host.Acquire().AsTask());

        Assert.DoesNotContain(KeyValue, failure.Message, StringComparison.Ordinal);
        host.Logs.AssertNoSecretValues(SecretValues);
    }
}

/// <summary>
/// §3.6/§5.2: the delegated <c>TokenExchange</c> type runs the same conformance suite as
/// every other built-in. It inherits the base suite rather than the caching one: the
/// caching suite's assumptions (one stub call per acquire, invalidation under the plain
/// partition) are vendor-token-shaped, while this type fetches a JWKS and keys per user —
/// those properties (single-flight, per-user isolation, refresh-on-401 of the per-user
/// entry) are proven in <c>TokenExchangeProviderTests</c>. Explicit-JwksUri mode keeps all
/// HTTP on the stub factory; the inbound token is a real signed JWT so the full
/// validate-then-exchange path runs.
/// </summary>
public sealed class TokenExchangeConformance
    : CredentialProviderConformanceTests<TokenExchangeProvider, TokenExchangeOptions>
{
    private const string ClientIdValue = "conformance-exchange-client-id";
    private const string ClientSecretValue = "conformance-exchange-client-secret";
    private const string IssuerValue = "https://conformance-idp.example";
    private const string JwksUrl = "https://conformance-idp.example/jwks";
    private const string AudienceValue = "conformance-api";

    private static readonly RSA IdpRsa = RSA.Create(2048);

    // A real inbound user token, validated against the JWKS the fake server serves.
    private static readonly string InboundToken = IssueInboundToken();

    protected override string CredentialTypeName => "TokenExchange";

    protected override IReadOnlyDictionary<string, string?> CredentialConfig { get; } =
        new Dictionary<string, string?>
        {
            ["Type"] = "TokenExchange",
            ["Issuer"] = IssuerValue,
            ["JwksUri"] = JwksUrl,
            ["Audience"] = AudienceValue,
            ["TokenEndpoint"] = "https://conformance-idp.example/token",
            ["ClientId"] = "secret:cid",
            ["ClientSecret"] = "secret:csec",
        };

    protected override IReadOnlyDictionary<string, string?> SecretConfig { get; } =
        new Dictionary<string, string?>
        {
            ["cid"] = ClientIdValue,
            ["csec"] = ClientSecretValue,
        };

    // The inbound token is a request secret (§3.5 rule 4): it must never surface either.
    protected override IReadOnlyList<string> SecretValues { get; } = [ClientIdValue, ClientSecretValue, InboundToken];

    protected override CredentialRequestContext CreateContext() => new()
    {
        CredentialName = CredentialName,
        Partition = Partition,
        InboundToken = InboundToken,
    };

    // JWKS GETs get the real key set; everything else gets the fresh-token default.
    protected override void ConfigureTokenServer(FakeTokenServer tokenServer) =>
        tokenServer.Responder = (req, call) => req.RequestUri!.AbsolutePath.Contains("/jwks")
            ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(JwksJson()) }
            : new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent($$"""{"access_token":"tok-{{call}}","expires_in":3600}"""),
            };

    /// <summary>
    /// The exchange-endpoint failure shape (the default drives failure from a script entry,
    /// which the earlier JWKS GET would consume): the token endpoint answers 500 and neither
    /// the message nor the logs may carry a secret value.
    /// </summary>
    [Fact]
    public override async Task Failure_DoesNotLeakSecretValues()
    {
        await using var host = BuildHost(server => server.Responder = (req, _) =>
            req.RequestUri!.AbsolutePath.Contains("/jwks")
                ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(JwksJson()) }
                : new HttpResponseMessage(HttpStatusCode.InternalServerError)
                {
                    Content = new StringContent("""{"error":"server_error"}"""),
                });

        var failure = await Assert.ThrowsAnyAsync<Exception>(() => host.Acquire().AsTask());

        foreach (var value in SecretValues)
        {
            Assert.DoesNotContain(value, failure.Message, StringComparison.Ordinal);
        }

        host.Logs.AssertNoSecretValues(SecretValues);
    }

    private static string IssueInboundToken()
    {
        var now = DateTimeOffset.UtcNow;
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = IssuerValue,
            Audience = AudienceValue,
            NotBefore = now.AddMinutes(-1).UtcDateTime,
            Expires = now.AddMinutes(5).UtcDateTime,
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(IdpRsa), SecurityAlgorithms.RsaSha256),
            Claims = new Dictionary<string, object> { ["sub"] = "conformance-user" },
        });
    }

    private static string JwksJson()
    {
        // Plain RFC 7517 JWKS for the IdP key — the shape a real IdP serves.
        var p = IdpRsa.ExportParameters(false);
        static string B64Url(byte[] bytes) =>
            Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return System.Text.Json.JsonSerializer.Serialize(new
        {
            keys = new[]
            {
                new { kty = "RSA", use = "sig", alg = "RS256", n = B64Url(p.Modulus!), e = B64Url(p.Exponent!) },
            },
        });
    }
}

public sealed class HmacConformance
    : CredentialProviderConformanceTests<HmacProvider, HmacOptions>
{
    private const string KeyValue = "conformance-hmac-key-value";

    protected override string CredentialTypeName => "Hmac";

    protected override IReadOnlyDictionary<string, string?> CredentialConfig { get; } =
        new Dictionary<string, string?>
        {
            ["Type"] = "Hmac",
            ["Secret"] = "secret:signing-key",
            ["SignatureHeader"] = "X-Signature",
            ["Components:0"] = "method",
            ["Components:1"] = "path",
        };

    protected override IReadOnlyDictionary<string, string?> SecretConfig { get; } =
        new Dictionary<string, string?>
        {
            ["signing-key"] = KeyValue,
        };

    protected override IReadOnlyList<string> SecretValues { get; } = [KeyValue];

    /// <summary>Signing-style credential: no HTTP, so failure is the unresolvable reference.</summary>
    [Fact]
    public override async Task Failure_DoesNotLeakSecretValues()
    {
        await using var host = BuildHost(configureConfig: keys => keys.Remove("CredProx:Secrets:signing-key"));

        var failure = await Assert.ThrowsAnyAsync<Exception>(() => host.Acquire().AsTask());

        Assert.DoesNotContain(KeyValue, failure.Message, StringComparison.Ordinal);
        host.Logs.AssertNoSecretValues(SecretValues);
    }
}
