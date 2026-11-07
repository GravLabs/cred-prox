using System.Net;
using CredProx.Abstractions;
using CredProx.Testing;
using Xunit;

// What a plugin author puts in their own test project: describe the credential in
// configuration, inherit the suite, and the §5.2 checks — acquire success, single-flight
// under 100 concurrent acquires, refresh-after-invalidate, per-partition isolation,
// no secret values in any log line, failure hygiene — run against the provider through
// the real binder, secret scoping and cache wiring. The built-ins run these same suites
// (tests/CredProx.ConformanceTests); there is no privileged path.
//
// Run them here without a test runner:  dotnet run -- --selftest
// In your own repo they are plain xunit facts — `dotnet test` runs them as-is.
public sealed class VendorSessionConformanceTests
    : CachingCredentialProviderConformanceTests<VendorSessionProvider, VendorSessionOptions>
{
    private const string AppIdValue = "conformance-app-id";
    private const string SecretValue = "conformance-vendor-secret";

    protected override string CredentialTypeName => "VendorSession";

    protected override IReadOnlyDictionary<string, string?> CredentialConfig { get; } =
        new Dictionary<string, string?>
        {
            ["Type"] = "VendorSession",
            ["LoginEndpoint"] = "https://vendor.example/login",
            ["AppId"] = "secret:app-id",
            ["Secret"] = "secret:vendor-secret",
        };

    protected override IReadOnlyDictionary<string, string?> SecretConfig { get; } =
        new Dictionary<string, string?>
        {
            ["app-id"] = AppIdValue,
            ["vendor-secret"] = SecretValue,
        };

    protected override IReadOnlyList<string> SecretValues { get; } = [AppIdValue, SecretValue];

    // ---- M19 consent signalling demo (§8.3) ----

    [Fact]
    public async Task LoginAnsweringConsentRequired_SurfacesTheTypedConsentSignal()
    {
        // The plugin side of §8.3: a vendor answer that distinguishes "this user has not
        // consented" from "the credential is broken" becomes the typed signal. The core's
        // half — 401 credprox.consent_required with the authorize URL, refresh-path
        // safety — is CredProxPipelineIntegrationTests' job, which every plugin inherits.
        using var server = new FakeTokenServer();
        server.Enqueue(
            HttpStatusCode.OK,
            """{"error":"consent_required","authorize_url":"https://vendor.example/consent?req=abc"}""");
        var provider = new VendorSessionProvider(
            new PassThroughCache(),
            new SingleClientFactory(new HttpClient(server)),
            TimeProvider.System);

        var ex = await Assert.ThrowsAsync<ConsentRequiredException>(() => provider.GetCredentialAsync(
            new VendorSessionOptions
            {
                LoginEndpoint = "https://vendor.example/login",
                AppId = "app",
                Secret = "sec",
            },
            new UnreachableSecrets(),
            new CredentialRequestContext { CredentialName = "vendor" },
            CancellationToken.None).AsTask());

        Assert.Equal("https://vendor.example/consent?req=abc", ex.AuthorizeUrl);
        Assert.Equal(1, server.CallCount); // the login answer drove the signal directly
    }

    // Minimal harness for the demo fact: no cache semantics to exercise here — just
    // hand the fetch result through.
    private sealed class PassThroughCache : ITokenCache
    {
        public async ValueTask<string> GetTokenAsync(
            string credential,
            string? partition,
            Func<CancellationToken, ValueTask<(string Value, DateTimeOffset ExpiresAt)>> acquire,
            CancellationToken cancellationToken)
        {
            var (value, _) = await acquire(cancellationToken);
            return value;
        }

        public void Invalidate(string credential, string? partition)
        {
        }
    }

    private sealed class SingleClientFactory(HttpClient client) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => client;
    }

    private sealed class UnreachableSecrets : ISecretAccessor
    {
        public ValueTask<string> GetSecretAsync(string name, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("the demo uses plain values, no secret references");
    }
}
