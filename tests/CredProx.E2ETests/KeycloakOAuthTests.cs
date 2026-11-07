using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using CredProx;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Testcontainers.Keycloak;
using Xunit;
using Yarp.ReverseProxy.Forwarder;

namespace CredProx.E2ETests;

/// <summary>
/// The plan §5.1 Keycloak row end to end: CredProx fetches an OAuth client-credentials
/// token from a real Keycloak, attaches it to the forwarded request, and the upstream
/// introspects that token at Keycloak to confirm it is genuine. Two requests carrying the
/// same access token confirm the token cache served the second one (Keycloak issues a fresh
/// token identity per fetch).
/// </summary>
public sealed class KeycloakOAuthTests : IClassFixture<KeycloakFixture>
{
    private readonly KeycloakFixture _keycloak;
    private readonly object _authorizationGate = new();
    private readonly List<string?> _seenAuthorization = [];

    public KeycloakOAuthTests(KeycloakFixture keycloak) => _keycloak = keycloak;

    [DockerFact]
    public async Task OAuthClientCredentials_AttachesATokenTheRealIdpAccepts_AndCachesIt()
    {
        var upstream = StartIntrospectingUpstream();
        using (upstream)
        {
            var host = StartProxy(upstream);
            using (host)
            {
                var client = host.GetTestClient();

                var first = await client.GetAsync("http://proxy/resource");
                Assert.Equal(HttpStatusCode.OK, first.StatusCode);
                Assert.Equal("introspected", await first.Content.ReadAsStringAsync());

                var second = await client.GetAsync("http://proxy/resource");
                Assert.Equal(HttpStatusCode.OK, second.StatusCode);

                Assert.Equal(2, _seenAuthorization.Count);
                Assert.All(_seenAuthorization, a => Assert.StartsWith("Bearer ", a));

                // A fresh token fetch would produce a different token (Keycloak gives each
                // access token its own identity); the same string means the cache answered.
                Assert.Equal(_seenAuthorization[0], _seenAuthorization[1]);
            }
        }
    }

    /// <summary>
    /// The in-process upstream: introspects the presented bearer token at Keycloak with
    /// client credentials and answers 200 only when Keycloak says the token is active.
    /// </summary>
    private IHost StartIntrospectingUpstream() => new HostBuilder()
        .ConfigureWebHost(web =>
        {
            web.UseTestServer();
            web.Configure(app => app.Run(async context =>
            {
                var authorization = context.Request.Headers.Authorization.ToString();
                lock (_authorizationGate)
                {
                    _seenAuthorization.Add(authorization);
                }

                var token = authorization.StartsWith("Bearer ", StringComparison.Ordinal)
                    ? authorization["Bearer ".Length..]
                    : string.Empty;
                if (token.Length == 0)
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return;
                }

                using var http = new HttpClient();
                using var request = new HttpRequestMessage(
                    HttpMethod.Post,
                    $"{_keycloak.Endpoint}/realms/{KeycloakFixture.Realm}/protocol/openid-connect/token/introspect")
                {
                    Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["token"] = token }),
                };
                request.Headers.Authorization = new AuthenticationHeaderValue(
                    "Basic",
                    Convert.ToBase64String(
                        Encoding.UTF8.GetBytes($"{KeycloakFixture.ClientId}:{KeycloakFixture.ClientSecret}")));

                using var response = await http.SendAsync(request, context.RequestAborted);
                using var document = await JsonDocument.ParseAsync(
                    await response.Content.ReadAsStreamAsync(context.RequestAborted),
                    cancellationToken: context.RequestAborted);

                var active = response.IsSuccessStatusCode
                    && document.RootElement.TryGetProperty("active", out var activeElement)
                    && activeElement.GetBoolean();
                if (active)
                {
                    await context.Response.WriteAsync("introspected");
                }
                else
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                }
            }));
        })
        .Start();

    private IHost StartProxy(IHost upstream)
    {
        var tokenEndpoint = $"{_keycloak.Endpoint}/realms/{KeycloakFixture.Realm}/protocol/openid-connect/token";
        var entries = new Dictionary<string, string?>
        {
            ["CredProx:Destinations:idp:Template"] = "http://upstream.example/",
            ["CredProx:Credentials:keycloak:Type"] = "OAuthClientCredentials",
            ["CredProx:Credentials:keycloak:TokenEndpoint"] = tokenEndpoint,
            ["CredProx:Credentials:keycloak:ClientId"] = KeycloakFixture.ClientId,
            ["CredProx:Credentials:keycloak:ClientSecret"] = "secret:keycloak-secret",
            ["CredProx:Secrets:keycloak-secret"] = KeycloakFixture.ClientSecret,
            ["ReverseProxy:Routes:idp:ClusterId"] = "idp",
            ["ReverseProxy:Routes:idp:Match:Path"] = "/{**catch-all}",
            ["ReverseProxy:Routes:idp:Metadata:CredProx.Destination"] = "idp",
            ["ReverseProxy:Routes:idp:Metadata:CredProx.Credential"] = "keycloak",
            ["ReverseProxy:Clusters:idp:Destinations:static:Address"] = "http://upstream.example/",
        };

        var transport = upstream.GetTestServer().CreateHandler();
        return new HostBuilder()
            .ConfigureAppConfiguration(build => build.AddInMemoryCollection(entries))
            .ConfigureServices((context, services) =>
            {
                services.AddCredProxTokenCache();
                services.AddCredProxConfigurationSecrets(context.Configuration);
                services.AddCredProxBuiltInCredentials();
                services.AddCredProxCredentials(context.Configuration);
                services.AddRouting();
                services.AddReverseProxy()
                    .LoadFromConfig(context.Configuration.GetSection("ReverseProxy"))
                    .AddCredProx(context.Configuration);

                // The credential fetch goes to real Keycloak over real HTTP; only the
                // forwarded request uses the in-process upstream.
                services.AddSingleton<IForwarderHttpClientFactory>(
                    sp => new StubTransportFactory(sp, transport));
            })
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints => endpoints.MapReverseProxy());
                });
            })
            .Start();
    }

    private sealed class StubTransportFactory(IServiceProvider services, HttpMessageHandler transport)
        : CredProxForwarderHttpClientFactory(services)
    {
        protected override HttpMessageHandler WrapHandler(
            ForwarderHttpClientContext context, HttpMessageHandler handler)
        {
            handler.Dispose(); // the sockets transport is not used in-process
            return ComposePipeline(context, transport);
        }
    }
}

/// <summary>
/// A real Keycloak with one realm and one confidential client created through the admin
/// API — the same shape an operator provisions. Credentials are throwaway values inside a
/// container that exists only for this test class.
/// </summary>
public sealed class KeycloakFixture : IAsyncLifetime
{
    public const string Realm = "credprox";
    public const string ClientId = "credprox-api";
    public const string ClientSecret = "credprox-api-secret";

    private KeycloakContainer _keycloak = null!;

    /// <summary>Base URL of the running Keycloak, with no trailing slash.</summary>
    public string Endpoint => _keycloak.GetBaseAddress().TrimEnd('/');

    public async Task InitializeAsync()
    {
        if (!DockerFactAttribute.IsAvailable)
        {
            return; // the tests skip; xunit still builds the fixture, so stay inert
        }

        _keycloak = new KeycloakBuilder("quay.io/keycloak/keycloak:24.0")
            .WithUsername("admin")
            .WithPassword("admin")
            .Build();
        await _keycloak.StartAsync();

        using var http = new HttpClient();
        using (var adminTokenResponse = await http.PostAsync(
                   $"{Endpoint}/realms/master/protocol/openid-connect/token",
                   new FormUrlEncodedContent(new Dictionary<string, string>
                   {
                       ["client_id"] = "admin-cli",
                       ["grant_type"] = "password",
                       ["username"] = "admin",
                       ["password"] = "admin",
                   })))
        {
            Assert.True(
                adminTokenResponse.IsSuccessStatusCode,
                $"The Keycloak admin token request failed with {(int)adminTokenResponse.StatusCode}.");
            using var tokenDocument = JsonDocument.Parse(
                await adminTokenResponse.Content.ReadAsStringAsync());
            var adminToken = tokenDocument.RootElement.GetProperty("access_token").GetString()!;

            var realmJson = $$"""
                {
                  "realm": "{{Realm}}",
                  "enabled": true,
                  "clients": [
                    {
                      "clientId": "{{ClientId}}",
                      "secret": "{{ClientSecret}}",
                      "protocol": "openid-connect",
                      "publicClient": false,
                      "bearerOnly": false,
                      "standardFlowEnabled": false,
                      "implicitFlowEnabled": false,
                      "directAccessGrantsEnabled": false,
                      "serviceAccountsEnabled": true
                    }
                  ]
                }
                """;
            using var createRealm = new HttpRequestMessage(HttpMethod.Post, $"{Endpoint}/admin/realms")
            {
                Content = new StringContent(realmJson, Encoding.UTF8, "application/json"),
            };
            createRealm.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
            using var created = await http.SendAsync(createRealm);
            Assert.True(
                created.IsSuccessStatusCode,
                $"Creating the '{Realm}' realm failed with {(int)created.StatusCode}.");
        }
    }

    public async Task DisposeAsync()
    {
        if (_keycloak is null)
        {
            return;
        }

        await _keycloak.StopAsync();
        await _keycloak.DisposeAsync();
    }
}
