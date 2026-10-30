using System.Net;
using System.Security.Cryptography;
using System.Text;
using CredProx;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Xunit;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;

namespace CredProx.Tests;

/// <summary>
/// The M6 request path end to end (§4 Phase B, §5.2 caller rows): caller API-key
/// authentication, per-caller credentials through the <c>caller:</c> partition (separate
/// token-cache entries per caller), and per-caller operation allow-lists — each asserted
/// against the real YARP pipeline, including that a rejected request never reaches the
/// token endpoint or the upstream and the key value never appears in a log.
/// </summary>
public sealed class CallerAuthIntegrationTests : IAsyncLifetime
{
    private const string KeyA = "caller-key-alpha";
    private const string KeyB = "caller-key-beta";

    private readonly StubHttpHandler _tokenHandler;
    private readonly IHost _upstream;
    private readonly List<string> _upstreamPaths = [];
    private readonly List<Dictionary<string, string?>> _upstreamHeaders = [];

    public CallerAuthIntegrationTests()
    {
        var tokens = new Queue<string>(["token-1", "token-2", "token-3", "token-4"]);
        _tokenHandler = new StubHttpHandler((_, _) =>
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(tokens.Dequeue()) });

        _upstream = new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.Configure(app => app.Run(context =>
                {
                    _upstreamPaths.Add(context.Request.Path + context.Request.QueryString);
                    _upstreamHeaders.Add(new Dictionary<string, string?>
                    {
                        ["Authorization"] = context.Request.Headers.Authorization.ToString(),
                        ["X-CredProx-Key"] = context.Request.Headers["X-CredProx-Key"],
                    });
                    return context.Response.WriteAsync("upstream-ok");
                }));
            })
            .Start();
    }

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        await _upstream.StopAsync();
        _upstream.Dispose();
    }

    private void ResetUpstream()
    {
        _upstreamPaths.Clear();
        _upstreamHeaders.Clear();
    }

    /// <summary>Base config: two callers, a <c>caller:</c>-partitioned credential whose
    /// token endpoint and vendor account expand per caller.</summary>
    private static Dictionary<string, string?> CallerEntries() => new()
    {
        ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
        ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash(KeyA),
        ["CredProx:Callers:app-b:Keys:0:KeyId"] = "k1",
        ["CredProx:Callers:app-b:Keys:0:KeyHash"] = Hash(KeyB),

        ["CredProx:Destinations:acme:Template"] = "http://upstream.example/",

        // Per-caller vendor accounts through the caller: partition: the login endpoint and
        // the account secret name both expand {partition}, so each caller authenticates to
        // its own account and the token cache holds a separate entry per caller.
        ["CredProx:Credentials:contoso:Type"] = "LoginExchange",
        ["CredProx:Credentials:contoso:LoginEndpoint"] = "http://token.example/{partition}/login",
        ["CredProx:Credentials:contoso:Method"] = "POST",
        ["CredProx:Credentials:contoso:Form:User"] = "user-{partition}",
        ["CredProx:Credentials:contoso:Form:Password"] = "secret:{partition}-pass",
        ["CredProx:Credentials:contoso:AttachPrefix"] = "Bearer",
        ["CredProx:Credentials:contoso:Partition:From"] = "caller:",
        ["CredProx:Credentials:contoso:Partition:Allowed:0"] = "app-a",
        ["CredProx:Credentials:contoso:Partition:Allowed:1"] = "app-b",
        ["CredProx:Secrets:app-a-pass"] = "pass-a",
        ["CredProx:Secrets:app-b-pass"] = "pass-b",
    };

    private static readonly RouteConfig AcmeRoute = new()
    {
        RouteId = "acme",
        ClusterId = "acme",
        Match = new RouteMatch { Path = "/api/{**catch-all}" },
        Metadata = new Dictionary<string, string>
        {
            [CredProxMetadata.Destination] = "acme",
            [CredProxMetadata.Credential] = "contoso",
        },
    };

    private static readonly ClusterConfig AcmeCluster = new()
    {
        ClusterId = "acme",
        Destinations = new Dictionary<string, DestinationConfig>
        {
            ["static"] = new() { Address = "http://static.example/" },
        },
    };

    private (IHost Host, List<string?> Logs) StartProxyHost(
        IReadOnlyList<RouteConfig> routes,
        IReadOnlyList<ClusterConfig> clusters,
        Dictionary<string, string?>? callerEntries = null)
    {
        var entries = CallerEntries();
        if (callerEntries is not null)
        {
            foreach (var (key, value) in callerEntries)
            {
                entries[key] = value;
            }
        }

        var transport = _upstream.GetTestServer().CreateHandler();
        var logs = new List<string?>();

        var host = new HostBuilder()
            .ConfigureAppConfiguration(build => build.AddInMemoryCollection(entries))
            .ConfigureServices((context, services) =>
            {
                services.AddCredProxTokenCache();
                services.AddCredProxConfigurationSecrets(context.Configuration);
                services.AddCredProxBuiltInCredentials();
                services.AddCredProxCredentials(context.Configuration);
                services.AddCredProxCallerAuthentication(context.Configuration);
                services.AddRouting();
                services.AddReverseProxy().LoadFromMemory(routes, clusters).AddCredProx(context.Configuration);

                services.AddHttpClient(CredProxHttpClientNames.TokenClient)
                    .ConfigurePrimaryHttpMessageHandler(() => _tokenHandler);

                services.AddSingleton<IForwarderHttpClientFactory>(
                    sp => new StubTransportFactory(sp, transport));
            })
            .ConfigureLogging(logging => logging.AddProvider(new CapturingLoggerProvider(logs)))
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

        return (host, logs);
    }

    private sealed class StubTransportFactory(IServiceProvider services, HttpMessageHandler transport)
        : CredProxForwarderHttpClientFactory(services)
    {
        protected override HttpMessageHandler WrapHandler(
            ForwarderHttpClientContext context, HttpMessageHandler handler)
        {
            handler.Dispose();
            return ComposePipeline(context, transport);
        }
    }

    [Fact]
    public async Task ValidKey_IsForwarded_WithCallerCredential()
    {
        ResetUpstream();
        var (host, _) = StartProxyHost([AcmeRoute], [AcmeCluster]);

        var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy/api/thing");
        request.Headers.Add("X-CredProx-Key", KeyA);
        var response = await host.GetTestClient().SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("Bearer token-1", Assert.Single(_upstreamHeaders)["Authorization"]);
        Assert.Contains("/app-a/login", _tokenHandler.Requests[0].RequestUri!.ToString());
        Assert.Contains("user=user-app-a", _tokenHandler.Body(0));
        Assert.Contains("password=pass-a", _tokenHandler.Body(0));
    }

    [Fact]
    public async Task CallerKeyHeader_NeverForwarded()
    {
        ResetUpstream();
        var (host, _) = StartProxyHost([AcmeRoute], [AcmeCluster]);

        var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy/api/thing");
        request.Headers.Add("X-CredProx-Key", KeyA);
        await host.GetTestClient().SendAsync(request);

        Assert.True(string.IsNullOrEmpty(Assert.Single(_upstreamHeaders)["X-CredProx-Key"]));
    }

    [Fact]
    public async Task MissingKey_401Problem_NoForwardNoToken()
    {
        ResetUpstream();
        var (host, _) = StartProxyHost([AcmeRoute], [AcmeCluster]);

        var response = await host.GetTestClient().GetAsync("http://proxy/api/thing");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType!.MediaType);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("credprox.caller_unauthenticated", body);
        Assert.Empty(_upstreamPaths);
        Assert.Empty(_tokenHandler.Requests);
    }

    [Fact]
    public async Task CallerBudget_Exceeded_429_RetryAfter_NoForwardNoToken()
    {
        // M15 (§3.7) end to end: the budget rejects before credential attachment — the
        // upstream sees exactly the admitted requests and the token endpoint is hit once
        // (the cached token), never for a rejected request.
        ResetUpstream();
        var (host, _) = StartProxyHost([AcmeRoute], [AcmeCluster], new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Limits:PermitsPerInterval"] = "2",
            ["CredProx:Callers:app-a:Limits:Interval"] = "00:01:00",
        });

        for (var i = 0; i < 2; i++)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy/api/thing");
            request.Headers.Add("X-CredProx-Key", KeyA);
            var admitted = await host.GetTestClient().SendAsync(request);
            Assert.Equal(HttpStatusCode.OK, admitted.StatusCode);
        }

        var third = new HttpRequestMessage(HttpMethod.Get, "http://proxy/api/thing");
        third.Headers.Add("X-CredProx-Key", KeyA);
        var rejected = await host.GetTestClient().SendAsync(third);

        Assert.Equal(HttpStatusCode.TooManyRequests, rejected.StatusCode);
        var body = await rejected.Content.ReadAsStringAsync();
        Assert.Contains("credprox.caller_throttled", body);
        Assert.NotNull(rejected.Headers.RetryAfter);
        Assert.Equal(2, _upstreamPaths.Count);
        Assert.Single(_tokenHandler.Requests); // cached for the second; none for the rejected
    }

    [Fact]
    public async Task CallerBudget_IsPerCaller_OtherCallersUnaffected()
    {
        ResetUpstream();
        var (host, _) = StartProxyHost([AcmeRoute], [AcmeCluster], new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Limits:PermitsPerInterval"] = "1",
            ["CredProx:Callers:app-a:Limits:Interval"] = "00:01:00",
        });

        var first = new HttpRequestMessage(HttpMethod.Get, "http://proxy/api/thing");
        first.Headers.Add("X-CredProx-Key", KeyA);
        Assert.Equal(HttpStatusCode.OK, (await host.GetTestClient().SendAsync(first)).StatusCode);

        var second = new HttpRequestMessage(HttpMethod.Get, "http://proxy/api/thing");
        second.Headers.Add("X-CredProx-Key", KeyA);
        Assert.Equal(
            HttpStatusCode.TooManyRequests,
            (await host.GetTestClient().SendAsync(second)).StatusCode);

        // app-b declares no Limits: one chatty app cannot exhaust the shared upstream
        // for the others — the whole point of the milestone.
        var other = new HttpRequestMessage(HttpMethod.Get, "http://proxy/api/thing");
        other.Headers.Add("X-CredProx-Key", KeyB);
        Assert.Equal(HttpStatusCode.OK, (await host.GetTestClient().SendAsync(other)).StatusCode);
    }

    [Fact]
    public async Task UnknownKey_401Problem_KeyValueNotLeaked()
    {
        ResetUpstream();
        var (host, logs) = StartProxyHost([AcmeRoute], [AcmeCluster]);

        var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy/api/thing");
        request.Headers.Add("X-CredProx-Key", "guessed-key-value");
        var response = await host.GetTestClient().SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("credprox.caller_unauthenticated", body);
        Assert.DoesNotContain("guessed-key-value", body);
        Assert.DoesNotContain(logs, l => l?.Contains("guessed-key-value", StringComparison.Ordinal) == true);
        Assert.Empty(_upstreamPaths);
        Assert.Empty(_tokenHandler.Requests);
    }

    [Fact]
    public async Task TwoCallers_GetOwnCredentialsAndCacheEntries()
    {
        ResetUpstream();
        var (host, _) = StartProxyHost([AcmeRoute], [AcmeCluster]);

        var first = new HttpRequestMessage(HttpMethod.Get, "http://proxy/api/thing");
        first.Headers.Add("X-CredProx-Key", KeyA);
        Assert.Equal(HttpStatusCode.OK, (await host.GetTestClient().SendAsync(first)).StatusCode);

        var second = new HttpRequestMessage(HttpMethod.Get, "http://proxy/api/thing");
        second.Headers.Add("X-CredProx-Key", KeyB);
        Assert.Equal(HttpStatusCode.OK, (await host.GetTestClient().SendAsync(second)).StatusCode);

        // Per-caller credentials: each caller logs into its own vendor account, and the
        // cache holds a separate entry per caller (two fetches, two distinct bearer tokens).
        Assert.Equal(2, _tokenHandler.Requests.Count);
        Assert.Contains("/app-a/login", _tokenHandler.Requests[0].RequestUri!.ToString());
        Assert.Contains("/app-b/login", _tokenHandler.Requests[1].RequestUri!.ToString());
        Assert.Contains("user=user-app-a", _tokenHandler.Body(0));
        Assert.Contains("user=user-app-b", _tokenHandler.Body(1));
        Assert.Equal("Bearer token-1", _upstreamHeaders[0]["Authorization"]);
        Assert.Equal("Bearer token-2", _upstreamHeaders[1]["Authorization"]);
    }

    [Fact]
    public async Task CallerWithNoMapping_403_NoTokenFetch()
    {
        ResetUpstream();
        // app-b authenticates fine but the credential allow-list only maps app-a.
        var (host, _) = StartProxyHost(
            [AcmeRoute],
            [AcmeCluster],
            new Dictionary<string, string?> { ["CredProx:Credentials:contoso:Partition:Allowed:1"] = null });

        var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy/api/thing");
        request.Headers.Add("X-CredProx-Key", KeyB);
        var response = await host.GetTestClient().SendAsync(request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("credprox.operation_not_allowed", body);
        Assert.DoesNotContain("app-b", body); // the rejected value never appears
        Assert.Empty(_tokenHandler.Requests); // no token fetched for an unmapped caller
        Assert.Empty(_upstreamPaths);
    }

    [Fact]
    public async Task AllowListedPath_ForbiddenPath_403_NoTokenNoUpstream()
    {
        ResetUpstream();
        var (host, _) = StartProxyHost(
            [AcmeRoute],
            [AcmeCluster],
            new Dictionary<string, string?>
            {
                ["CredProx:Callers:app-a:Operations:0:Route"] = "acme",
                ["CredProx:Callers:app-a:Operations:0:Methods:0"] = "GET",
                ["CredProx:Callers:app-a:Operations:0:Paths:0"] = "/api/reports/*",
            });

        var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy/api/admin");
        request.Headers.Add("X-CredProx-Key", KeyA);
        var response = await host.GetTestClient().SendAsync(request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains(
            "credprox.operation_not_allowed", await response.Content.ReadAsStringAsync());
        Assert.Empty(_tokenHandler.Requests);
        Assert.Empty(_upstreamPaths);
    }

    [Fact]
    public async Task AllowListedPath_MatchingPath_IsForwarded()
    {
        ResetUpstream();
        var (host, _) = StartProxyHost(
            [AcmeRoute],
            [AcmeCluster],
            new Dictionary<string, string?>
            {
                ["CredProx:Callers:app-a:Operations:0:Route"] = "acme",
                ["CredProx:Callers:app-a:Operations:0:Methods:0"] = "GET",
                ["CredProx:Callers:app-a:Operations:0:Paths:0"] = "/api/reports/*",
            });

        var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy/api/reports/q1");
        request.Headers.Add("X-CredProx-Key", KeyA);
        var response = await host.GetTestClient().SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("/api/reports/q1", Assert.Single(_upstreamPaths));
    }

    [Theory]
    [InlineData("/api/reports%2Fq1")]
    [InlineData("/api/reports%2fadmin")]
    [InlineData("/api/reports%5cadmin")]
    public async Task EncodedTraversalVariants_403_NoTokenNoUpstream(string path)
    {
        ResetUpstream();
        var (host, _) = StartProxyHost(
            [AcmeRoute],
            [AcmeCluster],
            new Dictionary<string, string?>
            {
                // A rule broad enough to match the resolved shape — the encoded traversal
                // must still be refused on shape alone (§5.2 traversal variants).
                ["CredProx:Callers:app-a:Operations:0:Route"] = "acme",
                ["CredProx:Callers:app-a:Operations:0:Paths:0"] = "/api/**",
            });

        // RequestUri.ToString() would unescape %2F back to '/', so build the target from
        // raw bytes to keep the escape on the wire.
        var request = new HttpRequestMessage(
            HttpMethod.Get, new Uri(new Uri("http://proxy"), new Uri(path, UriKind.Relative)));
        request.Headers.Add("X-CredProx-Key", KeyA);
        var response = await host.GetTestClient().SendAsync(request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains(
            "credprox.operation_not_allowed", await response.Content.ReadAsStringAsync());
        Assert.Empty(_tokenHandler.Requests);
        Assert.Empty(_upstreamPaths);
    }

    [Theory]
    [InlineData("/api/reports/../admin", "/api/admin")]
    public async Task DotSegments_NormalizedByKestrel_ScoreAgainstTheNormalizedPath(
        string wirePath, string expectedForwarded)
    {
        // Kestrel normalizes dot segments before routing (RFC 3986), so the pipeline never
        // sees them; whatever path does reach the allow-list is what gets forwarded — the
        // allow-list and the upstream can never disagree about which operation ran.
        ResetUpstream();
        var (host, _) = StartProxyHost(
            [AcmeRoute],
            [AcmeCluster],
            new Dictionary<string, string?>
            {
                ["CredProx:Callers:app-a:Operations:0:Route"] = "acme",
                ["CredProx:Callers:app-a:Operations:0:Paths:0"] = "/api/reports/*",
            });

        var blocked = new HttpRequestMessage(
            HttpMethod.Get, new Uri(new Uri("http://proxy"), new Uri(wirePath, UriKind.Relative)));
        blocked.Headers.Add("X-CredProx-Key", KeyA);
        Assert.Equal(HttpStatusCode.Forbidden, (await host.GetTestClient().SendAsync(blocked)).StatusCode);
        Assert.Empty(_tokenHandler.Requests);
        Assert.Empty(_upstreamPaths);

        // The same normalized path is what a matching rule admits.
        ResetUpstream();
        var (openHost, _) = StartProxyHost(
            [AcmeRoute],
            [AcmeCluster],
            new Dictionary<string, string?>
            {
                ["CredProx:Callers:app-a:Operations:0:Route"] = "acme",
                ["CredProx:Callers:app-a:Operations:0:Paths:0"] = "/api/**",
            });

        var open = new HttpRequestMessage(
            HttpMethod.Get, new Uri(new Uri("http://proxy"), new Uri(wirePath, UriKind.Relative)));
        open.Headers.Add("X-CredProx-Key", KeyA);
        Assert.Equal(HttpStatusCode.OK, (await openHost.GetTestClient().SendAsync(open)).StatusCode);
        Assert.Equal(expectedForwarded, Assert.Single(_upstreamPaths));
    }

    [Fact]
    public async Task AnonymousRoute_ServesWithoutKey()
    {
        ResetUpstream();
        var anonymousRoute = new RouteConfig
        {
            RouteId = "acme",
            ClusterId = "acme",
            Match = new RouteMatch { Path = "/api/{**catch-all}" },
            Metadata = new Dictionary<string, string>
            {
                [CredProxMetadata.Destination] = "acme",
                [CredProxMetadata.Caller] = "anonymous",
            },
        };

        var (host, _) = StartProxyHost([anonymousRoute], [AcmeCluster]);
        var response = await host.GetTestClient().GetAsync("http://proxy/api/thing");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("/api/thing", Assert.Single(_upstreamPaths));
    }

    [Fact]
    public async Task ExpiredKey_401()
    {
        ResetUpstream();
        var (host, _) = StartProxyHost(
            [AcmeRoute],
            [AcmeCluster],
            new Dictionary<string, string?>
            {
                ["CredProx:Callers:app-a:Keys:0:ExpiresAt"] = "2020-01-01T00:00:00+00:00",
            });

        var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy/api/thing");
        request.Headers.Add("X-CredProx-Key", KeyA);
        var response = await host.GetTestClient().SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Empty(_upstreamPaths);
    }

    [Fact]
    public async Task RotatedKeys_BothValuesAuthenticate()
    {
        ResetUpstream();
        var (host, _) = StartProxyHost(
            [AcmeRoute],
            [AcmeCluster],
            new Dictionary<string, string?>
            {
                ["CredProx:Callers:app-a:Keys:1:KeyId"] = "k2",
                ["CredProx:Callers:app-a:Keys:1:KeyHash"] = Hash(KeyB),
            });

        foreach (var key in new[] { KeyA, KeyB })
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy/api/thing");
            request.Headers.Add("X-CredProx-Key", key);
            Assert.Equal(HttpStatusCode.OK, (await host.GetTestClient().SendAsync(request)).StatusCode);
        }

        // Same caller, one cache entry: the second request reused the first token.
        Assert.Single(_tokenHandler.Requests);
        Assert.Equal(2, _upstreamPaths.Count);
    }

    private static string Hash(string keyValue) =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(keyValue))).ToLowerInvariant();
}
