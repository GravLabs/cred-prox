using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using CredProx;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Xunit;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;

namespace CredProx.Tests;

/// <summary>
/// The M4 request path end to end: a real YARP pipeline (transforms, forwarder, client
/// factory) with the transport swapped for the in-process upstream. Asserts the §3.4
/// failure semantics against the real forwarder — a short-circuited request is never
/// forwarded and never calls the token endpoint — plus the happy path, header hygiene,
/// credential failure and refresh-on-401.
/// </summary>
public sealed class CredProxPipelineIntegrationTests : IAsyncLifetime
{
    private readonly StubHttpHandler _tokenHandler;
    private readonly IHost _upstream;
    private readonly List<string> _upstreamPaths = [];
    private readonly List<Dictionary<string, string?>> _upstreamHeaders = [];
    private Queue<HttpStatusCode> _upstreamStatuses = new([HttpStatusCode.OK]);

    // M20: tests that need a reflecting upstream (error pages echoing the request,
    // §8.2) install a responder; the default one answers "upstream-ok".
    private Func<HttpContext, Task>? _upstreamResponder;

    public CredProxPipelineIntegrationTests()
    {
        var tokens = new Queue<string>(["token-1", "token-2", "token-3"]);
        _tokenHandler = new StubHttpHandler((_, _) =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    $$"""{"access_token":"{{tokens.Dequeue()}}","expires_in":3600}"""),
            });

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
                        ["X-API-Key"] = context.Request.Headers["X-API-Key"],
                        ["X-Env"] = context.Request.Headers["X-Env"],
                    });
                    context.Response.StatusCode = (int)_upstreamStatuses.Dequeue();
                    if (_upstreamResponder is { } responder)
                    {
                        return responder(context);
                    }

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

    private void ResetUpstream(params HttpStatusCode[] statuses)
    {
        _upstreamPaths.Clear();
        _upstreamHeaders.Clear();
        _upstreamStatuses = new Queue<HttpStatusCode>(statuses);
        _upstreamResponder = null;
    }

    private IHost StartProxyHost(
        IReadOnlyList<RouteConfig> routes,
        IReadOnlyList<ClusterConfig> clusters,
        Dictionary<string, string?>? credProxEntries = null,
        HttpMessageHandler? tokenTransport = null,
        Action<IServiceCollection>? credentialTypes = null,
        Action<IServiceCollection>? configureServices = null)
    {
        var entries = new Dictionary<string, string?>
        {
            ["CredProx:Destinations:acme:Template"] = "http://upstream.example/{partition}",
            ["CredProx:Destinations:acme:Partition"] = "header:X-Env",
            ["CredProx:Destinations:acme:Allowed:0"] = "prod",
            ["CredProx:Destinations:acme:StripHeader"] = "true",
            ["CredProx:Credentials:contoso:Type"] = "OAuthClientCredentials",
            ["CredProx:Credentials:contoso:TokenEndpoint"] = "http://token.example/token",
            ["CredProx:Credentials:contoso:ClientAuthentication"] = "FormPost",
            ["CredProx:Credentials:contoso:ClientId"] = "secret:cid",
            ["CredProx:Credentials:contoso:ClientSecret"] = "secret:csec",
            ["CredProx:Secrets:cid"] = "cid",
            ["CredProx:Secrets:csec"] = "csec",
        };
        if (credProxEntries is not null)
        {
            foreach (var (key, value) in credProxEntries)
            {
                entries[key] = value;
            }
        }

        var transport = _upstream.GetTestServer().CreateHandler();
        var tokenHandler = tokenTransport ?? _tokenHandler;

        return new HostBuilder()
            .ConfigureAppConfiguration(build => build.AddInMemoryCollection(entries))
            .ConfigureServices((context, services) =>
            {
                services.AddCredProxTokenCache();
                services.AddCredProxConfigurationSecrets(context.Configuration);
                services.AddCredProxBuiltInCredentials();
                credentialTypes?.Invoke(services);
                services.AddCredProxCredentials(context.Configuration);
                services.AddRouting();
                services.AddReverseProxy().LoadFromMemory(routes, clusters).AddCredProx(context.Configuration);
                configureServices?.Invoke(services); // plugin registrations land after the built-ins

                // The token endpoint runs in-process too.
                services.AddHttpClient(CredProxHttpClientNames.TokenClient)
                    .ConfigurePrimaryHttpMessageHandler(() => tokenHandler);

                // The forwarder's transport is the in-process upstream; the CredProx
                // pipeline still composes over it (the plan's subclass extension point).
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

    [Fact]
    public async Task HappyPath_PartitionedDestinationCredentialAttachedHeadersClean()
    {
        ResetUpstream(HttpStatusCode.OK);
        using var host = StartProxyHost([AcmeRoute], [AcmeCluster]);

        var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy/api/thing");
        request.Headers.Add("X-Env", "prod");
        request.Headers.Add("X-API-Key", "caller-key");
        var response = await host.GetTestClient().SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var upstreamHeaders = Assert.Single(_upstreamHeaders);
        Assert.Equal("Bearer token-1", upstreamHeaders["Authorization"]);
        Assert.True(string.IsNullOrEmpty(upstreamHeaders["X-API-Key"])); // never forwarded
        Assert.True(string.IsNullOrEmpty(upstreamHeaders["X-Env"]));     // StripHeader
        Assert.Contains("/prod", Assert.Single(_upstreamPaths));         // template expanded
        Assert.Contains("/api/thing", Assert.Single(_upstreamPaths));
    }

    [Fact]
    public async Task DisallowedPartition_400Problem_NoForwardNoToken()
    {
        ResetUpstream();
        using var host = StartProxyHost([AcmeRoute], [AcmeCluster]);

        var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy/api/thing");
        request.Headers.Add("X-Env", "attacker.com");
        var response = await host.GetTestClient().SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType!.MediaType);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("credprox.partition_not_allowed", body);
        Assert.DoesNotContain("attacker.com", body);
        Assert.Empty(_upstreamPaths);          // the forwarder never ran
        Assert.Empty(_tokenHandler.Requests);  // no token fetched for a rejected request
    }

    [Fact]
    public void KillSwitch_InvalidSection_FailsHostStartup()
    {
        // The startup validator binds the switch eagerly: a section that refuses
        // validation never leaves a host running with an unarmed switch.
        var ex = Record.Exception(() => StartProxyHost(
            [AcmeRoute], [AcmeCluster], new Dictionary<string, string?>
            {
                ["CredProx:KillSwitch:Clusters:acme"] = "true",
            }));

        Assert.IsAssignableFrom<OptionsValidationException>(ex?.GetBaseException() ?? ex);
    }

    [Fact]
    public async Task KillSwitch_ClusterDisabled_503Problem_NoForwardNoToken()
    {
        ResetUpstream();
        using var host = StartProxyHost([AcmeRoute], [AcmeCluster], new Dictionary<string, string?>
        {
            ["CredProx:KillSwitch:Clusters:0"] = "acme",
        });

        var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy/api/thing");
        request.Headers.Add("X-Env", "prod"); // well-formed: the switch alone rejects it
        var response = await host.GetTestClient().SendAsync(request);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType!.MediaType);
        Assert.Contains("credprox.vendor_disabled", await response.Content.ReadAsStringAsync());
        Assert.Empty(_upstreamPaths);         // the forwarder never ran
        Assert.Empty(_tokenHandler.Requests); // and no token endpoint was called (§3.4)
    }

    [Fact]
    public async Task MissingPartition_400Problem_NoForward()
    {
        ResetUpstream();
        using var host = StartProxyHost([AcmeRoute], [AcmeCluster]);

        var response = await host.GetTestClient().GetAsync("http://proxy/api/thing");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("credprox.partition_not_allowed", await response.Content.ReadAsStringAsync());
        Assert.Empty(_upstreamPaths);
    }

    [Fact]
    public async Task CredentialUnavailable_502Problem_NoForward()
    {
        ResetUpstream();
        // The token endpoint is up but failing: acquisition throws at request time.
        // (An unresolvable secret reference is a startup failure, not a request failure —
        // see CredProxStartupValidatorTests.)
        using var failingTokens = new StubHttpHandler(
            HttpStatusCode.InternalServerError, "token store down");
        using var host = StartProxyHost(
            [AcmeRoute], [AcmeCluster], tokenTransport: failingTokens);

        var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy/api/thing");
        request.Headers.Add("X-Env", "prod");
        var response = await host.GetTestClient().SendAsync(request);

        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("credprox.credential_unavailable", body);
        Assert.DoesNotContain("token store down", body); // provider error text stays internal
        Assert.Empty(_upstreamPaths);
        Assert.Single(failingTokens.Requests); // one acquisition attempt, no retry storm
    }

    [Fact]
    public async Task Upstream401_RefreshesInvalidatesAndRetriesOnce()
    {
        ResetUpstream(HttpStatusCode.Unauthorized, HttpStatusCode.OK);
        using var host = StartProxyHost([AcmeRoute], [AcmeCluster]);

        var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy/api/thing");
        request.Headers.Add("X-Env", "prod");
        var response = await host.GetTestClient().SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(2, _upstreamPaths.Count);
        Assert.Equal("Bearer token-1", _upstreamHeaders[0]["Authorization"]);
        Assert.Equal("Bearer token-2", _upstreamHeaders[1]["Authorization"]); // fresh after invalidate
        Assert.Equal(2, _tokenHandler.Requests.Count); // cache entry was dropped, then refetched
    }

    // ---- M19 consent signalling (§8.3) ----

    // An E10-style plugin type: no token endpoint involved — the provider itself knows
    // the user has not consented yet and says so with the typed signal.
    public sealed class ConsentPluginOptions : IHasAttachment
    {
        CredentialLocation IHasAttachment.Location => CredentialLocation.Header;

        string IHasAttachment.Name => "X-Consent";

        string? IHasAttachment.Prefix => null;
    }

    public sealed class ConsentPluginProvider : ICredentialProvider<ConsentPluginOptions>
    {
        public string Type => "Consent";

        public ValueTask<string> GetCredentialAsync(
            ConsentPluginOptions options,
            ISecretAccessor secrets,
            CredentialRequestContext context,
            CancellationToken cancellationToken) =>
            throw new ConsentRequiredException(
                "https://id.example/authorize?client_id=demo&state=xyz",
                "ConsentPlugin needs user consent.");
    }

    private static readonly RouteConfig ConsentRoute = new()
    {
        RouteId = "consent",
        ClusterId = "acme",
        Match = new RouteMatch { Path = "/api/{**catch-all}" },
        Metadata = new Dictionary<string, string>
        {
            [CredProxMetadata.Destination] = "acme",
            [CredProxMetadata.Credential] = "consent",
        },
    };

    [Fact]
    public async Task ConsentPlugin_401ConsentProblem_WithAuthorizeUrl_NoForwardNoToken()
    {
        ResetUpstream();
        using var host = StartProxyHost(
            [ConsentRoute],
            [AcmeCluster],
            new Dictionary<string, string?> { ["CredProx:Credentials:consent:Type"] = "Consent" },
            credentialTypes: services =>
                services.AddCredProxCredentialType<ConsentPluginProvider, ConsentPluginOptions>("Consent"));

        var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy/api/thing");
        request.Headers.Add("X-Env", "prod");
        var response = await host.GetTestClient().SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var body = await response.Content.ReadAsStringAsync();
        using var problem = JsonDocument.Parse(body);
        var extensions = problem.RootElement.GetProperty("extensions");
        Assert.Equal("credprox.consent_required", extensions.GetProperty("code").GetString());
        // The member rides decoded JSON — what the caller opens, character-exact.
        Assert.Equal(
            "https://id.example/authorize?client_id=demo&state=xyz",
            extensions.GetProperty("authorize_url").GetString());
        Assert.DoesNotContain("ConsentPlugin needs user consent", body, StringComparison.Ordinal);

        Assert.Empty(_upstreamPaths);          // the request never left the proxy
        Assert.Empty(_tokenHandler.Requests);  // no token endpoint was consulted
    }

    [Fact]
    public async Task ConsentDuringRefreshOn401_UpstreamUnauthorizedReturned_Not500()
    {
        // The built-in OAuth credential reports consent on the refresh fetch only: the
        // second token call says consent is required. The caller keeps the upstream's
        // own 401 (§8.3) — never a 500, never a retried request.
        ResetUpstream(HttpStatusCode.Unauthorized);
        using var consentOnRefresh = new StubHttpHandler((_, index) => index == 0
            ? new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"access_token":"token-1","expires_in":3600}"""),
            }
            : throw new ConsentRequiredException("https://id.example/authorize", "consent"));
        using var host = StartProxyHost([AcmeRoute], [AcmeCluster], tokenTransport: consentOnRefresh);

        var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy/api/thing");
        request.Headers.Add("X-Env", "prod");
        var response = await host.GetTestClient().SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("credprox.consent_required", body); // the upstream's own answer rides on
        Assert.Single(_upstreamPaths);                   // the retry never went out
        Assert.Equal(2, consentOnRefresh.Requests.Count); // initial acquire + refresh attempt
    }

    [Fact]
    public async Task RouteWithoutCredProxMetadata_NoCredentialNoDestinationRewrite()
    {
        ResetUpstream(HttpStatusCode.OK);
        var plainRoute = new RouteConfig
        {
            RouteId = "plain",
            ClusterId = "plain",
            Match = new RouteMatch { Path = "/plain/{**catch-all}" },
        };
        var plainCluster = new ClusterConfig
        {
            ClusterId = "plain",
            Destinations = new Dictionary<string, DestinationConfig>
            {
                ["static"] = new() { Address = "http://upstream.example/" },
            },
        };

        using var host = StartProxyHost([plainRoute], [plainCluster]);
        var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy/plain/thing");
        request.Headers.Add("X-API-Key", "caller-key");
        var response = await host.GetTestClient().SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var headers = Assert.Single(_upstreamHeaders);
        // The caller key never reaches any upstream, whatever the route (§3.2) — but no
        // credential is attached and the cluster's static address is used untouched.
        Assert.True(string.IsNullOrEmpty(headers["X-API-Key"]));
        Assert.True(string.IsNullOrEmpty(headers["Authorization"]));
        Assert.Equal("/plain/thing", Assert.Single(_upstreamPaths));
    }

    // ---- M20: response secret scrubbing (§8.2), end to end over the real pipeline ----

    /// <summary>
    /// An upstream that reflects the injected Authorization header into its body.
    /// The content type must be set explicitly before the first write: TestServer's
    /// in-memory transport loses the type <c>WriteAsync</c> infers after headers close.
    /// </summary>
    private void EchoAuthorizationIntoBody() =>
        _upstreamResponder = async context =>
        {
            context.Response.ContentType = "text/plain";
            await context.Response.WriteAsync(
                $"error page: you sent {context.Request.Headers.Authorization}");
        };

    private HttpRequestMessage AcmeRequest()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy/api/thing");
        request.Headers.Add("X-Env", "prod");
        return request;
    }

    [Fact]
    public async Task UpstreamEchoesToken_IntoBody_CallerSeesRedaction()
    {
        ResetUpstream(HttpStatusCode.OK);
        EchoAuthorizationIntoBody();
        using var host = StartProxyHost([AcmeRoute], [AcmeCluster]);

        var response = await host.GetTestClient().SendAsync(AcmeRequest());

        var body = await response.Content.ReadAsStringAsync();
        Assert.Equal("error page: you sent Bearer [redacted]", body);
        Assert.DoesNotContain("token-1", body, StringComparison.Ordinal);
        // The text framing survives, and the framing length describes the scrubbed
        // body — never the upstream one (the feature drops the stale length; the proxy
        // re-frames).
        Assert.Equal("text/plain", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal(Encoding.UTF8.GetByteCount("error page: you sent Bearer [redacted]"),
            response.Content.Headers.ContentLength);
    }

    /// <summary>
    /// M22: an SSE response survives the live pipeline with its event framing intact
    /// and the echoed token removed event-by-event. (E13's smoke proves the timing
    /// guarantee; this proves the scrubbing on the real dispatch path.)
    /// </summary>
    [Fact]
    public async Task UpstreamStreamsEvents_WithEchoedToken_CallerSeesRedactedEvents()
    {
        ResetUpstream(HttpStatusCode.OK);
        _upstreamResponder = async context =>
        {
            context.Response.ContentType = "text/event-stream";
            await context.Response.WriteAsync(
                $"event: auth_echo\ndata: you sent {context.Request.Headers.Authorization}\n\n");
            await context.Response.Body.FlushAsync();
            await context.Response.WriteAsync("data: done\n\n");
        };
        using var host = StartProxyHost([AcmeRoute], [AcmeCluster]);

        var response = await host.GetTestClient().SendAsync(AcmeRequest());

        var body = await response.Content.ReadAsStringAsync();
        Assert.Equal("event: auth_echo\ndata: you sent Bearer [redacted]\n\ndata: done\n\n", body);
        Assert.DoesNotContain("token-1", body, StringComparison.Ordinal);
        Assert.Equal("text/event-stream", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task UpstreamEchoesToken_IntoHeaders_Scrubbed_MultiValueKept()
    {
        ResetUpstream(HttpStatusCode.OK);
        _upstreamResponder = async context =>
        {
            var auth = context.Request.Headers.Authorization.ToString();
            context.Response.Headers["X-Echo"] = auth;
            context.Response.Headers.Append("Set-Cookie", "session=abc; Path=/");
            context.Response.Headers.Append("Set-Cookie", $"sid={auth}; HttpOnly");
            context.Response.ContentType = "text/plain";
            await context.Response.WriteAsync("ok");
        };
        using var host = StartProxyHost([AcmeRoute], [AcmeCluster]);

        var response = await host.GetTestClient().SendAsync(AcmeRequest());

        Assert.Equal("Bearer [redacted]", Assert.Single(response.Headers.GetValues("X-Echo")));
        var cookies = response.Headers.GetValues("Set-Cookie").ToList();
        Assert.Equal(["session=abc; Path=/", "sid=Bearer [redacted]; HttpOnly"], cookies);
        Assert.Equal("ok", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task GzipEchoedToken_DecodedScrubbed_ForwardedPlain()
    {
        ResetUpstream(HttpStatusCode.OK);
        _upstreamResponder = async context =>
        {
            context.Response.ContentType = "text/plain";
            context.Response.Headers.ContentEncoding = "gzip";
            await using var gzip = new GZipStream(
                context.Response.Body, CompressionMode.Compress, leaveOpen: true);
            await gzip.WriteAsync(Encoding.UTF8.GetBytes(
                $"stack trace: {context.Request.Headers.Authorization} crashed"));
        };
        using var host = StartProxyHost([AcmeRoute], [AcmeCluster]);

        var response = await host.GetTestClient().SendAsync(AcmeRequest());

        var body = await response.Content.ReadAsStringAsync();
        Assert.Equal("stack trace: Bearer [redacted] crashed", body);
        // Forwarded decompressed: the encoding header describes bytes that are gone.
        Assert.Empty(response.Content.Headers.ContentEncoding);
        Assert.Equal("text/plain", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task ScrubbingDisabled_EchoPassesThrough()
    {
        ResetUpstream(HttpStatusCode.OK);
        EchoAuthorizationIntoBody();
        using var host = StartProxyHost(
            [AcmeRoute],
            [AcmeCluster],
            new Dictionary<string, string?> { ["CredProx:Scrubbing:Enabled"] = "false" });

        var response = await host.GetTestClient().SendAsync(AcmeRequest());

        // The documented opt-out: the host accepts the echo as-is.
        Assert.Equal("error page: you sent Bearer token-1", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task RefreshedToken_AlsoScrubbed_OldAndNewBothRegistered()
    {
        // 401 → refresh → the second attempt's token is the one reflected back.
        ResetUpstream(HttpStatusCode.Unauthorized, HttpStatusCode.OK);
        EchoAuthorizationIntoBody();
        using var host = StartProxyHost([AcmeRoute], [AcmeCluster]);

        var response = await host.GetTestClient().SendAsync(AcmeRequest());

        var body = await response.Content.ReadAsStringAsync();
        Assert.Equal("error page: you sent Bearer [redacted]", body);
        Assert.DoesNotContain("token-2", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task BinaryEcho_NotScrubbed_ByteIdentical()
    {
        ResetUpstream(HttpStatusCode.OK);
        _upstreamResponder = async context =>
        {
            context.Response.ContentType = "application/octet-stream";
            await context.Response.Body.WriteAsync(Encoding.UTF8.GetBytes(
                "file says: " + context.Request.Headers.Authorization + " end"));
        };
        using var host = StartProxyHost([AcmeRoute], [AcmeCluster]);

        var response = await host.GetTestClient().SendAsync(AcmeRequest());

        // Documented residue (§8.2): byte-level scrubbing stops at binary content —
        // the body must still flow through untouched, length included.
        var body = await response.Content.ReadAsByteArrayAsync();
        Assert.Equal("file says: Bearer token-1 end"u8.ToArray(), body);
    }

    [Fact]
    public async Task PluginResponseFeature_IsDispatched_AfterTheBuiltInScrubber()
    {
        ResetUpstream(HttpStatusCode.OK);
        EchoAuthorizationIntoBody();
        using var host = StartProxyHost(
            [AcmeRoute],
            [AcmeCluster],
            configureServices: services => services.AddSingleton<IResponseFeature, MarkerResponseFeature>());

        var response = await host.GetTestClient().SendAsync(AcmeRequest());

        // The advertised contract is real: an IResponseFeature plugin runs on the way out.
        Assert.Equal("ran", Assert.Single(response.Headers.GetValues("X-Test-ResponseFeature")));
        // Built-ins are registered first and share the stage → scrubber ran before it.
        Assert.DoesNotContain("token-1", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public void DiResolvesPipelineWithBuiltInResponseFeatures()
    {
        using var host = StartProxyHost([AcmeRoute], [AcmeCluster]);

        var pipeline = host.Services.GetRequiredService<CredProxPipeline>();

        // M24's ordering guarantee, structural: the same-stage features keep
        // registration order, so vendor_detail can only ever embed scrubbed bytes.
        Assert.Equal(
            [typeof(ResponseScrubFeature), typeof(ErrorNormalisationFeature)],
            pipeline.ResponseFeatures.Select(feature => feature.GetType()).ToArray());
    }

    // ---- M24: vendor error normalisation (§8.5), end to end over the real pipeline ----

    [Fact]
    public async Task VendorError_CallerSeesProblemWithScrubbedVendorDetail()
    {
        // The scrubber→normaliser chain on the live path: the vendor reflects the
        // injected token into its JSON error body; the caller's problem document
        // carries the already-redacted payload and never the token.
        ResetUpstream(HttpStatusCode.BadRequest);
        _upstreamResponder = async context =>
        {
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                "{\"error\":\"auth_failed\",\"echo\":\"" + context.Request.Headers.Authorization + "\"}");
        };
        using var host = StartProxyHost([AcmeRoute], [AcmeCluster]);

        var response = await host.GetTestClient().SendAsync(AcmeRequest());

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode); // status preserved
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("token-1", body, StringComparison.Ordinal);
        using var problem = JsonDocument.Parse(body);
        var root = problem.RootElement;
        Assert.Equal("urn:credprox:errors:vendor", root.GetProperty("type").GetString());
        Assert.Equal(400, root.GetProperty("status").GetInt32());
        var extensions = root.GetProperty("extensions");
        Assert.Equal("credprox.vendor_error", extensions.GetProperty("code").GetString());
        Assert.Equal(
            "Bearer [redacted]",
            extensions.GetProperty("vendor_detail").GetProperty("echo").GetString());
    }

    [Fact]
    public async Task GzipVendorError_DecodedScrubbed_Normalised()
    {
        ResetUpstream(HttpStatusCode.InternalServerError);
        _upstreamResponder = async context =>
        {
            context.Response.ContentType = "text/plain";
            context.Response.Headers.ContentEncoding = "gzip";
            await using var gzip = new GZipStream(
                context.Response.Body, CompressionMode.Compress, leaveOpen: true);
            await gzip.WriteAsync(Encoding.UTF8.GetBytes(
                "vendor stack: " + context.Request.Headers.Authorization + " crashed"));
        };
        using var host = StartProxyHost([AcmeRoute], [AcmeCluster]);

        var response = await host.GetTestClient().SendAsync(AcmeRequest());

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("token-1", body, StringComparison.Ordinal);
        using var problem = JsonDocument.Parse(body);
        Assert.Equal(
            "vendor stack: Bearer [redacted] crashed",
            problem.RootElement.GetProperty("extensions").GetProperty("vendor_detail").GetString());
    }

    [Fact]
    public async Task VendorErrorOptOutRoute_VendorBodyFlowsAsWritten()
    {
        var optOutRoute = new RouteConfig
        {
            RouteId = "acme-raw",
            ClusterId = "acme",
            Match = new RouteMatch { Path = "/raw/{**catch-all}" },
            Metadata = new Dictionary<string, string>
            {
                [CredProxMetadata.Destination] = "acme",
                [CredProxMetadata.Credential] = "contoso",
                [CredProxMetadata.ErrorNormalisation] = ErrorNormalisationFeature.OptOutValue,
            },
        };
        ResetUpstream(HttpStatusCode.BadRequest);
        _upstreamResponder = async context =>
        {
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("""{"vendor":"own shape","code":17}""");
        };
        using var host = StartProxyHost([optOutRoute], [AcmeCluster]);

        var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy/raw/thing");
        request.Headers.Add("X-Env", "prod");
        var response = await host.GetTestClient().SendAsync(request);

        // Byte-identical: the vendor's body, the vendor's content type, no problem wrap.
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal("""{"vendor":"own shape","code":17}""", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task NonUtf8CharsetVendorError_FlowsByteIdentical()
    {
        // F1 (M24 review) on the live path: a declared latin-1 body is never read as
        // UTF-8 — the caller receives the vendor's exact bytes, 0xFC included, where a
        // UTF-8 read would have written U+FFFD into the "lossless" embed.
        ResetUpstream(HttpStatusCode.BadRequest);
        var latin1 = new byte[] { (byte)'F', (byte)'e', 0xFC, (byte)'h', (byte)'l', (byte)'e', (byte)'r' };
        _upstreamResponder = async context =>
        {
            context.Response.ContentType = "text/plain; charset=iso-8859-1";
            await context.Response.Body.WriteAsync(latin1);
        };
        using var host = StartProxyHost([AcmeRoute], [AcmeCluster]);

        var response = await host.GetTestClient().SendAsync(AcmeRequest());

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("iso-8859-1", response.Content.Headers.ContentType?.CharSet);
        Assert.Equal(latin1, await response.Content.ReadAsByteArrayAsync());
    }

    [Fact]
    public async Task Utf8CharsetVendorError_StillNormalises()
    {
        // The control beside it: an explicit utf-8 charset stays in the normalising set.
        ResetUpstream(HttpStatusCode.BadRequest);
        _upstreamResponder = async context =>
        {
            context.Response.ContentType = "text/plain; charset=utf-8";
            await context.Response.WriteAsync("ungültig");
        };
        using var host = StartProxyHost([AcmeRoute], [AcmeCluster]);

        var response = await host.GetTestClient().SendAsync(AcmeRequest());

        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(
            "ungültig",
            problem.RootElement.GetProperty("extensions").GetProperty("vendor_detail").GetString());
    }

    [Fact]
    public async Task VendorErrorBeyondCap_VendorBodyFlowsUntouched()
    {
        // The Errors section binds on the real host, cap included: this body is over it,
        // so the caller gets the vendor's page rather than a truncated document.
        ResetUpstream(HttpStatusCode.BadGateway);
        var page = new string('x', 200);
        _upstreamResponder = async context =>
        {
            context.Response.ContentType = "text/html";
            await context.Response.WriteAsync(page);
        };
        using var host = StartProxyHost(
            [AcmeRoute],
            [AcmeCluster],
            new Dictionary<string, string?> { ["CredProx:Errors:MaxNormalisedBodyBytes"] = "64" });

        var response = await host.GetTestClient().SendAsync(AcmeRequest());

        Assert.Equal(page, await response.Content.ReadAsStringAsync());
        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task ErrorsGloballyOff_VendorErrorFlowsUntouched()
    {
        ResetUpstream(HttpStatusCode.InternalServerError);
        EchoAuthorizationIntoBodyError();
        using var host = StartProxyHost(
            [AcmeRoute],
            [AcmeCluster],
            new Dictionary<string, string?> { ["CredProx:Errors:Enabled"] = "false" });

        var response = await host.GetTestClient().SendAsync(AcmeRequest());

        // Scrubbing still applies (it is the other feature's call); only the wrap is off.
        Assert.Equal("vendor error: Bearer [redacted]", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task ProxyProblem_CarriesProxyErrorType()
    {
        ResetUpstream();
        using var host = StartProxyHost([AcmeRoute], [AcmeCluster]);

        var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy/api/thing");
        request.Headers.Add("X-Env", "attacker.com"); // proxy-side 400, never vendor-side
        var response = await host.GetTestClient().SendAsync(request);

        using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("urn:credprox:errors:proxy", problem.RootElement.GetProperty("type").GetString());
        Assert.Equal(
            "credprox.partition_not_allowed",
            problem.RootElement.GetProperty("extensions").GetProperty("code").GetString());
    }

    /// <summary>An upstream error page echoing the Authorization header (error status).</summary>
    private void EchoAuthorizationIntoBodyError() =>
        _upstreamResponder = async context =>
        {
            context.Response.ContentType = "text/plain";
            await context.Response.WriteAsync("vendor error: " + context.Request.Headers.Authorization);
        };

    private sealed class MarkerResponseFeature : IResponseFeature
    {
        public ValueTask ApplyAsync(HttpContext context, CancellationToken cancellationToken)
        {
            context.Features.Get<CredProxRequestState>()?.ProxyResponse?
                .Headers.TryAddWithoutValidation("X-Test-ResponseFeature", "ran");
            return ValueTask.CompletedTask;
        }
    }
}
