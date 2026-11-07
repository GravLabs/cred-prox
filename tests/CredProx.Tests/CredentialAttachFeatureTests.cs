using System.Net.Http;
using System.Text.Json;
using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The <see cref="Stage.AttachCredential"/> feature (§3.2/§3.4): the credential value is
/// placed on the outbound request (replacing, never merging, a caller-supplied
/// <c>Authorization</c>), the refresh targets are stashed for the cluster handler, an
/// unobtainable credential answers <c>502 credprox.credential_unavailable</c> without a
/// forward, and the credential's own allow-list gates its endpoint and cache key.
/// </summary>
public sealed class CredentialAttachFeatureTests
{
    private sealed class RecordingCache : ITokenCache
    {
        public List<(string Credential, string? Partition)> Invalidations { get; } = [];

        public ValueTask<string> GetTokenAsync(
            string credential,
            string? partition,
            Func<CancellationToken, ValueTask<(string Value, DateTimeOffset ExpiresAt)>> acquire,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException("the attach feature does not acquire through the cache directly");

        public void Invalidate(string credential, string? partition) =>
            Invalidations.Add((credential, partition));
    }

    public sealed class RecordingOptions : IHasAttachment, IHasPartitionConfig, IHasConnection
    {
        public string Value { get; set; } = "recorded-token";

        public PartitionConfigOptions? Partition { get; set; }

        public string? Connection { get; set; }

        CredentialLocation IHasAttachment.Location => CredentialLocation.Header;

        string IHasAttachment.Name => "X-Recorded";

        string? IHasAttachment.Prefix => null;
    }

    public sealed class RecordingProvider : ICredentialProvider<RecordingOptions>
    {
        public string Type => "Recording";

        public List<CredentialRequestContext> Contexts { get; } = [];

        public Exception? FailWith { get; set; }

        public ValueTask<string> GetCredentialAsync(
            RecordingOptions options,
            ISecretAccessor secrets,
            CredentialRequestContext context,
            CancellationToken cancellationToken)
        {
            Contexts.Add(context);
            if (FailWith is not null)
            {
                throw FailWith;
            }

            return new ValueTask<string>(options.Value);
        }
    }

    private readonly RecordingCache _cache = new();

    private (ServiceProvider Services, CredentialAttachFeature Feature, RecordingProvider Provider) Build(
        params (string Key, string? Value)[] credProxEntries)
    {
        var configuration = TestConfig.Root(
            credProxEntries.Select(e => ("CredProx:" + e.Key, e.Value)).ToArray());

        var services = new ServiceCollection();
        services.AddCredProxTokenCache();
        services.AddCredProxConfigurationSecrets(configuration);
        services.AddCredProxBuiltInCredentials();
        services.AddCredProxCredentialType<RecordingProvider, RecordingOptions>("Recording");
        services.AddCredProxCredentials(configuration);
        services.AddSingleton<ITokenCache>(_cache);
        var provider = services.BuildServiceProvider();

        var feature = new CredentialAttachFeature(
            provider.GetRequiredService<CredentialRegistryProvider>(),
            _cache,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<CredentialAttachFeature>.Instance);
        return (provider, feature, provider.GetRequiredService<RecordingProvider>());
    }

    private static readonly Dictionary<string, string> AttachRoute =
        new() { [CredProxMetadata.Credential] = "contoso" };

    [Fact]
    public async Task StaticKey_IsAttachedAndTargetsAreStashed()
    {
        var (_, feature, _) = Build(
            ("Credentials:contoso:Type", "StaticKey"),
            ("Credentials:contoso:Secret", "secret:contoso-key"),
            ("Credentials:contoso:Name", "X-Contoso-Token"),
            ("Secrets:contoso-key", "contoso-secret-value"));

        var context = M4Contexts.Create(out var proxyRequest, AttachRoute);

        await feature.ApplyAsync(context, default);

        var state = context.Features.Get<CredProxRequestState>()!;
        Assert.False(state.IsAborted);
        Assert.Equal("contoso-secret-value", Assert.Single(proxyRequest.Headers.GetValues("X-Contoso-Token")));

        // The refresh-on-401 handler resolves its targets from the outbound message.
        Assert.True(proxyRequest.Options.TryGetValue(
            CredProxRequestOptions.TokenRefresh, out var targets));
        Assert.NotNull(targets);
    }

    [Fact]
    public async Task CallerAuthorization_IsReplacedNotMerged()
    {
        var (_, feature, _) = Build(
            ("Credentials:contoso:Type", "StaticKey"),
            ("Credentials:contoso:Secret", "secret:contoso-key"),
            ("Credentials:contoso:Name", "Authorization"),
            ("Credentials:contoso:Prefix", "Bearer "),
            ("Secrets:contoso-key", "contoso-secret-value"));

        var context = M4Contexts.Create(out var proxyRequest, AttachRoute);
        proxyRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", "caller-stuff");

        await feature.ApplyAsync(context, default);

        Assert.Equal("Bearer contoso-secret-value", proxyRequest.Headers.Authorization!.ToString());
    }

    [Fact]
    public async Task CookiePlacement_CallerCookiesReplacedEntirely()
    {
        var (_, feature, _) = Build(
            ("Credentials:contoso:Type", "StaticKey"),
            ("Credentials:contoso:Secret", "secret:contoso-key"),
            ("Credentials:contoso:Location", "Cookie"),
            ("Credentials:contoso:Name", "CRMSESSION"),
            ("Secrets:contoso-key", "contoso-session-value"));

        var context = M4Contexts.Create(out var proxyRequest, AttachRoute);
        proxyRequest.Headers.Add("Cookie", "theme=dark; CRMSESSION=caller-forged");

        await feature.ApplyAsync(context, default);

        var state = context.Features.Get<CredProxRequestState>()!;
        Assert.False(state.IsAborted);

        // The caller's own cookies never ride along to the vendor (§8.1, cookie hygiene).
        Assert.Equal(
            "CRMSESSION=contoso-session-value",
            Assert.Single(proxyRequest.Headers.GetValues("Cookie")));

        // And the value that went on the wire is registered for response scrubbing (M20).
        var injected = CredProxInjectedSecrets.GetOrCreate(context);
        Assert.Contains("contoso-session-value", injected.Values);
    }

    [Fact]
    public async Task UnobtainableCredential_Aborts502WithoutLeakingTheFailure()
    {
        var (_, feature, recording) = Build(("Credentials:contoso:Type", "Recording"));
        recording.FailWith = new InvalidOperationException("vendor said no for secret-value-xyz");

        var context = M4Contexts.Create(out var proxyRequest, AttachRoute);

        await feature.ApplyAsync(context, default);

        var state = context.Features.Get<CredProxRequestState>()!;
        Assert.True(state.IsAborted);
        Assert.Equal(502, context.Response.StatusCode);

        var body = M4Contexts.ResponseBody(context);
        using var problem = JsonDocument.Parse(body);
        Assert.Equal(
            "credprox.credential_unavailable",
            problem.RootElement.GetProperty("extensions").GetProperty("code").GetString());
        Assert.DoesNotContain("secret-value-xyz", body);
        Assert.Empty(proxyRequest.Headers); // nothing attached for a failed credential
    }

    [Fact]
    public async Task CredentialOwnAllowList_GatesItsEndpoint()
    {
        var (_, feature, recording) = Build(
            ("Credentials:contoso:Type", "Recording"),
            ("Credentials:contoso:Partition:From", "header:X-Env"),
            ("Credentials:contoso:Partition:Allowed:0", "prod"));

        var context = M4Contexts.Create(out _, AttachRoute);
        context.Request.Headers["X-Env"] = "dev";

        await feature.ApplyAsync(context, default);

        Assert.True(context.Features.Get<CredProxRequestState>()!.IsAborted);
        Assert.Equal(400, context.Response.StatusCode);
        Assert.Empty(recording.Contexts); // the provider was never reached
    }

    [Fact]
    public async Task AdmittedCredentialPartition_ReachesTheProviderContext()
    {
        var (_, feature, recording) = Build(
            ("Credentials:contoso:Type", "Recording"),
            ("Credentials:contoso:Partition:From", "header:X-Env"),
            ("Credentials:contoso:Partition:Allowed:0", "prod"));

        var context = M4Contexts.Create(out _, AttachRoute);
        context.Request.Headers["X-Env"] = "prod";

        await feature.ApplyAsync(context, default);

        Assert.Equal("prod", Assert.Single(recording.Contexts).Partition);
    }

    [Fact]
    public async Task DestinationAdmittedPartition_IsReusedByCredentialWithoutItsOwnSource()
    {
        var provider = TestProviders.Destinations(TestConfig.Root(
            ("CredProx:Destinations:acme:Template", "https://{partition}.acme.example/"),
            ("CredProx:Destinations:acme:Partition", "header:X-Env"),
            ("CredProx:Destinations:acme:Allowed:0", "prod")));

        var (_, feature, recording) = Build(("Credentials:contoso:Type", "Recording"));

        var context = M4Contexts.Create(
            out _,
            new() { [CredProxMetadata.Destination] = "acme", [CredProxMetadata.Credential] = "contoso" });
        context.Request.Headers["X-Env"] = "prod";
        await new DestinationResolutionFeature(provider).ApplyAsync(context, default);

        await feature.ApplyAsync(context, default);

        Assert.Equal("prod", Assert.Single(recording.Contexts).Partition);
    }

    [Fact]
    public async Task StashedInvalidate_DropsTheCacheEntryUnderTheAdmittedPartition()
    {
        var (_, feature, _) = Build(
            ("Credentials:contoso:Type", "Recording"),
            ("Credentials:contoso:Partition:From", "header:X-Env"),
            ("Credentials:contoso:Partition:Allowed:0", "prod"));

        var context = M4Contexts.Create(out var proxyRequest, AttachRoute);
        context.Request.Headers["X-Env"] = "prod";

        await feature.ApplyAsync(context, default);

        Assert.True(proxyRequest.Options.TryGetValue(CredProxRequestOptions.TokenRefresh, out var targets));
        targets!.Invalidate();

        Assert.Equal(("contoso", (string?)"prod"), Assert.Single(_cache.Invalidations));
    }

    // ---- F1 (M9 review): query placement on the live pipeline, where RequestUri
    // is null while features run and the state carries the final path/query ----

    private static readonly (string Key, string? Value)[] QueryKeyConfig =
    [
        ("Credentials:contoso:Type", "StaticKey"),
        ("Credentials:contoso:Secret", "secret:contoso-key"),
        ("Credentials:contoso:Name", "api_key"),
        ("Credentials:contoso:Location", "Query"),
        ("Secrets:contoso-key", "contoso-secret-value"),
    ];

    [Fact]
    public async Task QueryPlacement_LivePipelineShape_BuildsUriFromStateAndReplacesCallerValueOnce()
    {
        var (_, feature, _) = Build(QueryKeyConfig);

        var context = M4Contexts.Create(out var proxyRequest, AttachRoute);
        proxyRequest.RequestUri = null; // exactly what the live pipeline looks like here
        var state = context.Features.Get<CredProxRequestState>()!;
        state.DestinationPrefix = "https://vendor.example";
        state.OutboundPath = "/data";
        state.OutboundQuery = "?x=1&api_key=caller-value";

        await feature.ApplyAsync(context, default);

        Assert.False(state.IsAborted);
        Assert.NotNull(proxyRequest.RequestUri);
        var query = System.Web.HttpUtility.ParseQueryString(proxyRequest.RequestUri!.Query);
        Assert.Equal("contoso-secret-value", query["api_key"]); // replaced, not merged
        Assert.Equal("1", query["x"]); // pass-through preserved
        Assert.Equal(
            1,
            proxyRequest.RequestUri.Query.Split('&', StringSplitOptions.RemoveEmptyEntries)
                .Count(p => p.StartsWith("api_key=", StringComparison.Ordinal))); // exactly once
        Assert.Equal("https://vendor.example/data", proxyRequest.RequestUri.GetLeftPart(UriPartial.Path));
    }

    [Fact]
    public async Task QueryPlacement_NoDestinationPrefix_FallsBackToClusterDestinationAddress()
    {
        var (_, feature, _) = Build(QueryKeyConfig);

        var context = M4Contexts.Create(out var proxyRequest, AttachRoute);
        proxyRequest.RequestUri = null;
        var state = context.Features.Get<CredProxRequestState>()!;
        state.OutboundPath = "/data";
        // DestinationState.Model has an internal setter (YARP swaps it on config reload),
        // so the test installs the model reflectively.
        var destination = new Yarp.ReverseProxy.Model.DestinationState("d");
        typeof(Yarp.ReverseProxy.Model.DestinationState)
            .GetProperty(nameof(Yarp.ReverseProxy.Model.DestinationState.Model))!
            .SetValue(destination, new Yarp.ReverseProxy.Model.DestinationModel(
                new Yarp.ReverseProxy.Configuration.DestinationConfig { Address = "https://cluster.example/" }));
        context.Features.Get<Yarp.ReverseProxy.Model.IReverseProxyFeature>()!
            .ProxiedDestination = destination;

        await feature.ApplyAsync(context, default);

        Assert.False(state.IsAborted);
        Assert.Equal("https://cluster.example/data?api_key=contoso-secret-value", proxyRequest.RequestUri!.ToString());
    }

    [Fact]
    public async Task QueryPlacement_NoUriBuildable_Aborts502NotBare500()
    {
        // No RequestUri, no destination prefix, no selected cluster destination: the
        // placement cannot build a URI. The caller must get the documented credential
        // problem (502), not the transform provider's catch-all 500.
        var (_, feature, _) = Build(QueryKeyConfig);

        var context = M4Contexts.Create(out var proxyRequest, AttachRoute);
        proxyRequest.RequestUri = null;

        await feature.ApplyAsync(context, default);

        Assert.True(context.Features.Get<CredProxRequestState>()!.IsAborted);
        Assert.Equal(502, context.Response.StatusCode);
        var body = M4Contexts.ResponseBody(context);
        using var problem = JsonDocument.Parse(body);
        Assert.Equal(
            "credprox.credential_unavailable",
            problem.RootElement.GetProperty("extensions").GetProperty("code").GetString());
    }

    [Fact]
    public async Task QueryPlacement_MalformedDestinationPrefix_Aborts502NotBare500()
    {
        // A prefix that somehow survives startup validation must not surface as a
        // UriFormatException in the catch-all 500 (M9 review nit): URI building sits
        // inside the placement guard now.
        var (_, feature, _) = Build(QueryKeyConfig);

        var context = M4Contexts.Create(out var proxyRequest, AttachRoute);
        proxyRequest.RequestUri = null;
        var state = context.Features.Get<CredProxRequestState>()!;
        state.DestinationPrefix = "not a valid uri";
        state.OutboundPath = "/data";

        await feature.ApplyAsync(context, default);

        Assert.True(state.IsAborted);
        Assert.Equal(502, context.Response.StatusCode);
        var body = M4Contexts.ResponseBody(context);
        using var problem = JsonDocument.Parse(body);
        Assert.Equal(
            "credprox.credential_unavailable",
            problem.RootElement.GetProperty("extensions").GetProperty("code").GetString());
    }

    [Fact]
    public async Task RouteWithoutCredentialMetadata_IsLeftAlone()
    {
        var (_, feature, recording) = Build(("Credentials:contoso:Type", "Recording"));

        var context = M4Contexts.Create(out _);

        await feature.ApplyAsync(context, default);

        Assert.False(context.Features.Get<CredProxRequestState>()!.IsAborted);
        Assert.Empty(recording.Contexts);
    }

    // ---- delegated credentials (§3.6): inbound token plumbing and the two 401s ----

    public sealed class DelegatedRecordingOptions : IHasAttachment, IRequiresInboundToken
    {
        CredentialLocation IHasAttachment.Location => CredentialLocation.Header;

        string IHasAttachment.Name => "Authorization";

        string? IHasAttachment.Prefix => "Bearer ";
    }

    public sealed class DelegatedRecordingProvider : ICredentialProvider<DelegatedRecordingOptions>
    {
        public string Type => "Delegated";

        public List<CredentialRequestContext> Contexts { get; } = [];

        public Exception? FailWith { get; set; }

        public ValueTask<string> GetCredentialAsync(
            DelegatedRecordingOptions options,
            ISecretAccessor secrets,
            CredentialRequestContext context,
            CancellationToken cancellationToken)
        {
            Contexts.Add(context);
            if (FailWith is not null)
            {
                throw FailWith;
            }

            context.CachePartition = "p:p1|u:user-A";
            return new ValueTask<string>("down-tok");
        }
    }

    private (ServiceProvider Services, CredentialAttachFeature Feature, DelegatedRecordingProvider Provider) BuildDelegated()
    {
        var configuration = TestConfig.Root(
            ("CredProx:Credentials:contoso:Type", "Delegated"));

        var services = new ServiceCollection();
        services.AddCredProxTokenCache();
        services.AddCredProxConfigurationSecrets(configuration);
        services.AddCredProxCredentialType<DelegatedRecordingProvider, DelegatedRecordingOptions>("Delegated");
        services.AddCredProxCredentials(configuration);
        services.AddSingleton<ITokenCache>(_cache);
        var provider = services.BuildServiceProvider();

        var feature = new CredentialAttachFeature(
            provider.GetRequiredService<CredentialRegistryProvider>(),
            _cache,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<CredentialAttachFeature>.Instance);
        return (provider, feature, provider.GetRequiredService<DelegatedRecordingProvider>());
    }

    [Fact]
    public async Task Delegated_MissingInboundToken_Aborts401BeforeTheProvider()
    {
        var (_, feature, recording) = BuildDelegated();

        var context = M4Contexts.Create(out var proxyRequest, AttachRoute);

        await feature.ApplyAsync(context, default);

        var state = context.Features.Get<CredProxRequestState>()!;
        Assert.True(state.IsAborted);
        Assert.Equal(401, context.Response.StatusCode);
        var body = M4Contexts.ResponseBody(context);
        using var problem = JsonDocument.Parse(body);
        Assert.Equal(
            "credprox.inbound_token_missing",
            problem.RootElement.GetProperty("extensions").GetProperty("code").GetString());
        Assert.Empty(recording.Contexts); // the provider never ran
        Assert.Empty(proxyRequest.Headers);
    }

    [Fact]
    public async Task Delegated_NonBearerInboundCountsAsMissing()
    {
        var (_, feature, recording) = BuildDelegated();

        var context = M4Contexts.Create(out _, AttachRoute);
        context.Request.Headers.Authorization = "Basic dXNlcjpwYXNz";

        await feature.ApplyAsync(context, default);

        Assert.Equal(401, context.Response.StatusCode);
        Assert.Empty(recording.Contexts);
    }

    [Fact]
    public async Task Delegated_BearerToken_RidesTheContext()
    {
        var (_, feature, recording) = BuildDelegated();

        var context = M4Contexts.Create(out var proxyRequest, AttachRoute);
        context.Request.Headers.Authorization = "Bearer inbound-user-token";

        await feature.ApplyAsync(context, default);

        var seen = Assert.Single(recording.Contexts);
        Assert.Equal("inbound-user-token", seen.InboundToken);
        Assert.Equal("Bearer down-tok", proxyRequest.Headers.Authorization!.ToString());
    }

    [Fact]
    public async Task Delegated_RejectedToken_Aborts401Invalid_NamingKindNotToken()
    {
        var (_, feature, recording) = BuildDelegated();
        recording.FailWith = new InboundTokenRejectedException("expired", "the inbound token expired");

        var context = M4Contexts.Create(out _, AttachRoute);
        context.Request.Headers.Authorization = "Bearer secret-inbound-token-value";

        await feature.ApplyAsync(context, default);

        Assert.Equal(401, context.Response.StatusCode);
        var body = M4Contexts.ResponseBody(context);
        using var problem = JsonDocument.Parse(body);
        Assert.Equal(
            "credprox.inbound_token_invalid",
            problem.RootElement.GetProperty("extensions").GetProperty("code").GetString());
        Assert.Contains("expired", body, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-inbound-token-value", body, StringComparison.Ordinal);
    }

    // ---- M19 consent signalling (§8.3) ----

    private const string AuthorizeUrl = "https://id.example/authorize?client_id=demo&state=xyz";

    [Fact]
    public async Task ConsentException_MapsTo401ConsentProblem_WithAuthorizeUrlMember()
    {
        var (_, feature, recording) = Build(("Credentials:contoso:Type", "Recording"));
        recording.FailWith = new ConsentRequiredException(AuthorizeUrl, "contoso developer message");

        var context = M4Contexts.Create(out var proxyRequest, AttachRoute);

        await feature.ApplyAsync(context, default);

        var state = context.Features.Get<CredProxRequestState>()!;
        Assert.True(state.IsAborted);
        Assert.Equal(401, context.Response.StatusCode);
        Assert.Equal("application/problem+json", context.Response.ContentType);
        var body = M4Contexts.ResponseBody(context);
        using var problem = JsonDocument.Parse(body);
        Assert.Equal(401, problem.RootElement.GetProperty("status").GetInt32());
        var extensions = problem.RootElement.GetProperty("extensions");
        Assert.Equal("credprox.consent_required", extensions.GetProperty("code").GetString());
        Assert.Equal(AuthorizeUrl, extensions.GetProperty("authorize_url").GetString());

        // Short-circuited: the credential never resolved, so the refresh-on-401 handler
        // gets no targets for it either.
        Assert.False(proxyRequest.Options.TryGetValue(CredProxRequestOptions.TokenRefresh, out _));

        // The developer-facing message never enters the body (§3.4).
        Assert.DoesNotContain("contoso developer message", body, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("https://id.example/authorize?client_id=demo")]
    [InlineData("http://localhost:5123/authorize")] // dev IdP over plain http is a browser-safe entry point
    public async Task ConsentProblem_SurfacesBrowserSafeAuthorizeUrl(string url)
    {
        var (_, feature, recording) = Build(("Credentials:contoso:Type", "Recording"));
        recording.FailWith = new ConsentRequiredException(url, "consent");

        var context = M4Contexts.Create(out _, AttachRoute);

        await feature.ApplyAsync(context, default);

        Assert.Equal(401, context.Response.StatusCode);
        using var problem = JsonDocument.Parse(M4Contexts.ResponseBody(context));
        Assert.Equal(
            url,
            problem.RootElement.GetProperty("extensions").GetProperty("authorize_url").GetString());
    }

    [Theory]
    [InlineData("/authorize")]                            // relative reference
    [InlineData("javascript:alert(1)")]                   // script URL
    [InlineData("data:text/html,x")]                      // inline document
    [InlineData("ftp://id.example/authorize")]            // not a browser scheme
    [InlineData("file:///etc/passwd")]                    // local file
    [InlineData("https://user:***@id.example/authorize")] // embedded credentials
    [InlineData("   ")]                                   // whitespace
    public async Task ConsentProblem_OmitsUnsafeAuthorizeUrl(string unsafeUrl)
    {
        // §8.3 URL hygiene: a provider must not be able to smuggle credentials or script
        // URLs into a response body. The consent problem still lands — only the member
        // is dropped.
        var (_, feature, recording) = Build(("Credentials:contoso:Type", "Recording"));
        recording.FailWith = new ConsentRequiredException(unsafeUrl, "consent");

        var context = M4Contexts.Create(out _, AttachRoute);

        await feature.ApplyAsync(context, default);

        Assert.Equal(401, context.Response.StatusCode);
        using var problem = JsonDocument.Parse(M4Contexts.ResponseBody(context));
        var extensions = problem.RootElement.GetProperty("extensions");
        Assert.Equal("credprox.consent_required", extensions.GetProperty("code").GetString());
        Assert.False(extensions.TryGetProperty("authorize_url", out _));
        Assert.DoesNotContain("user:pass", M4Contexts.ResponseBody(context), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ConsentException_OnDelegatedCredential_MapsToConsentNotInboundToken()
    {
        // The two caller-facing 401s stay distinct even on a delegated credential: the
        // consent signal is about the user's authorization, not the inbound token.
        var (_, feature, provider) = BuildDelegated();
        provider.FailWith = new ConsentRequiredException(AuthorizeUrl, "consent");

        var context = M4Contexts.Create(out _, AttachRoute);
        context.Request.Headers.Authorization = "Bearer inbound-user-token";

        await feature.ApplyAsync(context, default);

        Assert.Equal(401, context.Response.StatusCode);
        using var problem = JsonDocument.Parse(M4Contexts.ResponseBody(context));
        Assert.Equal(
            "credprox.consent_required",
            problem.RootElement.GetProperty("extensions").GetProperty("code").GetString());
    }

    [Fact]
    public async Task Delegated_RefreshOn401_InvalidatesThePerUserEntry()
    {
        var (_, feature, _) = BuildDelegated();

        var context = M4Contexts.Create(out var proxyRequest, AttachRoute);
        context.Request.Headers.Authorization = "Bearer inbound-user-token";

        await feature.ApplyAsync(context, default);

        Assert.True(proxyRequest.Options.TryGetValue(
            CredProxRequestOptions.TokenRefresh, out var targets));
        targets!.Invalidate();

        // The per-user entry the provider recorded, not the plain (credential, partition).
        Assert.Equal(("contoso", "p:p1|u:user-A"), Assert.Single(_cache.Invalidations));
    }

    [Fact]
    public async Task NonDelegatedCredential_NeverSeesTheInboundToken()
    {
        // Secret scoping for request secrets: no marker, no token on the context.
        var (_, feature, recording) = Build(("Credentials:contoso:Type", "Recording"));

        var context = M4Contexts.Create(out _, AttachRoute);
        context.Request.Headers.Authorization = "Bearer inbound-user-token";

        await feature.ApplyAsync(context, default);

        Assert.Null(Assert.Single(recording.Contexts).InboundToken);
    }
}
