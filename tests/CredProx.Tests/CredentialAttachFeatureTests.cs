using System.Net.Http;
using System.Text.Json;
using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
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

        // A secret-bearing member, so consent-path pins can configure a credential's own
        // secret the same way the built-in providers' options hold theirs (by name).
        public string? Secret { get; set; }

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

    /// <summary>
    /// Drives the consent guard over the REAL <see cref="LoginExchangeOptions"/> shape:
    /// that options type nests its credentials one level (Basic/Form), which is exactly
    /// what the by-name walk's inner level exists for. Test-local because the real
    /// provider would attempt a login rather than raise consent.
    /// </summary>
    public sealed class LoginConsentProvider : ICredentialProvider<LoginExchangeOptions>
    {
        public string Type => "LoginConsent";

        public Exception? FailWith { get; set; }

        public ValueTask<string> GetCredentialAsync(
            LoginExchangeOptions options,
            ISecretAccessor secrets,
            CredentialRequestContext context,
            CancellationToken cancellationToken)
        {
            if (FailWith is not null)
            {
                throw FailWith;
            }

            return new ValueTask<string>("unused");
        }
    }

    /// <summary>
    /// The plugin contract's shape (samples/CustomPlugin): a custom provider's option
    /// type with ARBITRARY member names. The by-name configured-secret arm catches the
    /// listed name and NOT the unlisted one — the documented honest limit.
    /// </summary>
    public sealed class PluginConsentOptions : IHasAttachment, IHasPartitionConfig, IHasConnection
    {
        public string Value { get; set; } = "plugin-token";

        /// <summary>A listed member name: the by-name arm sees it.</summary>
        public string? ClientSecret { get; set; }

        /// <summary>An unlisted member name: documented not covered by the name list.</summary>
        public string? ApiKey { get; set; }

        public PartitionConfigOptions? Partition { get; set; }

        public string? Connection { get; set; }

        CredentialLocation IHasAttachment.Location => CredentialLocation.Header;

        string IHasAttachment.Name => "X-Plugin";

        string? IHasAttachment.Prefix => null;
    }

    public sealed class PluginConsentProvider : ICredentialProvider<PluginConsentOptions>
    {
        public string Type => "PluginConsent";

        public Exception? FailWith { get; set; }

        public ValueTask<string> GetCredentialAsync(
            PluginConsentOptions options,
            ISecretAccessor secrets,
            CredentialRequestContext context,
            CancellationToken cancellationToken)
        {
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

    private (ServiceProvider Services, CredentialAttachFeature Feature, LoginConsentProvider Provider) BuildLoginConsent(
        params (string Key, string? Value)[] credProxEntries)
    {
        var configuration = TestConfig.Root(
            credProxEntries.Select(e => ("CredProx:" + e.Key, e.Value)).ToArray());

        var services = new ServiceCollection();
        services.AddCredProxTokenCache();
        services.AddCredProxConfigurationSecrets(configuration);
        services.AddCredProxBuiltInCredentials();
        services.AddCredProxCredentialType<LoginConsentProvider, LoginExchangeOptions>("LoginConsent");
        services.AddCredProxCredentials(configuration);
        services.AddSingleton<ITokenCache>(_cache);
        var provider = services.BuildServiceProvider();

        var feature = new CredentialAttachFeature(
            provider.GetRequiredService<CredentialRegistryProvider>(),
            _cache,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<CredentialAttachFeature>.Instance);
        return (provider, feature, provider.GetRequiredService<LoginConsentProvider>());
    }

    private (ServiceProvider Services, CredentialAttachFeature Feature, PluginConsentProvider Provider) BuildPlugin(
        params (string Key, string? Value)[] credProxEntries)
    {
        var configuration = TestConfig.Root(
            credProxEntries.Select(e => ("CredProx:" + e.Key, e.Value)).ToArray());

        var services = new ServiceCollection();
        services.AddCredProxTokenCache();
        services.AddCredProxConfigurationSecrets(configuration);
        services.AddCredProxBuiltInCredentials();
        services.AddCredProxCredentialType<PluginConsentProvider, PluginConsentOptions>("PluginConsent");
        services.AddCredProxCredentials(configuration);
        services.AddSingleton<ITokenCache>(_cache);
        var provider = services.BuildServiceProvider();

        var feature = new CredentialAttachFeature(
            provider.GetRequiredService<CredentialRegistryProvider>(),
            _cache,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<CredentialAttachFeature>.Instance);
        return (provider, feature, provider.GetRequiredService<PluginConsentProvider>());
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

    // ---- M47 finding F-9: the query rides, a query that carries a secret does not ----

    [Theory]
    [InlineData("https://id.example/authorize?client_id=demo&client_secret=TOPSECRET&state=xyz", "client_secret", "TOPSECRET")]
    [InlineData("https://id.example/authorize?client_assertion=JWTVALUE", "client_assertion", "JWTVALUE")]
    [InlineData("https://id.example/authorize?assertion=SAMLVALUE", "assertion", "SAMLVALUE")]
    [InlineData("https://id.example/authorize?password=login-pw", "password", "login-pw")]
    [InlineData("https://id.example/authorize?Client_Secret=TOPSECRET", "Client_Secret", "TOPSECRET")] // name match is case-insensitive
    public async Task ConsentProblem_OmitsAuthorizeUrl_WhenQueryCarriesKnownSecretParameter(
        string url, string parameterName, string secretValue)
    {
        // F-9: a provider-supplied authorize URL whose query carries one of the wire
        // secret names the credential providers send is not relayed, whatever its
        // value — the name itself marks a leak.
        Assert.Contains(parameterName, url, StringComparison.Ordinal);
        var (_, feature, recording) = Build(("Credentials:contoso:Type", "Recording"));
        recording.FailWith = new ConsentRequiredException(url, "consent");

        var context = M4Contexts.Create(out _, AttachRoute);

        await feature.ApplyAsync(context, default);

        Assert.Equal(401, context.Response.StatusCode);
        var body = M4Contexts.ResponseBody(context);
        using var problem = JsonDocument.Parse(body);
        var extensions = problem.RootElement.GetProperty("extensions");
        Assert.Equal("credprox.consent_required", extensions.GetProperty("code").GetString());
        Assert.False(extensions.TryGetProperty("authorize_url", out _));
        Assert.DoesNotContain(secretValue, body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ConsentProblem_OmitsAuthorizeUrl_WhenQueryValueMatchesAnInjectedSecret()
    {
        // F-9: reuse the scrubber's registered values — a query parameter carrying a
        // secret this pipeline injected (whatever the parameter is called) is a leak.
        const string Injected = "injected-wire-secret-1";
        var (_, feature, recording) = Build(("Credentials:contoso:Type", "Recording"));
        recording.FailWith = new ConsentRequiredException(
            "https://id.example/authorize?client_id=demo&token=" + Injected, "consent");

        var context = M4Contexts.Create(out _, AttachRoute);
        CredProxInjectedSecrets.GetOrCreate(context).Register(Injected);

        await feature.ApplyAsync(context, default);

        var body = M4Contexts.ResponseBody(context);
        using var problem = JsonDocument.Parse(body);
        Assert.False(
            problem.RootElement.GetProperty("extensions").TryGetProperty("authorize_url", out _));
        Assert.DoesNotContain(Injected, body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ConsentProblem_OmitsAuthorizeUrl_WhenPercentEncodedQueryValueCarriesAnInjectedSecret()
    {
        // Matching reads the percent-decoded form too (the scrubber registers both
        // forms): containment, not just exact equality.
        const string Injected = "injected-wire-secret-2";
        var (_, feature, recording) = Build(("Credentials:contoso:Type", "Recording"));
        recording.FailWith = new ConsentRequiredException(
            "https://id.example/authorize?state=ctx%20" + Uri.EscapeDataString(Injected), "consent");

        var context = M4Contexts.Create(out _, AttachRoute);
        CredProxInjectedSecrets.GetOrCreate(context).Register(Injected);

        await feature.ApplyAsync(context, default);

        var body = M4Contexts.ResponseBody(context);
        using var problem = JsonDocument.Parse(body);
        Assert.False(
            problem.RootElement.GetProperty("extensions").TryGetProperty("authorize_url", out _));
    }

    [Fact]
    public async Task ConsentProblem_RidesThePlausibleAuthorizationCodeQuery_Intact()
    {
        // F-9 must not break the consent flow: client_id, redirect_uri and state are
        // exactly what the entry point needs, and a registered secret that appears
        // nowhere in the values changes nothing.
        const string Plausible = "https://id.example/authorize?client_id=demo&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&state=xyz";
        var (_, feature, recording) = Build(("Credentials:contoso:Type", "Recording"));
        recording.FailWith = new ConsentRequiredException(Plausible, "consent");

        var context = M4Contexts.Create(out _, AttachRoute);
        CredProxInjectedSecrets.GetOrCreate(context).Register("some-registered-secret");

        await feature.ApplyAsync(context, default);

        var body = M4Contexts.ResponseBody(context);
        using var problem = JsonDocument.Parse(body);
        Assert.Equal(Plausible,
            problem.RootElement.GetProperty("extensions").GetProperty("authorize_url").GetString());
    }

    [Fact]
    public async Task ConsentProblem_LogsDroppedAuthorizeUrl_ByParameterNamesOnly()
    {
        // F-9: the operator hears which parameters carried a secret — names only,
        // never values.
        var logs = new Capturing();
        var configuration = TestConfig.Root(("CredProx:Credentials:contoso:Type", "Recording"));
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
            logs);
        var recording = provider.GetRequiredService<RecordingProvider>();
        recording.FailWith = new ConsentRequiredException(
            "https://id.example/authorize?client_id=demo&client_secret=TOPSECRET&state=xyz", "consent");

        var context = M4Contexts.Create(out _, AttachRoute);
        await feature.ApplyAsync(context, default);

        var warning = Assert.Single(logs.Entries, e => e.Level == LogLevel.Warning);
        Assert.Contains("client_secret", warning.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("TOPSECRET", warning.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("authorize_url", warning.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ConsentProblem_LogsTheParameterName_WhenOnlyTheDecodedValueCarriesTheSecret()
    {
        // F-4: the per-parameter decode exists so the log can NAME the parameter. A
        // space-encoded secret under an ordinary 'state' name is invisible to the raw
        // arm; the decoded arm still drops the URL (the whole-URL fallback would drop
        // it anyway) but attributes it to 'state', not 'path-or-fragment'. The secret
        // must be the CONFIGURED one: the injected registry also stores each value's
        // escaped form (CredProxInjectedSecrets.Register), so an injected secret is
        // raw-visible and cannot witness the decode arm.
        var logs = new Capturing();
        var configuration = TestConfig.Root(
            ("CredProx:Credentials:contoso:Type", "Recording"),
            ("CredProx:Credentials:contoso:Secret", "cfg wire s3cret"));
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
            logs);
        var recording = provider.GetRequiredService<RecordingProvider>();
        recording.FailWith = new ConsentRequiredException(
            "https://id.example/authorize?client_id=demo&state=cfg%20wire%20s3cret", "consent");

        var context = M4Contexts.Create(out _, AttachRoute);

        await feature.ApplyAsync(context, default);

        var body = M4Contexts.ResponseBody(context);
        using (var problem = JsonDocument.Parse(body))
        {
            Assert.False(
                problem.RootElement.GetProperty("extensions").TryGetProperty("authorize_url", out _));
        }

        var warning = Assert.Single(logs.Entries, e => e.Level == LogLevel.Warning);
        Assert.Contains("state", warning.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("path-or-fragment", warning.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("cfg wire s3cret", warning.Message, StringComparison.Ordinal);
    }

    // ---- M47 F-9 widened: the guard scans the whole URL, knows the credential's own
    // configured secrets, and over-refuses nothing the flow needs ----

    [Theory]
    // H2: a top-level query or fragment parameter NAME that contains secret, assertion
    // or password (case-insensitive containment), or is exactly access_token or
    // refresh_token, marks a leak whatever its value. ';' separates parameters too.
    [InlineData("https://id.example/authorize?client_id=demo&client-secret=TOPSECRET")]
    [InlineData("https://id.example/authorize?client_id=demo&clientSecret=TOPSECRET")]
    [InlineData("https://id.example/authorize?client_id=demo&secret=TOPSECRET")]
    [InlineData("https://id.example/authorize?client_id=demo&client_secret_value=TOPSECRET")]
    [InlineData("https://id.example/authorize?id=1;client_secret=TOPSECRET")]
    [InlineData("https://id.example/authorize?client_id=demo#access_token=TOPSECRET")]
    [InlineData("https://id.example/authorize#refresh_token=TOPSECRET")]
    [InlineData("https://id.example/authorize?client_id=demo#state=x&assertion=SAMLVALUE")]
    public async Task ConsentProblem_OmitsAuthorizeUrl_WhenParameterNameMarksASecret(string url)
    {
        var (_, feature, recording) = Build(("Credentials:contoso:Type", "Recording"));
        recording.FailWith = new ConsentRequiredException(url, "consent");

        var context = M4Contexts.Create(out _, AttachRoute);

        await feature.ApplyAsync(context, default);

        var body = M4Contexts.ResponseBody(context);
        using var problem = JsonDocument.Parse(body);
        Assert.Equal("credprox.consent_required",
            problem.RootElement.GetProperty("extensions").GetProperty("code").GetString());
        Assert.False(
            problem.RootElement.GetProperty("extensions").TryGetProperty("authorize_url", out _));
        Assert.DoesNotContain("TOPSECRET", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ConsentProblem_OmitsAuthorizeUrl_WhenPathSegmentCarriesAConfiguredSecret()
    {
        // Low-2: the guard read the query only; a secret in the PATH or FRAGMENT relays.
        // The value scan covers the whole URL, and on a first consent it must know the
        // credential's OWN configured secret — the injected registry is still empty.
        const string Configured = "cfg-wire-secret-99";
        var (_, feature, recording) = Build(
            ("Credentials:contoso:Type", "Recording"),
            ("Credentials:contoso:Secret", Configured));
        recording.FailWith = new ConsentRequiredException(
            "https://id.example/authorize/" + Configured + "?client_id=demo", "consent");

        var context = M4Contexts.Create(out _, AttachRoute);

        await feature.ApplyAsync(context, default);

        var body = M4Contexts.ResponseBody(context);
        using var problem = JsonDocument.Parse(body);
        Assert.False(
            problem.RootElement.GetProperty("extensions").TryGetProperty("authorize_url", out _));
        Assert.DoesNotContain(Configured, body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ConsentProblem_OmitsAuthorizeUrl_WhenFirstAttemptEchoesConfiguredSecret()
    {
        // Low-1: first attempt, no credential ever obtained, so CredProxInjectedSecrets
        // is empty — an arbitrary-name echo of the credential's configured secret under
        // 'state' must still refuse, from the configured value alone.
        const string Configured = "cfg-wire-secret-77";
        var (_, feature, recording) = Build(
            ("Credentials:contoso:Type", "Recording"),
            ("Credentials:contoso:Secret", Configured));
        recording.FailWith = new ConsentRequiredException(
            "https://id.example/authorize?client_id=demo&state=" + Uri.EscapeDataString(Configured),
            "consent");

        var context = M4Contexts.Create(out _, AttachRoute);

        // The guard must leave the request's secret registry EMPTY — registering the
        // configured secret early would make never-credential'd requests scrubbable
        // and refusable (the scrubber's HasAny gate and FailClosed both key on it).
        await feature.ApplyAsync(context, default);

        Assert.False(CredProxInjectedSecrets.GetOrCreate(context).HasAny);

        var body = M4Contexts.ResponseBody(context);
        using var problem = JsonDocument.Parse(body);
        Assert.False(
            problem.RootElement.GetProperty("extensions").TryGetProperty("authorize_url", out _));
        Assert.DoesNotContain(Configured, body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ConsentProblem_OmitsAuthorizeUrl_WhenFirstAttemptEchoesNestedLoginPassword()
    {
        // Round-2 F-3: the by-name walk reaches ONE nesting level, and the login options
        // are exactly that shape — LoginExchangeOptions nests its password under Basic —
        // so a login credential's own nested password is visible to the guard on a first
        // attempt with an empty injected registry. Made inert, the inner level has no
        // other witness anywhere in the suite.
        const string Nested = "pw-nested-login-42";
        var (_, feature, login) = BuildLoginConsent(
            ("Credentials:contoso:Type", "LoginConsent"),
            // The stub reuses LoginExchangeOptions for its nesting shape, and since M49
            // the built-in batch brings that options type's validator — the endpoint is
            // the one field it requires; the stub never calls it.
            ("Credentials:contoso:LoginEndpoint", "https://id.example/login"),
            ("Credentials:contoso:Basic:User", "svc@example.com"),
            ("Credentials:contoso:Basic:Password", Nested));
        login.FailWith = new ConsentRequiredException(
            "https://id.example/authorize?client_id=demo&state=" + Uri.EscapeDataString(Nested),
            "consent");

        var context = M4Contexts.Create(out _, AttachRoute);

        await feature.ApplyAsync(context, default);

        Assert.False(CredProxInjectedSecrets.GetOrCreate(context).HasAny);

        var body = M4Contexts.ResponseBody(context);
        using var problem = JsonDocument.Parse(body);
        Assert.False(
            problem.RootElement.GetProperty("extensions").TryGetProperty("authorize_url", out _));
        Assert.DoesNotContain(Nested, body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ConsentProblem_OmitsAuthorizeUrl_WhenPluginShapedOptionsUseAListedMemberName()
    {
        // F-2 pin (caught): a plugin-contract provider whose options follow the naming
        // convention — the guard sees the configured value by name on a first attempt.
        const string Listed = "plg-listed-77";
        var (_, feature, plugin) = BuildPlugin(
            ("Credentials:contoso:Type", "PluginConsent"),
            ("Credentials:contoso:ClientSecret", Listed));
        plugin.FailWith = new ConsentRequiredException(
            "https://id.example/authorize?client_id=demo&state=" + Listed, "consent");

        var context = M4Contexts.Create(out _, AttachRoute);

        await feature.ApplyAsync(context, default);

        var body = M4Contexts.ResponseBody(context);
        using var problem = JsonDocument.Parse(body);
        Assert.False(
            problem.RootElement.GetProperty("extensions").TryGetProperty("authorize_url", out _));
        Assert.DoesNotContain(Listed, body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ConsentProblem_Relays_WhenPluginShapedOptionsUseAnUnlistedMemberName()
    {
        // F-2 pin (documented limit): a plugin that names its member ApiKey instead of a
        // listed name is NOT caught by the configured-value arm — plugin option shapes
        // are arbitrary and the by-name match is best-effort. The general guard is the
        // parameter-NAME rule (name this parameter client_secret/assertion/password and
        // it drops regardless), and the plugin must never put its secret into an
        // authorize URL. This pin fixes the limit so a later change that widens or
        // narrows the name list is a conscious edit here, not a silent drift.
        const string Unlisted = "plg-unlisted-13";
        var (_, feature, plugin) = BuildPlugin(
            ("Credentials:contoso:Type", "PluginConsent"),
            ("Credentials:contoso:ApiKey", Unlisted));
        var url = "https://id.example/authorize?client_id=demo&state=" + Unlisted;
        plugin.FailWith = new ConsentRequiredException(url, "consent");

        var context = M4Contexts.Create(out _, AttachRoute);

        await feature.ApplyAsync(context, default);

        var body = M4Contexts.ResponseBody(context);
        using var problem = JsonDocument.Parse(body);
        Assert.Equal(
            url, problem.RootElement.GetProperty("extensions").GetProperty("authorize_url").GetString());
    }

    [Theory]
    // H2 over-refusal guard: these are what a working consent flow needs. The NAME rule
    // reads top-level parameter names only, never paths or values — 'token' alone is not
    // a secret word, and 'password' inside a PATH or inside another parameter's VALUE
    // changes nothing.
    [InlineData("https://id.example/authorize?client_id=demo&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&state=xyz&scope=openid%20profile&nonce=n1&response_type=code&prompt=consent&code_challenge=E9Me&code_challenge_method=S256&id_token_hint=hint&login_hint=user%40example.com&token=opaque-op")]
    [InlineData("https://id.example/authorize_passwordless?client_id=demo")]
    [InlineData("https://id.example/authorize?client_id=demo&redirect_uri=https%3A%2F%2Fapp.example%2Fcb%3Fpassword_hint%3Dabc%26login_hint%3Dme")]
    public async Task ConsentProblem_RidesTheParametersAConsentFlowNeeds(string url)
    {
        var (_, feature, recording) = Build(("Credentials:contoso:Type", "Recording"));
        recording.FailWith = new ConsentRequiredException(url, "consent");

        var context = M4Contexts.Create(out _, AttachRoute);

        await feature.ApplyAsync(context, default);

        var body = M4Contexts.ResponseBody(context);
        using var problem = JsonDocument.Parse(body);
        Assert.Equal(url,
            problem.RootElement.GetProperty("extensions").GetProperty("authorize_url").GetString());
    }

    [Fact]
    public async Task ConsentProblem_RelaysUnsetOptionalSecret_SelectivelyRefusesConfiguredValue()
    {
        // An unset optional secret is no value to match, and a configured secret
        // refuses ONLY when its own value appears — client_id=demo still relays.
        const string Configured = "cfg-wire-secret-55";
        var (_, feature, recording) = Build(
            ("Credentials:contoso:Type", "Recording"),
            ("Credentials:contoso:Secret", Configured));
        recording.FailWith = new ConsentRequiredException(
            "https://id.example/authorize?client_id=demo&state=xyz", "consent");

        var context = M4Contexts.Create(out _, AttachRoute);
        await feature.ApplyAsync(context, default);

        using (var problem = JsonDocument.Parse(M4Contexts.ResponseBody(context)))
        {
            Assert.Equal("https://id.example/authorize?client_id=demo&state=xyz",
                problem.RootElement.GetProperty("extensions").GetProperty("authorize_url").GetString());
        }
    }

    [Fact]
    public async Task ConsentProblem_Relays_WhenConfiguredSecretIsWhitespaceOnly()
    {
        // A whitespace-only configured secret is an unconfigured optional secret. It is
        // SKIPPED, not matched — an entry that any URL contains would refuse every
        // consent flow. (Availability, deliberately ahead of the scrubber's behaviour.)
        var logs = new Capturing();
        var configuration = TestConfig.Root(
            ("CredProx:Credentials:contoso:Type", "Recording"),
            ("CredProx:Credentials:contoso:Secret", "   "));
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
            logs);
        provider.GetRequiredService<RecordingProvider>().FailWith = new ConsentRequiredException(
            "https://id.example/authorize?client_id=demo&state=xyz", "consent");

        var context = M4Contexts.Create(out _, AttachRoute);
        await feature.ApplyAsync(context, default);

        using var problem = JsonDocument.Parse(M4Contexts.ResponseBody(context));
        Assert.Equal("https://id.example/authorize?client_id=demo&state=xyz",
            problem.RootElement.GetProperty("extensions").GetProperty("authorize_url").GetString());
    }

    [Fact]
    public async Task ConsentProblem_Relays_WhenConfiguredSecretIsEmpty()
    {
        // An empty configured secret is an unconfigured one. Matched, an empty string
        // is contained in every URL — it would refuse every consent flow. It is
        // skipped, and the consent URL rides.
        var (_, feature, recording) = Build(
            ("Credentials:contoso:Type", "Recording"),
            ("Credentials:contoso:Secret", string.Empty));
        recording.FailWith = new ConsentRequiredException(
            "https://id.example/authorize?client_id=demo&state=xyz", "consent");

        var context = M4Contexts.Create(out _, AttachRoute);
        await feature.ApplyAsync(context, default);

        using var problem = JsonDocument.Parse(M4Contexts.ResponseBody(context));
        Assert.Equal("https://id.example/authorize?client_id=demo&state=xyz",
            problem.RootElement.GetProperty("extensions").GetProperty("authorize_url").GetString());
    }

    [Fact]
    public async Task ConsentProblem_RefusesShortConfiguredSecret_AsIntended_AndNamesTheCredential()
    {
        // Parity with the scrubber, which registers short values as eagerly as long
        // ones: a deliberately short configured secret contains-match's ordinary
        // consent URLs and refuses them. That fail-closed cost is INTENDED — the
        // operator sees which credential caused it, so the refusal's warning names it.
        var logs = new Capturing();
        var configuration = TestConfig.Root(
            ("CredProx:Credentials:contoso:Type", "Recording"),
            ("CredProx:Credentials:contoso:Secret", "ab"));
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
            logs);
        provider.GetRequiredService<RecordingProvider>().FailWith = new ConsentRequiredException(
            "https://id.example/authorize?client_id=demo&state=abc123", "consent");

        var context = M4Contexts.Create(out _, AttachRoute);
        await feature.ApplyAsync(context, default);

        using var problem = JsonDocument.Parse(M4Contexts.ResponseBody(context));
        Assert.False(
            problem.RootElement.GetProperty("extensions").TryGetProperty("authorize_url", out _));
        var warning = Assert.Single(logs.Entries, e => e.Level == LogLevel.Warning);
        Assert.Contains("contoso", warning.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ConsentProblem_LogsDroppedSecretBearingNames_Escaped()
    {
        // Info-2: provider-chosen parameter names are attacker text. The warning may
        // carry them only escaped — never a raw newline the provider picked, never a
        // value.
        const string Injected = "injected-wire-secret-3";
        var logs = new Capturing();
        var configuration = TestConfig.Root(("CredProx:Credentials:contoso:Type", "Recording"));
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
            logs);
        provider.GetRequiredService<RecordingProvider>().FailWith = new ConsentRequiredException(
            "https://id.example/authorize?x=1&"
            + Uri.EscapeDataString("ok\n[FORGED] credprox=never_happened") + "=" + Injected,
            "consent");

        var context = M4Contexts.Create(out _, AttachRoute);
        CredProxInjectedSecrets.GetOrCreate(context).Register(Injected);
        await feature.ApplyAsync(context, default);

        var warning = Assert.Single(logs.Entries, e => e.Level == LogLevel.Warning);
        Assert.Contains("contoso", warning.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(Injected, warning.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("\n", warning.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("[FORGED]", warning.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("credprox=never_happened", warning.Message, StringComparison.Ordinal);
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

    [Fact]
    public async Task QueryPlacement_StatePrefixWinsOverSelectedDestinationAddress()
    {
        // The documented precedence: the transform-stashed prefix first, the selected
        // cluster destination only as fallback (a reload swapping the cluster model must
        // not silently move an in-flight request).
        var (_, feature, _) = Build(QueryKeyConfig);

        var context = M4Contexts.Create(out var proxyRequest, AttachRoute);
        proxyRequest.RequestUri = null;
        var state = context.Features.Get<CredProxRequestState>()!;
        state.DestinationPrefix = "https://state.example";
        state.OutboundPath = "/data";
        var destination = new Yarp.ReverseProxy.Model.DestinationState("d");
        typeof(Yarp.ReverseProxy.Model.DestinationState)
            .GetProperty(nameof(Yarp.ReverseProxy.Model.DestinationState.Model))!
            .SetValue(destination, new Yarp.ReverseProxy.Model.DestinationModel(
                new Yarp.ReverseProxy.Configuration.DestinationConfig { Address = "https://cluster.example/" }));
        context.Features.Get<Yarp.ReverseProxy.Model.IReverseProxyFeature>()!
            .ProxiedDestination = destination;

        await feature.ApplyAsync(context, default);

        Assert.False(state.IsAborted);
        Assert.StartsWith("https://state.example/data", proxyRequest.RequestUri!.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task QueryPlacement_PathWithoutLeadingSlash_GetsExactlyOne()
    {
        // The join rule is "/" only when the path lacks it: never a doubled or missing
        // separator between destination and path.
        var (_, feature, _) = Build(QueryKeyConfig);

        var context = M4Contexts.Create(out var proxyRequest, AttachRoute);
        proxyRequest.RequestUri = null;
        var state = context.Features.Get<CredProxRequestState>()!;
        state.DestinationPrefix = "https://vendor.example";
        state.OutboundPath = "v1/data";

        await feature.ApplyAsync(context, default);

        Assert.False(state.IsAborted);
        Assert.Equal(
            "https://vendor.example/v1/data",
            proxyRequest.RequestUri!.GetLeftPart(UriPartial.Path));
    }

    /// <summary>Minimal <see cref="ILogger{TCategoryName}"/> capture for the
    /// feature constructor argument.</summary>
    private sealed class Capturing : ILogger<CredentialAttachFeature>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception)));
    }
}
