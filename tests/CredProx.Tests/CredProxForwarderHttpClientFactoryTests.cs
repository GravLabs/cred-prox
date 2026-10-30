using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;
using Yarp.ReverseProxy.Forwarder;

namespace CredProx.Tests;

/// <summary>
/// The CredProx forwarder client factory (§3.3): the cluster's client certificate is
/// applied in <c>ConfigureHandler</c>, the version stamp decides <c>CanReuseOldClient</c>
/// across a rotation, and <c>ComposePipeline</c> orders the outbound chain — registered
/// pipeline features outermost-first by ascending stage, the refresh-on-401 handler
/// innermost.
/// </summary>
public sealed class CredProxForwarderHttpClientFactoryTests
{
    /// <summary>Exposes the protected seams, exactly as a plugin subclass would.</summary>
    private sealed class TestFactory(IServiceProvider services) : CredProxForwarderHttpClientFactory(services)
    {
        public void Configure(ForwarderHttpClientContext context, SocketsHttpHandler handler) =>
            ConfigureHandler(context, handler);

        public bool Reuse(ForwarderHttpClientContext context) => CanReuseOldClient(context);
    }

    private static ForwarderHttpClientContext Context(
        string clusterId = "cluster-1",
        Dictionary<string, string>? metadata = null,
        HttpMessageInvoker? oldClient = null) =>
        new()
        {
            ClusterId = clusterId,
            NewConfig = new Yarp.ReverseProxy.Configuration.HttpClientConfig(),
            OldConfig = new Yarp.ReverseProxy.Configuration.HttpClientConfig(),
            NewMetadata = metadata,
            OldClient = oldClient,
        };

    private static TestFactory CreateFactory(out ServiceProvider services, params IPipelineFeature[] features)
    {
        var collection = new ServiceCollection();
        collection.AddOptions();
        collection.AddSingleton<IOptions<RefreshOn401Options>>(Options.Create(new RefreshOn401Options()));
        foreach (var feature in features)
        {
            collection.AddSingleton(feature);
        }

        services = collection.BuildServiceProvider();
        return new TestFactory(services);
    }

    private sealed class RecordingHandler(string name, List<string> order, HttpMessageHandler inner)
        : DelegatingHandler(inner)
    {
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            order.Add(name);
            return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
    }

    private sealed class Feature(Stage stage, string name, List<string> order) : IPipelineFeature
    {
        public Stage Stage { get; } = stage;

        public DelegatingHandler CreateHandler(DelegatingHandler innerHandler) =>
            new RecordingHandler(name, order, innerHandler);
    }

    private sealed class StubTransport(Func<HttpRequestMessage, HttpResponseMessage> responder) : HttpMessageHandler
    {
        public List<HttpRequestMessage> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Requests.Add(request);
            return Task.FromResult(responder(request));
        }
    }

    [Fact]
    public async Task ComposePipeline_OrdersFeaturesByAscendingStage_RefreshInnermost()
    {
        var order = new List<string>();
        var transport = new StubTransport(_ => new HttpResponseMessage(HttpStatusCode.OK));
        var factory = CreateFactory(
            out var services,
            new Feature(Stage.Send, "send", order),
            new Feature(Stage.Pipeline, "pipeline", order));
        // Registration order is deliberately wrong (Send before Pipeline): the declared
        // stage must decide, not registration.

        var chain = factory.ComposePipeline(Context(), transport);
        using var invoker = new HttpMessageInvoker(chain, disposeHandler: true);
        await invoker.SendAsync(new HttpRequestMessage(HttpMethod.Get, "http://upstream/"), default);

        Assert.Equal(["pipeline", "send"], order); // ascending stage: outermost first
        Assert.Single(transport.Requests);
        services.Dispose();
    }

    [Fact]
    public async Task ComposePipeline_RefreshHandlerActsInsideTheChain()
    {
        var order = new List<string>();
        var responses = new Queue<HttpStatusCode>([HttpStatusCode.Unauthorized, HttpStatusCode.OK]);
        var transport = new StubTransport(_ => new HttpResponseMessage(responses.Dequeue()));
        var factory = CreateFactory(out var services, new Feature(Stage.Pipeline, "pipeline", order));

        var chain = factory.ComposePipeline(Context(), transport);
        using var invoker = new HttpMessageInvoker(chain, disposeHandler: true);

        var request = new HttpRequestMessage(HttpMethod.Get, "http://upstream/");
        var attachCount = 0;
        request.Options.Set(
            CredProxRequestOptions.TokenRefresh,
            new TokenRefreshTargets(
                _ => new ValueTask<string>("token-" + attachCount),
                invalidate: () => { },
                attach: (r, v) => { attachCount++; r.Headers.Authorization = new("Bearer", v); }));

        var response = await invoker.SendAsync(request, default);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Single(order); // the outer feature saw one logical request; the retry is inside
        Assert.Equal(2, transport.Requests.Count);
        services.Dispose();
    }

    [Fact]
    public async Task ComposePipeline_RequestWithoutTargets_PassesThrough()
    {
        var transport = new StubTransport(_ => new HttpResponseMessage(HttpStatusCode.Unauthorized));
        var factory = CreateFactory(out var services);

        var chain = factory.ComposePipeline(Context(), transport);
        using var invoker = new HttpMessageInvoker(chain, disposeHandler: true);
        var response = await invoker.SendAsync(new HttpRequestMessage(HttpMethod.Get, "http://upstream/"), default);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Single(transport.Requests); // no refresh attempted
        services.Dispose();
    }

    [Fact]
    public void ConfigureHandler_AppliesClusterClientCertificate()
    {
        using var cert = TestCertificates.CreateSelfSigned("factory-cert");
        var (config, _) = ConnectionConfigWith(cert);
        var registry = new ConnectionBinder(
            config,
            new SecretAccessorFactory(new ConfigurationSecretSource(config)),
            NullLoggerFactory.Instance).Bind();

        var collection = new ServiceCollection();
        collection.AddSingleton(registry);
        using var services = collection.BuildServiceProvider();
        var factory = new TestFactory(services);

        var handler = new SocketsHttpHandler();
        factory.Configure(
            Context(metadata: new() { [CredProxMetadata.Connection] = "contoso" }),
            handler);

        var applied = (X509Certificate2?)Assert.Single(handler.SslOptions.ClientCertificates!);
        Assert.NotNull(applied);
        Assert.Equal(cert.Thumbprint, applied.Thumbprint);
    }

    [Fact]
    public void ConfigureHandler_WithoutConnectionMetadata_AppliesNoCertificate()
    {
        using var cert = TestCertificates.CreateSelfSigned("factory-cert-none");
        var (config, _) = ConnectionConfigWith(cert);
        var registry = new ConnectionBinder(
            config,
            new SecretAccessorFactory(new ConfigurationSecretSource(config)),
            NullLoggerFactory.Instance).Bind();

        var collection = new ServiceCollection();
        collection.AddSingleton(registry);
        using var services = collection.BuildServiceProvider();
        var factory = new TestFactory(services);

        var handler = new SocketsHttpHandler();
        factory.Configure(Context(), handler);

        Assert.True(handler.SslOptions.ClientCertificates is null
            || handler.SslOptions.ClientCertificates.Count == 0);
    }

    [Fact]
    public void CanReuseOldClient_StampDecidesAcrossRotation()
    {
        using var first = TestCertificates.CreateSelfSigned("factory-rotate-1");
        var (config, reloadable) = ConnectionConfigWith(first);
        var registry = new ConnectionBinder(
            config,
            new SecretAccessorFactory(new ConfigurationSecretSource(config)),
            NullLoggerFactory.Instance).Bind();
        var connection = registry.Get("contoso");

        var collection = new ServiceCollection();
        collection.AddSingleton(registry);
        using var services = collection.BuildServiceProvider();
        var factory = new TestFactory(services);

        var oldClient = new HttpMessageInvoker(new SocketsHttpHandler());
        var metadata = new Dictionary<string, string> { [CredProxMetadata.Connection] = "contoso" };

        // First build records the stamp.
        factory.Configure(Context(metadata: metadata), new SocketsHttpHandler());

        // Unrelated reload: same config, same certificate → reuse.
        Assert.True(factory.Reuse(Context(metadata: metadata, oldClient: oldClient)));

        // Rotated certificate: stamp differs → rebuild.
        using var second = TestCertificates.CreateSelfSigned("factory-rotate-2");
        reloadable.Set("CredProx:Secrets:contoso-cert", TestCertificates.PfxBase64(second));
        reloadable.Reload();

        Assert.False(factory.Reuse(Context(metadata: metadata, oldClient: oldClient)));
    }

    [Fact]
    public void CanReuseOldClient_SwitchBetweenEqualVersionConnections_Rebuilds()
    {
        // F1 (M4 review): Version is per-connection and starts at 1, so two connections
        // routinely carry equal stamps — the stamp must carry the connection identity.
        using var certA = TestCertificates.CreateSelfSigned("factory-switch-a");
        using var certB = TestCertificates.CreateSelfSigned("factory-switch-b");
        var config = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
            .Add(new Microsoft.Extensions.Configuration.Memory.MemoryConfigurationSource
            {
                InitialData = new Dictionary<string, string?>
                {
                    ["CredProx:Connections:alpha:ClientCertificate"] = "secret:cert-a",
                    ["CredProx:Connections:beta:ClientCertificate"] = "secret:cert-b",
                    ["CredProx:Secrets:cert-a"] = TestCertificates.PfxBase64(certA),
                    ["CredProx:Secrets:cert-b"] = TestCertificates.PfxBase64(certB),
                },
            })
            .Build();
        var registry = new ConnectionBinder(
            config,
            new SecretAccessorFactory(new ConfigurationSecretSource(config)),
            NullLoggerFactory.Instance).Bind();

        Assert.Equal(1, registry.Get("alpha").Version); // the equal-stamp precondition
        Assert.Equal(1, registry.Get("beta").Version);

        var collection = new ServiceCollection();
        collection.AddSingleton(registry);
        using var services = collection.BuildServiceProvider();
        var factory = new TestFactory(services);

        var oldClient = new HttpMessageInvoker(new SocketsHttpHandler());

        // First build on connection alpha records the stamp.
        factory.Configure(
            Context(metadata: new() { [CredProxMetadata.Connection] = "alpha" }),
            new SocketsHttpHandler());

        // Unrelated reload on alpha: reuse.
        Assert.True(factory.Reuse(Context(
            metadata: new() { [CredProxMetadata.Connection] = "alpha" }, oldClient: oldClient)));

        // Switch alpha -> beta at equal versions: rebuild, or the cluster keeps alpha's cert.
        Assert.False(factory.Reuse(Context(
            metadata: new() { [CredProxMetadata.Connection] = "beta" }, oldClient: oldClient)));
    }

    [Fact]
    public void CanReuseOldClient_ReferenceChangeVersionReset_Rebuilds()
    {
        // F1 (M5 review): repointing a connection's ClientCertificate reference at a
        // different secret — the versioned-secret-name rotation pattern — replaces the
        // connection object, whose Version restarts at 1. A name+version stamp collided
        // with the old one and the cluster kept presenting the previous certificate; the
        // stamp carries the connection object, so the replacement forces a rebuild.
        using var cert1 = TestCertificates.CreateSelfSigned("factory-refchange-1");
        using var cert2 = TestCertificates.CreateSelfSigned("factory-refchange-2");
        var source = new ReloadableMemoryConfigurationSource(new Dictionary<string, string?>
        {
            ["CredProx:Connections:contoso:ClientCertificate"] = "secret:cert-1",
            ["CredProx:Secrets:cert-1"] = TestCertificates.PfxBase64(cert1),
            ["CredProx:Secrets:cert-2"] = TestCertificates.PfxBase64(cert2),
        });
        var config = new Microsoft.Extensions.Configuration.ConfigurationBuilder().Add(source).Build();
        var reloadable = (ReloadableMemoryConfigurationProvider)config.Providers
            .OfType<ReloadableMemoryConfigurationProvider>().Single();
        var secretSource = new ConfigurationSecretSource(config);
        var provider = new ConnectionRegistryProvider(
            new ConnectionBinder(
                config,
                new SecretAccessorFactory(secretSource),
                NullLoggerFactory.Instance),
            secretSource,
            NullLogger<ConnectionRegistryProvider>.Instance);

        // Same wiring as the configured host: the factory resolves the live registry per call.
        var collection = new ServiceCollection();
        collection.AddTransient(_ => provider.Current);
        using var services = collection.BuildServiceProvider();
        var factory = new TestFactory(services);

        var oldClient = new HttpMessageInvoker(new SocketsHttpHandler());
        var metadata = new Dictionary<string, string> { [CredProxMetadata.Connection] = "contoso" };

        // First build on secret:cert-1 records the stamp (connection object, Version 1).
        factory.Configure(Context(metadata: metadata), new SocketsHttpHandler());
        Assert.Equal(1, provider.Current.Get("contoso").Version);

        // Unrelated reload: the binder keeps the same object → reuse.
        reloadable.Reload();
        Assert.True(factory.Reuse(Context(metadata: metadata, oldClient: oldClient)));

        // Reload repointing the reference at secret:cert-2: a new object whose Version
        // restarts at 1 — the equal-stamp collision the name comparison reused through.
        reloadable.Set("CredProx:Connections:contoso:ClientCertificate", "secret:cert-2");
        reloadable.Reload();
        Assert.Equal(1, provider.Current.Get("contoso").Version);

        Assert.False(factory.Reuse(Context(metadata: metadata, oldClient: oldClient)));
    }

    [Fact]
    public void CanReuseOldClient_ConnectionRemoved_Rebuilds()
    {
        using var cert = TestCertificates.CreateSelfSigned("factory-remove");
        var (config, _) = ConnectionConfigWith(cert);
        var registry = new ConnectionBinder(
            config,
            new SecretAccessorFactory(new ConfigurationSecretSource(config)),
            NullLoggerFactory.Instance).Bind();

        var collection = new ServiceCollection();
        collection.AddSingleton(registry);
        using var services = collection.BuildServiceProvider();
        var factory = new TestFactory(services);

        var oldClient = new HttpMessageInvoker(new SocketsHttpHandler());
        var metadata = new Dictionary<string, string> { [CredProxMetadata.Connection] = "contoso" };
        factory.Configure(Context(metadata: metadata), new SocketsHttpHandler());

        // Removal as an empty metadata dictionary: rebuild.
        Assert.False(factory.Reuse(Context(metadata: [], oldClient: oldClient)));

        // Removal as null new metadata (the old metadata still carries the connection):
        // the new config's identity decides, so still rebuild.
        Assert.False(factory.Reuse(new ForwarderHttpClientContext
        {
            ClusterId = "cluster-1",
            NewConfig = new Yarp.ReverseProxy.Configuration.HttpClientConfig(),
            OldConfig = new Yarp.ReverseProxy.Configuration.HttpClientConfig(),
            NewMetadata = null,
            OldMetadata = metadata,
            OldClient = oldClient,
        }));
    }

    private static (Microsoft.Extensions.Configuration.IConfiguration Config,
        ReloadableMemoryConfigurationProvider Reloadable) ConnectionConfigWith(
            System.Security.Cryptography.X509Certificates.X509Certificate2 certificate)
    {
        var source = new ReloadableMemoryConfigurationSource(new Dictionary<string, string?>
        {
            ["CredProx:Connections:contoso:ClientCertificate"] = "secret:contoso-cert",
            ["CredProx:Secrets:contoso-cert"] = TestCertificates.PfxBase64(certificate),
        });
        var config = new Microsoft.Extensions.Configuration.ConfigurationBuilder().Add(source).Build();
        return (config, (ReloadableMemoryConfigurationProvider)config.Providers
            .OfType<ReloadableMemoryConfigurationProvider>().Single());
    }
}
