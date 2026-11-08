using System.Security.Cryptography.X509Certificates;
using CredProx;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Transforms;
using Yarp.ReverseProxy.Transforms.Builder;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage of the dispatch layer: the forwarder factory's stamp sentinels keep
/// no-connection and unknown-connection clusters reusable (each a distinct identity), a
/// reloaded certificate reaches the handler through the refresh call, the composed chain
/// survives a host without logging, the response dispatcher fail-closes and logs, and the
/// transform's carry/short-circuit/net rules hold when driven directly.
/// </summary>
public sealed class YarpDispatchSurvivorTests
{
    // ---- forwarder factory probe ----

    private sealed class Probe(IServiceProvider services) : CredProxForwarderHttpClientFactory(services)
    {
        public bool Reuse(ForwarderHttpClientContext context) => CanReuseOldClient(context);

        public void Configure(ForwarderHttpClientContext context, SocketsHttpHandler handler) =>
            ConfigureHandler(context, handler);

        public HttpMessageHandler Wrap(ForwarderHttpClientContext context, HttpMessageHandler handler) =>
            WrapHandler(context, handler);

        public ClientCertificateConnection? Connection(ForwarderHttpClientContext context) =>
            ResolveConnection(context);
    }

    private static ForwarderHttpClientContext Context(
        Dictionary<string, string>? metadata = null,
        HttpMessageInvoker? oldClient = null) =>
        new()
        {
            ClusterId = "cluster-1",
            NewConfig = new HttpClientConfig(),
            OldConfig = new HttpClientConfig(),
            NewMetadata = metadata,
            OldClient = oldClient,
        };

    private static Probe EmptyProbe(out ServiceProvider services)
    {
        services = new ServiceCollection().BuildServiceProvider();
        return new Probe(services);
    }

    [Fact]
    public void Factory_GuardsEveryEntry()
    {
        var factory = EmptyProbe(out var services);
        using (services)
        {
            Assert.Throws<ArgumentNullException>(() => factory.Reuse(null!));
            Assert.Throws<ArgumentNullException>(() => factory.Configure(null!, new SocketsHttpHandler()));
            Assert.Throws<ArgumentNullException>(() => factory.Configure(Context(), null!));
            Assert.Throws<ArgumentNullException>(() => factory.Wrap(null!, new SocketsHttpHandler()));
            Assert.Throws<ArgumentNullException>(() => factory.Wrap(Context(), null!));
            Assert.Throws<ArgumentNullException>(() => factory.Connection(null!));
        }
    }

    [Fact]
    public void Reuse_NoConnectionCluster_KeepsItsClient()
    {
        // A cluster with no Connection metadata carries the no-connection identity; the
        // same config must reuse. A mixed-up sentinel (unknown vs none) would rebuild the
        // client on every check.
        var factory = EmptyProbe(out var services);
        using (services)
        {
            var oldClient = new HttpMessageInvoker(new SocketsHttpHandler());
            factory.Configure(Context(), new SocketsHttpHandler());

            Assert.True(factory.Reuse(Context(oldClient: oldClient)));
        }
    }

    [Fact]
    public void Reuse_UnknownConnectionCluster_KeepsItsClient()
    {
        // Naming a connection the registry does not know is still a stable identity —
        // distinct from "no connection", stable across checks.
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>())
            .Build();
        var secretSource = new ConfigurationSecretSource(config);
        var provider = new ConnectionRegistryProvider(
            new ConnectionBinder(config, new SecretAccessorFactory(secretSource), NullLoggerFactory.Instance),
            secretSource,
            NullLogger<ConnectionRegistryProvider>.Instance);
        var collection = new ServiceCollection();
        collection.AddTransient(_ => provider.Current);
        using var services = collection.BuildServiceProvider();
        var factory = new Probe(services);

        var metadata = new Dictionary<string, string> { [CredProxMetadata.Connection] = "ghost" };
        var oldClient = new HttpMessageInvoker(new SocketsHttpHandler());
        factory.Configure(Context(metadata), new SocketsHttpHandler());

        Assert.True(factory.Reuse(Context(metadata, oldClient)));
    }

    [Fact]
    public void Configure_ReloadedCertificate_ReachesTheHandler()
    {
        // The refresh call inside ConfigureHandler is what picks up a rotated secret on
        // the next client build; without it the handler keeps presenting the old certificate.
        using var cert1 = TestCertificates.CreateSelfSigned("dispatch-rot-1");
        using var cert2 = TestCertificates.CreateSelfSigned("dispatch-rot-2");
        var source = new ReloadableMemoryConfigurationSource(new Dictionary<string, string?>
        {
            ["CredProx:Connections:contoso:ClientCertificate"] = "secret:contoso-cert",
            ["CredProx:Secrets:contoso-cert"] = TestCertificates.PfxBase64(cert1),
        });
        var config = new ConfigurationBuilder().Add(source).Build();
        var reloadable = (ReloadableMemoryConfigurationProvider)config.Providers
            .OfType<ReloadableMemoryConfigurationProvider>().Single();
        var secretSource = new ConfigurationSecretSource(config);
        var provider = new ConnectionRegistryProvider(
            new ConnectionBinder(config, new SecretAccessorFactory(secretSource), NullLoggerFactory.Instance),
            secretSource,
            NullLogger<ConnectionRegistryProvider>.Instance);
        var collection = new ServiceCollection();
        collection.AddTransient(_ => provider.Current);
        using var services = collection.BuildServiceProvider();
        var factory = new Probe(services);
        var metadata = new Dictionary<string, string> { [CredProxMetadata.Connection] = "contoso" };

        // First build loads cert1 through the refresh call.
        var first = new SocketsHttpHandler();
        factory.Configure(Context(metadata), first);
        Assert.Equal(cert1.Thumbprint, GetClientCert(first)!.Thumbprint);

        reloadable.Set("CredProx:Secrets:contoso-cert", TestCertificates.PfxBase64(cert2));
        reloadable.Reload();

        var second = new SocketsHttpHandler();
        factory.Configure(Context(metadata), second);
        Assert.Equal(cert2.Thumbprint, GetClientCert(second)!.Thumbprint);
    }

    // The collection is typed X509Certificate; the handler only ever stores the
    // X509Certificate2 loaded from the connection's PFX.
    private static X509Certificate2? GetClientCert(SocketsHttpHandler handler) =>
        handler.SslOptions.ClientCertificates is { Count: > 0 } certs ? (X509Certificate2)certs[0] : null;

    private sealed class RecordingConnectionFeature : IConnectionFeature
    {
        public bool Configured { get; private set; }

        public void ConfigureHandler(SocketsHttpHandler handler) => Configured = true;
    }

    [Fact]
    public void Configure_RunsEveryConnectionFeature()
    {
        var feature = new RecordingConnectionFeature();
        var collection = new ServiceCollection();
        collection.AddSingleton<IConnectionFeature>(feature);
        using var services = collection.BuildServiceProvider();
        var factory = new Probe(services);

        factory.Configure(Context(), new SocketsHttpHandler());

        Assert.True(feature.Configured);
    }

    [Fact]
    public void ComposePipeline_Guards_AndWorksWithoutLogging()
    {
        // A bare host composes fine: the dispatcher falls back to the null logger when no
        // logging was registered.
        var collection = new ServiceCollection();
        collection.AddSingleton<IOptions<RefreshOn401Options>>(Options.Create(new RefreshOn401Options()));
        collection.AddSingleton(new CredProxPipeline([], [], []));
        using var services = collection.BuildServiceProvider();
        var factory = new Probe(services);
        var inner = new SocketsHttpHandler();

        Assert.Throws<ArgumentNullException>(() => factory.ComposePipeline(null!, inner));
        Assert.Throws<ArgumentNullException>(() => factory.ComposePipeline(Context(), null!));
        Assert.IsType<ResponseDispatchHandler>(factory.ComposePipeline(Context(), inner));
    }

    [Fact]
    public void Configure_PropagatesYarpBaseHandlerOptions()
    {
        // base.ConfigureHandler is the only applier of the cluster's HttpClientConfig to
        // the handler (pool limits, TLS settings); dropping the call silently ignores the
        // operator's pool options.
        var factory = EmptyProbe(out var services);
        using (services)
        {
            var context = new ForwarderHttpClientContext
            {
                ClusterId = "cluster-opts",
                NewConfig = new HttpClientConfig { MaxConnectionsPerServer = 42 },
                OldConfig = new HttpClientConfig(),
            };
            var handler = new SocketsHttpHandler();

            factory.Configure(context, handler);

            Assert.Equal(42, handler.MaxConnectionsPerServer);
        }
    }

    [Fact]
    public void Guards_PinTheirOwnParamNamesWhereBclAbsorbersWouldRenameTheThrow()
    {
        // Removing ComposePipeline's inner guard still throws ArgumentNullException — the
        // InnerHandler setter does it, but naming "value". Removing WrapHandler's guard
        // yields ComposePipeline's own "inner". The documented entry-point names survive
        // only as explicit assertions.
        var collection = new ServiceCollection();
        collection.AddSingleton<IOptions<RefreshOn401Options>>(Options.Create(new RefreshOn401Options()));
        collection.AddSingleton(new CredProxPipeline([], [], []));
        using var services = collection.BuildServiceProvider();
        var factory = new Probe(services);

        Assert.Equal("inner", Assert.Throws<ArgumentNullException>(
            () => factory.ComposePipeline(Context(), null!)).ParamName);
        Assert.Equal("handler", Assert.Throws<ArgumentNullException>(
            () => factory.Wrap(Context(), null!)).ParamName);
    }

    [Fact]
    public async Task ComposePipeline_DispatcherLogsThroughTheRegisteredLogger()
    {
        // The null-coalescing fallback must keep the registered logger: with NullLogger
        // the response-pipeline failure goes unlogged — the operator loses the fail-close
        // diagnosis (§3.5).
        var logs = new List<string?>();
        var collection = new ServiceCollection();
        collection.AddSingleton<IOptions<RefreshOn401Options>>(Options.Create(new RefreshOn401Options()));
        collection.AddSingleton(new CredProxPipeline([], [],
            [new ResponseFeature(_ => throw new InvalidOperationException("response triage failure"))]));
        collection.AddSingleton<ILogger<ResponseDispatchHandler>>(
            new LoggerFactory([new CapturingLoggerProvider(logs)]).CreateLogger<ResponseDispatchHandler>());
        using var services = collection.BuildServiceProvider();
        var factory = new Probe(services);
        var request = new HttpRequestMessage(HttpMethod.Get, "https://vendor.invalid/x");
        AttachState(request, new DefaultHttpContext());
        var chain = factory.ComposePipeline(
            Context(),
            new StubTransport(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent("upstream"),
            }));
        using var invoker = new HttpMessageInvoker(chain);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => invoker.SendAsync(request, default));

        Assert.Equal("response triage failure", error.Message);
        Assert.Contains("The CredProx response pipeline failed for this request.", logs);
    }

    [Fact]
    public async Task Transform_FeatureFailureAfterAbort_Propagates()
    {
        // The catch filter excludes already-aborted requests: the caller got its verdict
        // from the abort; swallowing a later failure hides a broken feature behind a
        // healthy-looking abort response. The throw must ride inside the aborting feature
        // itself — the pipeline breaks on abort, so no later feature would run.
        var pipeline = new CredProxPipeline(
            [
                new RequestFeature(
                    Stage.AuthenticateCaller,
                    async (ctx, _) =>
                    {
                        await ctx.Features.Get<CredProxRequestState>()!
                            .AbortAsync(StatusCodes.Status503ServiceUnavailable, "credprox.triaged", "Triaged.")
                            .AsTask();
                        throw new InvalidOperationException("post-abort failure");
                    }),
            ],
            [],
            []);
        var transform = BuildTransform(Provider(pipeline));
        var httpContext = new DefaultHttpContext { Response = { Body = new MemoryStream() } };
        var tctx = TransformerContext(
            httpContext,
            new HttpRequestMessage(HttpMethod.Get, "https://vendor.invalid/x"),
            new PathString("/api"));

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => transform.ApplyAsync(tctx).AsTask());

        Assert.Equal("post-abort failure", error.Message);
    }

    // ---- response dispatcher ----

    private sealed class StubTransport(HttpResponseMessage response) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(response);
    }

    private sealed class ResponseFeature(Func<CancellationToken, Task> act) : IResponseFeature
    {
        public int Calls { get; private set; }

        public ValueTask ApplyAsync(HttpContext context, CancellationToken cancellationToken)
        {
            Calls++;
            return new ValueTask(act(cancellationToken));
        }
    }

    private static CredProxRequestState AttachState(
        HttpRequestMessage request, DefaultHttpContext context)
    {
        var state = new CredProxRequestState(context, request);
        request.Options.Set(CredProxRequestOptions.RequestState, state);
        return state;
    }

    [Fact]
    public async Task Dispatch_NoState_PassesTheResponseThrough()
    {
        var feature = new ResponseFeature(_ => Task.CompletedTask);
        var pipeline = new CredProxPipeline([], [], [feature]);
        var handler = new ResponseDispatchHandler(
            new StubTransport(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent("upstream"),
            }),
            pipeline,
            NullLogger<ResponseDispatchHandler>.Instance);
        using var invoker = new HttpMessageInvoker(handler);

        var response = await invoker.SendAsync(
            new HttpRequestMessage(HttpMethod.Get, "https://vendor.invalid/x"), default);

        Assert.Equal("upstream", await response.Content.ReadAsStringAsync());
        Assert.Equal(0, feature.Calls);
    }

    [Fact]
    public async Task Dispatch_WithState_SetsProxyResponseAndRunsFeatures()
    {
        var feature = new ResponseFeature(_ => Task.CompletedTask);
        var pipeline = new CredProxPipeline([], [], [feature]);
        var handler = new ResponseDispatchHandler(
            new StubTransport(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent("upstream"),
            }),
            pipeline,
            NullLogger<ResponseDispatchHandler>.Instance);
        using var invoker = new HttpMessageInvoker(handler);

        var request = new HttpRequestMessage(HttpMethod.Get, "https://vendor.invalid/x");
        var context = new DefaultHttpContext();
        var state = AttachState(request, context);

        var response = await invoker.SendAsync(request, default);

        Assert.Equal(1, feature.Calls);
        Assert.Same(response, state.ProxyResponse);
    }

    [Fact]
    public async Task Dispatch_FeatureFailure_FailClosesAndLogs()
    {
        var logs = new List<string?>();
        var feature = new ResponseFeature(_ => Task.FromException(new InvalidOperationException("reshape failed")));
        var pipeline = new CredProxPipeline([], [], [feature]);
        var handler = new ResponseDispatchHandler(
            new StubTransport(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent("upstream"),
            }),
            pipeline,
            new LoggerFactory([new CapturingLoggerProvider(logs)]).CreateLogger<ResponseDispatchHandler>());
        using var invoker = new HttpMessageInvoker(handler);

        var request = new HttpRequestMessage(HttpMethod.Get, "https://vendor.invalid/x");
        AttachState(request, new DefaultHttpContext());

        await Assert.ThrowsAsync<InvalidOperationException>(() => invoker.SendAsync(request, default));

        Assert.Contains(
            "The CredProx response pipeline failed for this request.", logs);
    }

    // ---- transform provider (driven directly) ----

    private static CredProxTransformProvider Provider(
        CredProxPipeline pipeline,
        List<string?>? logs = null) =>
        new(
            pipeline,
            logs is null
                ? NullLogger<CredProxTransformProvider>.Instance
                : new LoggerFactory([new CapturingLoggerProvider(logs)]).CreateLogger<CredProxTransformProvider>(),
            new CredProxAuditRecorder(
                [],
                new CredProxAuditOptions(),
                TimeProvider.System,
                NullLogger<CredProxAuditRecorder>.Instance,
                new CredProxCoreOptions(),
                callerKeyOptions: null));

    private static RequestTransform BuildTransform(CredProxTransformProvider provider)
    {
        var builderContext = new TransformBuilderContext();
        provider.Apply(builderContext);
        return Assert.Single(builderContext.RequestTransforms);
    }

    // The YARP 2.3 shape: RequestTransformContext has settable properties, the query view
    // reads through the HttpRequest (its QueryString is empty-exactly when absent), and the
    // stored transforms are RequestTransform instances driven via ApplyAsync.
    private static RequestTransformContext TransformerContext(
        HttpContext httpContext,
        HttpRequestMessage proxyRequest,
        PathString path) =>
        new()
        {
            HttpContext = httpContext,
            ProxyRequest = proxyRequest,
            Path = path,
            Query = new QueryTransformContext(httpContext.Request),
        };

    private sealed class RequestFeature(Stage stage, Func<HttpContext, CancellationToken, Task> act) : IRequestFeature
    {
        public Stage Stage { get; } = stage;

        public ValueTask ApplyAsync(HttpContext context, CancellationToken cancellationToken) =>
            new(act(context, cancellationToken));
    }

    [Fact]
    public void Transform_ApplyGuardsNullContext()
    {
        var provider = Provider(new CredProxPipeline([], [], []));

        Assert.Throws<ArgumentNullException>(() => provider.Apply(null!));
    }

    [Fact]
    public async Task Transform_EmptyPath_StillCarriesRootPath()
    {
        // An outbound request with no path must carry "/" onward: the signing stage and
        // the audit record need a concrete path, not null.
        var pipeline = new CredProxPipeline([], [], []);
        var transform = BuildTransform(Provider(pipeline));
        var httpContext = new DefaultHttpContext { Response = { Body = new MemoryStream() } };
        var tctx = TransformerContext(
            httpContext,
            new HttpRequestMessage(HttpMethod.Get, "https://vendor.invalid/x"),
            default);

        await transform.ApplyAsync(tctx).AsTask();

        var state = httpContext.Features.Get<CredProxRequestState>()!;
        Assert.Equal("/", state.OutboundPath);
        Assert.Null(state.OutboundQuery);
    }

    [Fact]
    public async Task Transform_RealPath_Query_CarriedVerbatim()
    {
        var pipeline = new CredProxPipeline([], [], []);
        var transform = BuildTransform(Provider(pipeline));
        var httpContext = new DefaultHttpContext { Response = { Body = new MemoryStream() } };
        httpContext.Request.QueryString = new QueryString("?a=1");
        var tctx = TransformerContext(
            httpContext,
            new HttpRequestMessage(HttpMethod.Get, "https://vendor.invalid/x"),
            new PathString("/api/v1/orders"));

        await transform.ApplyAsync(tctx).AsTask();

        var state = httpContext.Features.Get<CredProxRequestState>()!;
        Assert.Equal("/api/v1/orders", state.OutboundPath);
        Assert.Equal("?a=1", state.OutboundQuery);
    }

    [Fact]
    public async Task Transform_OperationCanceled_Rethrows()
    {
        // Shutdown is not a pipeline failure: cancellation must escape, never a 500.
        var pipeline = new CredProxPipeline(
            [new RequestFeature(Stage.AuthenticateCaller, (_, ct) => Task.FromCanceled(ct))], [], []);
        var transform = BuildTransform(Provider(pipeline));
        var httpContext = new DefaultHttpContext { Response = { Body = new MemoryStream() } };
        var tctx = TransformerContext(
            httpContext,
            new HttpRequestMessage(HttpMethod.Get, "https://vendor.invalid/x"),
            new PathString("/"));
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        tctx.CancellationToken = cts.Token;

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => transform.ApplyAsync(tctx).AsTask());
        Assert.Equal(StatusCodes.Status200OK, httpContext.Response.StatusCode);
    }

    [Fact]
    public async Task Transform_AbortThenThrow_KeepsTheAbortedAnswer()
    {
        // A feature that short-circuited and THEN crashed must not have its answer
        // replaced by the catch-all 500 — the caller already got the real rejection.
        var feature = new RequestFeature(Stage.AuthenticateCaller, async (context, _) =>
        {
            var state = context.Features.Get<CredProxRequestState>()!;
            await state.AbortAsync(403, "credprox.triage", "Triaged");
            throw new InvalidOperationException("crashed after aborting");
        });
        var pipeline = new CredProxPipeline([feature], [], []);
        var logs = new List<string?>();
        var transform = BuildTransform(Provider(pipeline, logs));
        var httpContext = new DefaultHttpContext { Response = { Body = new MemoryStream() } };
        var tctx = TransformerContext(
            httpContext,
            new HttpRequestMessage(HttpMethod.Get, "https://vendor.invalid/x"),
            new PathString("/"));

        await Assert.ThrowsAsync<InvalidOperationException>(() => transform.ApplyAsync(tctx).AsTask());

        Assert.Equal(403, httpContext.Response.StatusCode);
        Assert.DoesNotContain(
            "The CredProx request pipeline failed for this request.", logs);
    }

    [Fact]
    public async Task Transform_UnexpectedFailure_NetsInternalErrorProblem()
    {
        var feature = new RequestFeature(
            Stage.AuthenticateCaller,
            (_, _) => Task.FromException(new InvalidOperationException("feature exploded")));
        var pipeline = new CredProxPipeline([feature], [], []);
        var logs = new List<string?>();
        var transform = BuildTransform(Provider(pipeline, logs));
        var httpContext = new DefaultHttpContext { Response = { Body = new MemoryStream() } };
        var tctx = TransformerContext(
            httpContext,
            new HttpRequestMessage(HttpMethod.Get, "https://vendor.invalid/x"),
            new PathString("/"));

        await transform.ApplyAsync(tctx).AsTask();

        Assert.Equal(500, httpContext.Response.StatusCode);
        var body = System.Text.Encoding.UTF8.GetString(((MemoryStream)httpContext.Response.Body).ToArray());
        Assert.Contains("credprox.internal_error", body, StringComparison.Ordinal);
        Assert.Contains("The CredProx request pipeline failed for this request.", logs);
    }

    [Fact]
    public async Task Transform_AbortSkipsTheDestinationAssignment()
    {
        // The abort means the forwarder must not receive a destination: the transform
        // returns before applying the resolved prefix.
        var feature = new RequestFeature(Stage.AuthenticateCaller, async (context, _) =>
        {
            var state = context.Features.Get<CredProxRequestState>()!;
            state.DestinationPrefix = "https://vendor.invalid/base";
            await state.AbortAsync(503, "credprox.switched_off", "Off");
        });
        var pipeline = new CredProxPipeline([feature], [], []);
        var transform = BuildTransform(Provider(pipeline));
        var httpContext = new DefaultHttpContext { Response = { Body = new MemoryStream() } };
        var tctx = TransformerContext(
            httpContext,
            new HttpRequestMessage(HttpMethod.Get, "https://vendor.invalid/x"),
            new PathString("/"));

        await transform.ApplyAsync(tctx).AsTask();

        Assert.Null(tctx.DestinationPrefix);
        Assert.Equal(503, httpContext.Response.StatusCode);
    }
}
