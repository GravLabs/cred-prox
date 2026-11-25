using System.Net;
using System.Text;
using CredProx;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M50 fold LOW-3: the metering features' guard branches at unit level — the response
/// feature's early return (no state, short-circuited response, re-run) and the request
/// feature's three body shapes (bodyless, forwarder-owned content whose read stream is
/// refused by design, leg-owned content wrapped through the content with headers copied).
/// The end-to-end legs live in CredProxMeteringPipelineTests; these cells pin the branch
/// decisions the coverage report showed unexecuted.
/// </summary>
public sealed class CredProxMeteringFeatureTests
{
    private sealed class NotImplementedContent : HttpContent
    {
        // The shape the forwarder's own content presents: handing out no read stream.
        protected override Task<Stream> CreateContentReadStreamAsync() =>
            Task.FromException<Stream>(new NotImplementedException("forwarder-owned"));

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
            Task.FromException(new NotImplementedException("forwarder-owned"));

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }

    private sealed class ThrowingStreamContent : HttpContent
    {
        // An install-path fault (P15's shapes plus one the checker could not reach before):
        // the stream hands out, then throws when pumped — pre-fold this escaped ApplyAsync.
        public ThrowingStreamContent(string mediaType) =>
            Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(mediaType);

        protected override Task<Stream> CreateContentReadStreamAsync() =>
            Task.FromException<Stream>(new InvalidOperationException("install-path witness"));

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
            Task.FromException(new InvalidOperationException("install-path witness"));

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }

    private sealed class FakeProxyFeature : Yarp.ReverseProxy.Model.IReverseProxyFeature
    {
        // This YARP shape: Route is a RouteModel (no accessible RouteState), built from
        // (RouteConfig, ClusterState, HttpTransformer); ClusterState demands a real
        // ClusterModel (ArgumentNullException otherwise) though nothing here is invoked.
        // The metering path reads only Route.Config (metadata + route id), so the rest
        // of the feature stays empty.
        public FakeProxyFeature(IReadOnlyDictionary<string, string> metadata)
        {
            var cluster = new Yarp.ReverseProxy.Model.ClusterModel(
                new Yarp.ReverseProxy.Configuration.ClusterConfig { ClusterId = "unit" },
                new System.Net.Http.HttpMessageInvoker(new System.Net.Http.HttpClientHandler()));
            Route = new Yarp.ReverseProxy.Model.RouteModel(
                new Yarp.ReverseProxy.Configuration.RouteConfig
                {
                    RouteId = "unit",
                    ClusterId = "unit",
                    Match = new Yarp.ReverseProxy.Configuration.RouteMatch(),
                    Metadata = metadata,
                },
                new Yarp.ReverseProxy.Model.ClusterState("unit", cluster),
                Yarp.ReverseProxy.Forwarder.HttpTransformer.Default);
        }

        public Yarp.ReverseProxy.Model.RouteModel Route { get; }
        public Yarp.ReverseProxy.Model.ClusterModel Cluster { get; } = null!;
        public IReadOnlyList<Yarp.ReverseProxy.Model.DestinationState> AllDestinations { get; } = [];
        public IReadOnlyList<Yarp.ReverseProxy.Model.DestinationState> AvailableDestinations { get; set; } = [];
        public Yarp.ReverseProxy.Model.DestinationState? ProxiedDestination { get; set; }
    }

    private static DefaultHttpContext OptedInContext()
    {
        var context = new DefaultHttpContext();
        context.Features.Set<Yarp.ReverseProxy.Model.IReverseProxyFeature>(
            new FakeProxyFeature(new Dictionary<string, string> { ["CredProx.Metering.Usage"] = "anthropic" }));
        return context;
    }

    // A real transient reader for text/event-stream: without a registered reader
    // SelectReader returns null and the peek-install path — the code INFO-1 wraps —
    // is never reached, so the witness cell would pass at any pin (stub-arm trap).
    private static IServiceProvider MeteringServices() =>
        new ServiceCollection()
            .AddSingleton(new CredProxMeteringReloadGuard(
                new ConfigurationBuilder().Build(),
                NullLogger<CredProxMeteringReloadGuard>.Instance))
            .AddTransient<IUsageReader, AnthropicSseUsageReader>()
            .BuildServiceProvider();

    private static CredProxMeteringResponseFeature ResponseFeature() =>
        ResponseFeature(NullLogger<CredProxMeteringResponseFeature>.Instance);

    private static CredProxMeteringResponseFeature ResponseFeature(ILogger<CredProxMeteringResponseFeature> logger) =>
        new(MeteringServices(), new CredProxMeteringOptions(), logger);

    private sealed class CollectingLogger : ILogger<CredProxMeteringResponseFeature>
    {
        public List<string> Messages { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Messages.Add(formatter(state, exception));
    }

    [Fact]
    public async Task ResponseFeature_NoPipelineState_ReturnsUnchanged()
    {
        var context = new DefaultHttpContext();
        var bodyBefore = context.Response.Body;

        await ResponseFeature().ApplyAsync(context, default);

        Assert.Same(bodyBefore, context.Response.Body);
        Assert.Null(context.Features.Get<MeteringRequestState>());
    }

    [Fact]
    public async Task ResponseFeature_ShortCircuitedResponse_ReturnsUnchanged()
    {
        var context = new DefaultHttpContext();
        context.Features.Set(new MeteringRequestState());
        context.Features.Set(new CredProxRequestState(context, new HttpRequestMessage())); // no ProxyResponse yet
        var bodyBefore = context.Response.Body;

        await ResponseFeature().ApplyAsync(context, default);

        Assert.Same(bodyBefore, context.Response.Body);
    }

    [Fact]
    public async Task ResponseFeature_ReRunWithCountingAlreadyInstalled_ReturnsUnchanged()
    {
        var context = new DefaultHttpContext();
        var state = new CredProxRequestState(context, new HttpRequestMessage());
        state.ProxyResponse = new HttpResponseMessage(HttpStatusCode.OK);
        context.Features.Set(state);
        var metering = new MeteringRequestState { ResponseBytes = new CountingWriteStream(context.Response.Body) };
        context.Features.Set(metering);
        var bodyBefore = context.Response.Body;

        await ResponseFeature().ApplyAsync(context, default);

        Assert.Same(bodyBefore, context.Response.Body); // a re-run never re-wraps or re-counts
    }

    [Fact]
    public async Task RequestFeature_AlreadyWrapped_DoesNotReWrap()
    {
        var context = new DefaultHttpContext();
        var content = new StringContent("abc");
        context.Features.Set(new CredProxRequestState(context, new HttpRequestMessage { Content = content }));
        var existing = new MeteringRequestState();
        context.Features.Set(existing);

        await new CredProxMeteringRequestFeature().ApplyAsync(context, default);

        Assert.Same(existing, context.Features.Get<MeteringRequestState>());
        Assert.Same(content, context.Features.Get<CredProxRequestState>()!.ProxyRequest.Content);
    }

    [Fact]
    public async Task RequestFeature_NotACredProxRequest_SkipsQuietly()
    {
        var context = new DefaultHttpContext();

        await new CredProxMeteringRequestFeature().ApplyAsync(context, default);

        Assert.Null(context.Features.Get<MeteringRequestState>());
    }

    [Fact]
    public async Task RequestFeature_BodylessRequest_RecordsZeroWithoutACounter()
    {
        var context = new DefaultHttpContext();
        context.Features.Set(new CredProxRequestState(context, new HttpRequestMessage()));

        await new CredProxMeteringRequestFeature().ApplyAsync(context, default);

        var metering = context.Features.Get<MeteringRequestState>();
        Assert.NotNull(metering);
        Assert.Null(metering!.RequestBytes); // bodyless: zero request bytes, nothing to wrap
    }

    [Fact]
    public async Task RequestFeature_ForwarderOwnedContent_WrapsTheRequestBodyKeepsTheContent()
    {
        var context = new DefaultHttpContext();
        var body = new MemoryStream([1, 2, 3, 4]);
        context.Request.Body = body;
        var content = new NotImplementedContent();
        var state = new CredProxRequestState(context, new HttpRequestMessage { Content = content });
        context.Features.Set(state);

        await new CredProxMeteringRequestFeature().ApplyAsync(context, default);

        Assert.NotSame(body, context.Request.Body); // the pumped body is wrapped
        Assert.IsType<CountingReadStream>(context.Request.Body);
        Assert.Same(content, state.ProxyRequest.Content); // the forwarder's content reference stays
        Assert.NotNull(context.Features.Get<MeteringRequestState>()!.RequestBytes);
    }

    [Fact]
    public async Task RequestFeature_LegOwnedContent_WrapsThroughTheContentCopyingHeaders()
    {
        var context = new DefaultHttpContext();
        var content = new StringContent("payload");
        content.Headers.TryAddWithoutValidation("X-Custom", "keepme");
        var state = new CredProxRequestState(context, new HttpRequestMessage { Content = content });
        context.Features.Set(state);

        await new CredProxMeteringRequestFeature().ApplyAsync(context, default);

        var replacement = state.ProxyRequest.Content!;
        Assert.NotSame(content, replacement);
        Assert.Equal("keepme", Assert.Single(replacement.Headers.GetValues("X-Custom")));
        var bytes = await replacement.ReadAsStreamAsync();
        var buffer = new byte[16];
        var read = await bytes.ReadAsync(buffer);
        Assert.Equal("payload", Encoding.UTF8.GetString(buffer, 0, read)); // every byte preserved
        var counting = context.Features.Get<MeteringRequestState>()!.RequestBytes!;
        Assert.Equal(7, counting.BytesRead);
    }

    [Fact]
    public async Task PeekInstallFault_KeepsTheResponseAndMetersBytes()
    {
        // M50 fold INFO-1: a throw inside the peek-install path costs token counts only —
        // the response content stays the upstream one, byte metering still installs, and
        // ApplyAsync does not throw. Pre-wrap this escaped into the pipeline.
        var context = OptedInContext();
        context.Features.Set(new MeteringRequestState());
        var state = new CredProxRequestState(context, new HttpRequestMessage());
        var content = new ThrowingStreamContent("text/event-stream");
        state.ProxyResponse = new HttpResponseMessage(HttpStatusCode.OK) { Content = content };
        context.Features.Set(state);
        var logger = new CollectingLogger();

        await ResponseFeature(logger).ApplyAsync(context, default);

        Assert.Same(content, state.ProxyResponse!.Content); // caller's content untouched
        var metering = context.Features.Get<MeteringRequestState>()!;
        Assert.NotNull(metering.ResponseBytes); // bytes still metered
        Assert.Null(metering.Usage); // only the token counts are lost
        Assert.Contains(
            "CredProx usage peek could not be installed; the response is metered without token usage.",
            logger.Messages); // the degrade reaches the log, not the caller
    }
}
