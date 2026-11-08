using System.Diagnostics;
using CredProx;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Logging;
using Xunit;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Model;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage of <see cref="CredProxAuditRecorder"/>: constructor and Begin
/// guards, the headers that must never reach a record regardless of configuration, the
/// headers field's presence rule, the live-destination preference over route metadata,
/// trace-id sourcing, and every sink-failure log path (fault, cancel, abandon, and the
/// last net around record construction).
/// </summary>
public sealed class AuditRecorderSurvivorTests
{
    private sealed class CapturingSink : IAuditSink
    {
        public List<(string Event, IReadOnlyDictionary<string, object?> Fields)> Records { get; } = [];

        public ValueTask WriteAsync(
            string eventName,
            IReadOnlyDictionary<string, object?> fields,
            CancellationToken cancellationToken)
        {
            Records.Add((eventName, fields));
            return ValueTask.CompletedTask;
        }
    }

    private sealed class RecordingLogger : ILogger<CredProxAuditRecorder>
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

    private static CredProxAuditRecorder CreateRecorder(
        IAuditSink sink,
        CredProxAuditOptions? options = null,
        RecordingLogger? logger = null,
        CredProxCoreOptions? coreOptions = null,
        CallerKeyOptions? callerKeys = null) =>
        new(
            [sink],
            options ?? new CredProxAuditOptions(),
            TimeProvider.System,
            logger ?? new RecordingLogger(),
            coreOptions ?? new CredProxCoreOptions(),
            callerKeys);

    /// <summary>
    /// A DefaultHttpContext never runs <c>Response.OnCompleted</c> callbacks: <c>CompleteAsync</c>
    /// completes the body but nothing executes the registered list. This feature records the
    /// callbacks so <see cref="FireOnCompletedAsync"/> can run them at the point a real host
    /// would (the full-host audit integration tests cover the production wiring itself).
    /// </summary>
    private sealed class CapturingResponseFeature : IHttpResponseFeature
    {
        public List<Func<Task>> OnCompletedCallbacks { get; } = [];

        public int StatusCode { get; set; } = 200;

        public string? ReasonPhrase { get; set; }

        public IHeaderDictionary Headers { get; set; } = new HeaderDictionary();

        public Stream Body { get; set; } = Stream.Null;

        public bool HasStarted => false;

        public void OnStarting(Func<Task> callback)
        {
        }

        public void OnStarting(Func<object, Task> callback, object state)
        {
        }

        public void OnCompleted(Func<Task> callback) => OnCompletedCallbacks.Add(callback);

        public void OnCompleted(Func<object, Task> callback, object state) =>
            OnCompletedCallbacks.Add(() => callback(state));
    }

    private static DefaultHttpContext NewContext()
    {
        var context = new DefaultHttpContext();
        context.Features.Set<IHttpResponseFeature>(new CapturingResponseFeature());
        context.Response.Body = new MemoryStream();
        return context;
    }

    private static async Task FireOnCompletedAsync(HttpContext context)
    {
        await context.Response.CompleteAsync();
        var feature = (CapturingResponseFeature)context.Features.Get<IHttpResponseFeature>()!;
        foreach (var callback in feature.OnCompletedCallbacks)
        {
            await callback();
        }
    }

    private static async Task<(HttpContext Context, MemoryStream Body)> RunAsync(
        CredProxAuditRecorder recorder,
        Action<HttpContext>? configureFeatures = null,
        string body = "hello")
    {
        var context = NewContext();
        var inner = new MemoryStream();
        context.Response.Body = inner;
        configureFeatures?.Invoke(context);

        recorder.Begin(context);
        await context.Response.WriteAsync(body);
        await FireOnCompletedAsync(context);
        return (context, inner);
    }

    [Fact]
    public void Constructor_GuardsEveryNullArgument()
    {
        var sink = new CapturingSink();
        var options = new CredProxAuditOptions();
        var logger = new RecordingLogger();

        Assert.Throws<ArgumentNullException>(() => new CredProxAuditRecorder(
            null!, options, TimeProvider.System, logger, new CredProxCoreOptions(), null));
        Assert.Throws<ArgumentNullException>(() => new CredProxAuditRecorder(
            [sink], null!, TimeProvider.System, logger, new CredProxCoreOptions(), null));
        Assert.Throws<ArgumentNullException>(() => new CredProxAuditRecorder(
            [sink], options, null!, logger, new CredProxCoreOptions(), null));
        Assert.Throws<ArgumentNullException>(() => new CredProxAuditRecorder(
            [sink], options, TimeProvider.System, null!, new CredProxCoreOptions(), null));
        Assert.Throws<ArgumentNullException>(() => new CredProxAuditRecorder(
            [sink], options, TimeProvider.System, logger, null!, null));
    }

    [Fact]
    public void Begin_NullContext_Throws()
    {
        var recorder = CreateRecorder(new CapturingSink());
        Assert.Throws<ArgumentNullException>(() => recorder.Begin(null!));
    }

    [Fact]
    public async Task KeyHeaders_AreMaskedRegardlessOfRedactionConfig()
    {
        var sink = new CapturingSink();
        var options = new CredProxAuditOptions();
        options.IncludeHeaders.Add("X-Mine-Inbound");
        options.IncludeHeaders.Add("X-Custom-Secret");
        options.IncludeHeaders.Add("   "); // a blank entry carries no header
        options.RedactHeaders.Add("X-Custom-Secret");
        var recorder = CreateRecorder(
            sink,
            options,
            coreOptions: new CredProxCoreOptions { InboundKeyHeader = "X-Mine-Inbound" });

        var context = NewContext();
        context.Request.Headers["X-Mine-Inbound"] = "inbound-key";
        context.Request.Headers["X-Custom-Secret"] = "custom-value";
        recorder.Begin(context);
        await FireOnCompletedAsync(context);

        var headers = Assert.IsAssignableFrom<IReadOnlyDictionary<string, object?>>(
            sink.Records.Single().Fields["headers"]);
        Assert.Equal("[redacted]", headers["X-Mine-Inbound"]); // inbound key header
        Assert.Equal("[redacted]", headers["X-Custom-Secret"]); // configured redact name
        Assert.Equal(2, headers.Count); // the blank IncludeHeaders entry was skipped
    }

    [Fact]
    public async Task NoIncludeHeaders_RecordHasNoHeadersField()
    {
        var sink = new CapturingSink();
        await RunAsync(CreateRecorder(sink));

        Assert.False(sink.Records.Single().Fields.ContainsKey("headers"));
    }

    [Fact]
    public async Task Vendor_PrefersTheLiveDestinationOverRouteMetadata()
    {
        var sink = new CapturingSink();
        await RunAsync(
            CreateRecorder(sink),
            configureFeatures: context =>
            {
                SetRouteMetadata(context, "metadata-vendor");
                SetState(context, DestinationName: "live-vendor");
            });

        Assert.Equal("live-vendor", sink.Records.Single().Fields["vendor"]);
    }

    [Fact]
    public async Task Vendor_FallsBackToRouteMetadataWithoutALiveDestination()
    {
        var sink = new CapturingSink();
        await RunAsync(
            CreateRecorder(sink),
            configureFeatures: context => SetRouteMetadata(context, "metadata-vendor"));

        Assert.Equal("metadata-vendor", sink.Records.Single().Fields["vendor"]);
    }

    [Fact]
    public async Task TraceId_ComesFromTheAmbientActivityElseTheRequest()
    {
        var sink = new CapturingSink();
        var recorder = CreateRecorder(sink);
        string activityTrace;
        var context = NewContext();
        using (var activity = new Activity("audit-triage").Start())
        {
            activityTrace = activity.TraceId.ToString();
            recorder.Begin(context);
        }

        await FireOnCompletedAsync(context);
        Assert.Equal(activityTrace, sink.Records.Single().Fields["traceId"]);
        Assert.NotEqual(context.TraceIdentifier, activityTrace);

        Activity.Current = null;
        var sink2 = new CapturingSink();
        var (context2, _) = await RunAsync(CreateRecorder(sink2));
        Assert.Equal(context2.TraceIdentifier, sink2.Records.Single().Fields["traceId"]);
    }

    [Fact]
    public async Task SinkFault_LogsTheFailureAndNeverSurfaces()
    {
        var logger = new RecordingLogger();
        var recorder = CreateRecorder(new FaultySink(() => new InvalidOperationException("sink down")), logger: logger);

        await RunAsync(recorder); // must not throw

        var entry = Assert.Single(logger.Entries, e => e.Level == LogLevel.Warning);
        Assert.Contains("failed", entry.Message, StringComparison.Ordinal);
        Assert.Contains(nameof(FaultySink), entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SinkHonoursCancellation_LogsTheTimeoutBound()
    {
        var logger = new RecordingLogger();
        var options = new CredProxAuditOptions { SinkTimeout = TimeSpan.FromMilliseconds(50) };
        var recorder = CreateRecorder(new CancellingSink(), options, logger);

        await RunAsync(recorder);

        var entry = Assert.Single(logger.Entries, e => e.Level == LogLevel.Warning);
        Assert.Contains("timed out after", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SinkIgnoringTheToken_IsAbandonedWithinTheBound()
    {
        var logger = new RecordingLogger();
        var options = new CredProxAuditOptions { SinkTimeout = TimeSpan.FromMilliseconds(50) };
        var recorder = CreateRecorder(new IgnoringSink(TimeSpan.FromMilliseconds(500)), options, logger);

        var sw = Stopwatch.StartNew();
        await RunAsync(recorder);
        sw.Stop();

        // Abandon, not join: the completed request waits no part of the sink's own delay.
        Assert.True(sw.Elapsed < TimeSpan.FromMilliseconds(400), $"abandon took {sw.ElapsedMilliseconds} ms");
        var entry = Assert.Single(logger.Entries, e => e.Level == LogLevel.Warning);
        Assert.Contains("abandoned", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RecordConstructionFault_LogsTheLastNetAndNeverSurfaces()
    {
        var logger = new RecordingLogger();
        var sink = new CapturingSink();

        await RunAsync(
            CreateRecorder(sink, logger: logger),
            configureFeatures: context => context.Features.Set<IReverseProxyFeature>(new PoisonedProxyFeature()));

        Assert.Empty(sink.Records);
        var entry = Assert.Single(logger.Entries, e => e.Level == LogLevel.Warning);
        Assert.Contains(
            "The CredProx audit record for this request could not be written.",
            entry.Message,
            StringComparison.Ordinal);
    }

    // ---- feature helpers ----

    private static void SetRouteMetadata(HttpContext context, string vendor)
    {
        var route = new RouteConfig
        {
            RouteId = "r1",
            Match = new RouteMatch { Path = "/{**catch-all}" },
            Metadata = new Dictionary<string, string> { [CredProxMetadata.Destination] = vendor },
        };
        context.Features.Set<IReverseProxyFeature>(
            new StubProxyFeature(new RouteModel(route, cluster: null, HttpTransformer.Default))); // transformer never read
    }

    private static void SetState(HttpContext context, string DestinationName)
    {
        var state = new CredProxRequestState(context, new HttpRequestMessage())
        {
            Destination = new DestinationEntry(DestinationName, new DestinationDefinition(), null),
        };
        context.Features.Set(state);
    }

    private sealed class StubProxyFeature(RouteModel route) : IReverseProxyFeature
    {
        public RouteModel Route { get; } = route;

        public ClusterModel Cluster => null!; // never read by the recorder

        public IReadOnlyList<DestinationState> AllDestinations => [];

        public IReadOnlyList<DestinationState> AvailableDestinations { get; set; } = [];

        public DestinationState? ProxiedDestination { get; set; }
    }

    private sealed class PoisonedProxyFeature : IReverseProxyFeature
    {
        public RouteModel Route => throw new InvalidOperationException("poisoned feature");

        public ClusterModel Cluster => null!;

        public IReadOnlyList<DestinationState> AllDestinations => [];

        public IReadOnlyList<DestinationState> AvailableDestinations { get; set; } = [];

        public DestinationState? ProxiedDestination { get; set; }
    }

    // ---- sinks exercising each failure path ----

    private sealed class FaultySink(Func<Exception> fault) : IAuditSink
    {
        public ValueTask WriteAsync(
            string eventName, IReadOnlyDictionary<string, object?> fields, CancellationToken cancellationToken) =>
            throw fault();
    }

    private sealed class CancellingSink : IAuditSink
    {
        // An honest cancellation fault must win the WhenAny race against the bound's own
        // timer, so the failure lands before the timeout elapses (an infinite token-delayed
        // wait races that timer and can take the abandon path instead).
        public ValueTask WriteAsync(
            string eventName, IReadOnlyDictionary<string, object?> fields, CancellationToken cancellationToken) =>
            ValueTask.FromException(new TaskCanceledException("sink observed its token"));
    }

    private sealed class IgnoringSink(TimeSpan delay) : IAuditSink
    {
        public async ValueTask WriteAsync(
            string eventName, IReadOnlyDictionary<string, object?> fields, CancellationToken cancellationToken)
        {
            await Task.Delay(delay, CancellationToken.None); // ignores the bound entirely
        }
    }

    [Fact]
    public async Task FactoryBuiltRecorder_HonorsTheAuditOptionsFromTheContainer()
    {
        // The built-by-DI recorder must carry the options the audit module registered:
        // a silent fallback to the shipped 5 s defaults when 123 ms was configured is
        // config loss the host cannot see (M31 triage: the factory's options fallback
        // was unobserved — a 2 s slow sink abandons at the configured bound but
        // completes under the default).
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["CredProx:Audit:SinkTimeout"] = "00:00:00.123",
            })
            .Build();
        var logger = new RecordingLogger();
        var services = new ServiceCollection();
        services.AddReverseProxy().AddCredProx(config);
        services.AddCredProxAudit(config);
        services.AddSingleton<IAuditSink>(new IgnoringSink(TimeSpan.FromSeconds(2)));
        services.AddSingleton<ILogger<CredProxAuditRecorder>>(logger); // after AddLogging: last registration serves
        var recorder = services.BuildServiceProvider().GetRequiredService<CredProxAuditRecorder>();

        await RunAsync(recorder);

        Assert.Contains(
            logger.Entries,
            e => e.Message.Contains("00:00:00.1230000", StringComparison.Ordinal)
                && e.Message.Contains("bound and was abandoned", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ConfiguredJsonFields_MaskTheirEntriesInRecordMaps()
    {
        // §5.2 "redacted JSON fields never reach the sink": names added through the
        // options join the walker's set (defaults aside) and mask every entry of that
        // name in a captured map — blank entries add no name.
        var sink = new CapturingSink();
        var options = new CredProxAuditOptions();
        options.IncludeHeaders.Add("X-Login-Body");
        options.RedactJsonFields.Add("X-Login-Body"); // configured name, not a default
        options.RedactJsonFields.Add("   ");          // carries no field name
        var recorder = CreateRecorder(sink, options);

        await RunAsync(recorder, context => context.Request.Headers["X-Login-Body"] = "login-payload");

        var headers = Assert.IsAssignableFrom<IReadOnlyDictionary<string, object?>>(
            sink.Records.Single().Fields["headers"]);
        Assert.Equal("[redacted]", headers["X-Login-Body"]);
    }
}
