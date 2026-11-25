using System.Collections.Concurrent;
using System.Net;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
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
/// M54 ADR-0009 item 3: the fail-closed usage-format gate. Unit cells drive
/// <see cref="CredProxUsageFormatConfigValidator"/> directly (the message names the route id
/// and the value; empty is opt-out; a broken reader set refuses the load). Host cells pin
/// both arms the ADR promises through the real YARP pipeline: startup refuses a route
/// naming an unknown format (nothing serves, the refusal reason is logged naming route and
/// value), and a reload introducing one is refused while the previously applied
/// configuration keeps serving — the same mechanism M5 established for credential
/// references. A registration cell proves the metering leg really contributes the
/// validator to the host's <see cref="IConfigValidator"/> set.
/// </summary>
public sealed class CredProxUsageFormatValidationTests
{
    private const string UsageKey = "CredProx.Metering.Usage";

    private sealed class RecordingReader(string format) : IUsageReader
    {
        public string Format => format;
        public bool CanRead(string? mediaType) => true;
        public void Observe(ReadOnlySpan<byte> utf8Chunk, bool endOfStream)
        {
        }

        public long? InputTokens { get; }
        public long? OutputTokens { get; }
    }

    private sealed class ThrowingReader : IUsageReader
    {
        public string Format => throw new InvalidOperationException("host reader is broken");
        public bool CanRead(string? mediaType) => true;
        public void Observe(ReadOnlySpan<byte> utf8Chunk, bool endOfStream)
        {
        }

        public long? InputTokens { get; }
        public long? OutputTokens { get; }
    }

    /// <summary>A host-style reader: claims a format and only application/json, the shape
    /// that duplicates a built-in JSON reader when the format name matches.</summary>
    private sealed class JsonCloneReader(string format) : IUsageReader
    {
        public string Format => format;
        public bool CanRead(string? mediaType) =>
            mediaType is not null && mediaType.Equals("application/json", StringComparison.OrdinalIgnoreCase);
        public void Observe(ReadOnlySpan<byte> utf8Chunk, bool endOfStream)
        {
        }

        public long? InputTokens { get; }
        public long? OutputTokens { get; }
    }

    private static CredProxUsageFormatConfigValidator Validator(params IUsageReader[] readers)
    {
        var services = new ServiceCollection();
        foreach (var reader in readers)
        {
            services.AddSingleton(reader);
        }

        return new CredProxUsageFormatConfigValidator(services.BuildServiceProvider());
    }

    private static RouteConfig Route(string routeId, string? usageValue) => new()
    {
        RouteId = routeId,
        ClusterId = routeId,
        Match = new RouteMatch { Path = "/x/{**catch-all}" },
        Metadata = usageValue is null
            ? new Dictionary<string, string>()
            : new Dictionary<string, string> { [UsageKey] = usageValue },
    };

    private static async Task<IList<Exception>> ErrorsAsync(
        CredProxUsageFormatConfigValidator validator, RouteConfig route) =>
        await validator.ValidateRouteAsync(route);

    [Theory]
    [InlineData("anthropic")]
    [InlineData("openai")]
    [InlineData("ANTHROPIC")] // ordinal, case-insensitive, like the feature's selection
    public async Task BuiltInFormats_AreAccepted(string format)
    {
        var validator = Validator(
            new RecordingReader("anthropic"), new RecordingReader("openai"));

        Assert.Empty(await ErrorsAsync(validator, Route("r-ok", format)));
    }

    [Fact]
    public async Task UnknownFormat_IsRefused_NamingRouteIdAndValue()
    {
        var validator = Validator(
            new RecordingReader("anthropic"), new RecordingReader("openai"));

        var errors = await ErrorsAsync(validator, Route("r-bad", "openaii"));

        var error = Assert.Single(errors);
        Assert.Contains("Route 'r-bad'", error.Message, StringComparison.Ordinal);
        Assert.Contains("names unknown usage format 'openaii'", error.Message, StringComparison.Ordinal);
        Assert.Contains(UsageKey, error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("true")] // the M50 preview spelling is gone: it names no registered format
    [InlineData(" ")] // whitespace is a name, and it names nothing
    public async Task LegacyAndBlankNames_AreRefused(string value)
    {
        var validator = Validator(new RecordingReader("anthropic"));

        var error = Assert.Single(await ErrorsAsync(validator, Route("r-legacy", value)));
        Assert.Contains("names unknown usage format", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AbsentAndEmptyValues_AreOptOut_NotErrors()
    {
        var validator = Validator(new RecordingReader("anthropic"));

        Assert.Empty(await ErrorsAsync(validator, Route("r-none", null)));
        Assert.Empty(await ErrorsAsync(validator, Route("r-empty", string.Empty)));
    }

    [Fact]
    public async Task HostReaderFormat_IsAccepted_OnItsOwnCaseSpelling()
    {
        var validator = Validator(new RecordingReader("acme-host"));

        Assert.Empty(await ErrorsAsync(validator, Route("r-host", "ACME-HOST")));
    }

    [Fact]
    public async Task BrokenReaderSet_RefusesTheLoad_NamingKindAndRefusal()
    {
        // A reader whose Format throws must not wave the value through: refusing a config
        // load keeps the previous one serving — the fail-closed direction available here.
        var validator = Validator(new ThrowingReader());

        var error = Assert.Single(await ErrorsAsync(validator, Route("r-throw", "openai")));
        Assert.Contains("Route 'r-throw'", error.Message, StringComparison.Ordinal);
        Assert.Contains("refusing the load", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ClusterValidation_IsSilentlyEmpty()
    {
        var validator = Validator(new RecordingReader("anthropic"));

        Assert.Empty(await validator.ValidateClusterAsync(new ClusterConfig { ClusterId = "c" }));
    }

    [Fact]
    public async Task DuplicateFormatSameMediaType_IsRefused_NamingBothImplementations()
    {
        // INFO-2: two readers share the format the route names and both accept the same
        // probed media type, so selection would fall to registration order — refused, and
        // the error names the format, the media type, and both implementations.
        var validator = Validator(new RecordingReader("openai"), new JsonCloneReader("openai"));

        var error = Assert.Single(await ErrorsAsync(validator, Route("r-dup", "openai")));
        Assert.Contains("Route 'r-dup'", error.Message, StringComparison.Ordinal);
        Assert.Contains("usage format 'openai'", error.Message, StringComparison.Ordinal);
        Assert.Contains("both accept 'application/json'", error.Message, StringComparison.Ordinal);
        Assert.Contains("RecordingReader", error.Message, StringComparison.Ordinal);
        Assert.Contains("JsonCloneReader", error.Message, StringComparison.Ordinal);
        Assert.Contains("refusing the load", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("openai")]
    [InlineData("anthropic")]
    public async Task BuiltInQuartet_IsNotADuplicate_JsonAndSseSplitMediaTypes(string format)
    {
        // The naive Format-string-only rule would refuse this stock registration and no
        // host could start. The probe rule sees the JSON/SSE media-type split per format
        // and accepts: all four built-ins stay legal.
        var validator = Validator(
            new AnthropicJsonUsageReader(), new AnthropicSseUsageReader(),
            new OpenAiJsonUsageReader(), new OpenAiSseUsageReader());

        Assert.Empty(await ErrorsAsync(validator, Route("r-builtin", format)));
    }

    [Fact]
    public async Task DuplicateOfAnUnclaimedFormat_IsAccepted_ScopedToTheRouteValue()
    {
        // A duplicated format the route does not name cannot steer this route's
        // selection, so it stays a legal registration for this route.
        var validator = Validator(
            new RecordingReader("openai"),
            new RecordingReader("anthropic"), new JsonCloneReader("anthropic"));

        Assert.Empty(await ErrorsAsync(validator, Route("r-other", "openai")));
    }

    [Fact]
    public void MeteringLeg_RegistersTheValidator_InAdditionToTheCoreOne()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CredProx:Metering:MaxUsageParseBytes"] = "1048576",
        }).Build();

        var services = new ServiceCollection();
        services.AddCredProxMetering(config);
        var provider = services.BuildServiceProvider();

        var validators = provider.GetServices<IConfigValidator>().ToList();
        Assert.Single(validators.OfType<CredProxUsageFormatConfigValidator>());
    }

    // ---- host arms: startup refusal and reload refusal through the real YARP load ----

    private sealed class CollectingLoggerProvider : ILoggerProvider
    {
        public ConcurrentQueue<string> Messages { get; } = [];

        public ILogger CreateLogger(string categoryName) => new Collector(Messages);

        public void Dispose()
        {
        }

        private sealed class Collector(ConcurrentQueue<string> messages) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => true;

            // The exception text joins the line: YARP logs the config-refusal reason as
            // the exception, not in the message template, and the assertion reads the
            // validator's wording.
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
                messages.Enqueue(formatter(state, exception) + " " + exception?.ToString());
        }
    }

    /// <summary>Stub upstream: the good load really serves (200) without a real network,
    /// so a refused reload has a previous configuration that can keep serving.</summary>
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

    private static Dictionary<string, string?> ProxyEntries(string usageValue) => new()
    {
        ["CredProx:Metering:MaxUsageParseBytes"] = "1048576",
        ["ReverseProxy:Routes:acme:ClusterId"] = "acme",
        ["ReverseProxy:Routes:acme:Match:Path"] = "/acme/{**catch-all}",
        ["ReverseProxy:Routes:acme:Metadata:" + UsageKey] = usageValue,
        ["ReverseProxy:Clusters:acme:Destinations:static:Address"] = "http://static.example/",
    };

    private static (IHost Host, HttpClient Client, ReloadableMemoryConfigurationProvider? Reloadable, CollectingLoggerProvider Logs) StartMeteringHost(
        IDictionary<string, string?> entries, bool reloadableSource, Action<IServiceCollection>? extraServices = null,
        Func<HttpRequestMessage, int, HttpResponseMessage>? responder = null)
    {
        var logs = new CollectingLoggerProvider();
        var builder = new HostBuilder()
            .ConfigureAppConfiguration(build =>
            {
                if (reloadableSource)
                {
                    build.Add(new ReloadableMemoryConfigurationSource(entries));
                }
                else
                {
                    build.AddInMemoryCollection(entries);
                }
            })
            .ConfigureServices((context, services) =>
            {
                services.AddRouting();
                services.AddReverseProxy()
                    .LoadFromConfig(context.Configuration.GetSection("ReverseProxy"))
                    .AddCredProx(context.Configuration);
                services.AddCredProx(context.Configuration).AddOperations();
                extraServices?.Invoke(services);
                services.AddSingleton<IForwarderHttpClientFactory>(sp => new StubTransportFactory(
                    sp, new StubHttpHandler(responder ?? ((_, _) => new HttpResponseMessage(HttpStatusCode.OK)))));
            })
            .ConfigureLogging(logging =>
            {
                logging.ClearProviders();
                logging.AddProvider(logs);
                // The factory filter defaults to Information and would drop the bounded
                // no-reader Debug diagnostic before it reaches the collector.
                logging.SetMinimumLevel(LogLevel.Debug);
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

        var reloadable = reloadableSource
            ? ((IConfigurationRoot)builder.Services.GetRequiredService<IConfiguration>()).Providers
                .OfType<ReloadableMemoryConfigurationProvider>().Single()
            : null;
        return (builder, builder.GetTestClient(), reloadable, logs);
    }

    [Theory]
    [InlineData("openaii")]
    [InlineData("true")]
    public void Startup_UnknownFormat_RefusesStartup_NamingRouteIdAndValue(string value)
    {
        // The measured YARP semantics: an invalid INITIAL config fails fast — the host
        // does not come up at all, the strongest fail-closed there is — and this
        // validator's error sits in the thrown tree naming the route id and the value.
        // (A RELOAD cannot throw at a running host: that path refuses the change and
        // keeps the previous config serving — pinned by the reload cell below.)
        var error = Assert.ThrowsAny<Exception>(
            () => StartMeteringHost(ProxyEntries(value), reloadableSource: false));
        Assert.Contains("Route 'acme'", error.ToString(), StringComparison.Ordinal);
        Assert.Contains("names unknown usage format '" + value + "'", error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Reload_UnknownFormatOnExistingRoute_Refused_OldConfigKeepsServing()
    {
        var entries = ProxyEntries("openai");
        var (host, client, reloadable, logs) = StartMeteringHost(entries, reloadableSource: true);
        using (host)
        {
            // The good load (format openai) serves.
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("http://proxy/acme/thing")).StatusCode);

            // A reload that breaks the format name on the live route: the validator runs
            // again, the whole load is refused, and the previously applied configuration —
            // the good one — keeps serving.
            reloadable!.Set("ReverseProxy:Routes:acme:Metadata:" + UsageKey, "openaii");
            reloadable.Reload();

            await Task.Delay(500); // let YARP's reload loop process (and reject) the change
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("http://proxy/acme/thing")).StatusCode);
            Assert.Contains(
                logs.Messages,
                m => m.Contains("names unknown usage format 'openaii'", StringComparison.Ordinal));
        }
    }

    [Fact]
    public void Startup_DuplicateFormatClaim_RefusesStartup_NamingBothReaders()
    {
        // INFO-2 through the real load: a host reader re-claiming openai on
        // application/json alongside the built-in JSON reader leaves selection to
        // registration order, so the host refuses to start and the refusal names both
        // implementations.
        var error = Assert.ThrowsAny<Exception>(() => StartMeteringHost(
            ProxyEntries("openai"),
            reloadableSource: false,
            extraServices: services => services.AddSingleton<IUsageReader, DuplicateOpenAiJsonReader>()));
        Assert.Contains("Route 'acme'", error.ToString(), StringComparison.Ordinal);
        Assert.Contains("OpenAiJsonUsageReader", error.ToString(), StringComparison.Ordinal);
        Assert.Contains("DuplicateOpenAiJsonReader", error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task NoReaderAcceptsMediaType_LogsOncePerTuple_NotPerResponse()
    {
        // INFO-1: with every registered reader declining the response media type the
        // route still serves and stays metered without token usage, and the operator
        // gets ONE bounded Debug line naming route, format and media type — a second
        // identical response logs nothing more. The stub answers OK with no content
        // type at all, which every built-in declines (null media type).
        var (host, client, _, logs) = StartMeteringHost(ProxyEntries("openai"), reloadableSource: false);
        using (host)
        {
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("http://proxy/acme/thing")).StatusCode);
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("http://proxy/acme/thing")).StatusCode);

            var line = Assert.Single(
                logs.Messages,
                m => m.Contains("no registered reader accepts", StringComparison.Ordinal));
            Assert.Contains("acme", line, StringComparison.Ordinal);
            Assert.Contains("openai", line, StringComparison.Ordinal);
            Assert.Contains("(none)", line, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task DistinctTuples_EachLogOnce_TheKeyIsTheWholeTuple()
    {
        // Reviewer item 1, distinct-tuple half. Three tuples that differ in exactly one
        // component at a time — (acme, openai, application/x-a), (acme2, openai, none),
        // (acme2, openai, application/x-a) — each log exactly one line, and a repeat of
        // the first logs nothing more. A key that drops ANY single component collapses
        // at least one pair here (global: all three into one line; route-only or
        // media-type-only: the two acme2 tuples; format-only: all three), so this fails
        // for every partial key, not only the process-wide one the fold shipped without.
        // Predicates name the full "route X names" phrase: "acme2" contains "acme".
        var entries = ProxyEntries("openai");
        entries["ReverseProxy:Routes:acme2:ClusterId"] = "acme2";
        entries["ReverseProxy:Routes:acme2:Match:Path"] = "/acme2/{**catch-all}";
        entries["ReverseProxy:Routes:acme2:Metadata:" + UsageKey] = "openai";
        entries["ReverseProxy:Clusters:acme2:Destinations:static:Address"] = "http://static.example/";
        // "application/x-a" is declined by every built-in (not the JSON type, no +json
        // suffix, not event-stream); the no-content response carries no media type at all.
        var (host, client, _, logs) = StartMeteringHost(
            entries,
            reloadableSource: false,
            responder: (_, index) => index == 2
                ? new HttpResponseMessage(HttpStatusCode.OK)
                : new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{}", Encoding.UTF8, "application/x-a"),
                });
        using (host)
        {
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("http://proxy/acme/thing")).StatusCode);
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("http://proxy/acme/thing")).StatusCode);
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("http://proxy/acme2/thing")).StatusCode);
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("http://proxy/acme2/thing")).StatusCode);

            var all = logs.Messages
                .Where(m => m.Contains("no registered reader accepts", StringComparison.Ordinal))
                .ToList();
            var acme = Assert.Single(all, l => l.Contains("route acme names", StringComparison.Ordinal));
            Assert.Contains("application/x-a", acme, StringComparison.Ordinal);
            var acme2 = all.Where(l => l.Contains("route acme2 names", StringComparison.Ordinal)).ToList();
            Assert.Equal(2, acme2.Count);
            Assert.Contains(acme2, l => l.Contains("(none)", StringComparison.Ordinal));
            Assert.Contains(acme2, l => l.Contains("application/x-a", StringComparison.Ordinal));
        }
    }

    [Fact]
    public async Task DistinctMediaTypesBeyondCap_LinesStopAtTheCap()
    {
        // The cap itself is pinned: 70 distinct media types are 70 distinct tuples, and
        // the line count stops at exactly 64 — a cap of 1 or a raised cap is RED here.
        // Every media type is declined by all built-ins (not the JSON type, no +json
        // suffix, not event-stream), so each tuple is genuinely unmatched.
        var (host, client, _, logs) = StartMeteringHost(
            ProxyEntries("openai"),
            reloadableSource: false,
            responder: (req, _) => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    "{}", Encoding.UTF8, "application/x-" + req.RequestUri!.AbsolutePath.Split('/')[2]),
            });
        using (host)
        {
            for (var i = 0; i < 70; i++)
            {
                Assert.Equal(
                    HttpStatusCode.OK,
                    (await client.GetAsync($"http://proxy/acme/probe-{i}")).StatusCode);
            }

            Assert.Equal(
                64,
                logs.Messages.Count(m => m.Contains("no registered reader accepts", StringComparison.Ordinal)));
        }
    }

    [Fact]
    public async Task SelectionThrow_ThenGenuineMismatchOnSameTuple_TheMismatchStillLogs()
    {
        // Both halves of the guarantee (skip the log in the throw path, and do
        // not let a swallowed throw spend the tuple's once-key): request one meets a
        // reader whose selection question throws. The Warning naming that failure logs;
        // the no-reader line does NOT — nobody was actually asked, and logging it here
        // would also spend the once-key for (acme, openai, null). Request two, same
        // tuple, selection declines cleanly: the genuine configuration mismatch still
        // logs, exactly once. Dropping the throw-path guard makes the first assertion
        // RED (the line fires for the wrong cause); consuming the key on the throw —
        // or never logging the declined case — makes the last assertion RED.
        var (host, client, _, logs) = StartMeteringHost(
            ProxyEntries("openai"),
            reloadableSource: false,
            extraServices: services => services.AddSingleton<IUsageReader, ThrowOnceSelectorReader>());
        using (host)
        {
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("http://proxy/acme/thing")).StatusCode);
            Assert.Contains(
                logs.Messages,
                m => m.Contains("usage-reader selection failed", StringComparison.Ordinal));
            Assert.DoesNotContain(
                logs.Messages,
                m => m.Contains("no registered reader accepts", StringComparison.Ordinal));

            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("http://proxy/acme/thing")).StatusCode);
            var line = Assert.Single(
                logs.Messages,
                m => m.Contains("route acme names usage format openai", StringComparison.Ordinal));
            Assert.Contains("no registered reader accepts", line, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task Reload_FormatMovesOnSameRoute_LogsTheNewTuplesLine()
    {
        // The once-key is the whole tuple across reload too, which no static-tuple cell
        // can reach: the route starts on openai and a no-media-type response logs
        // (acme, openai, none) once. A reload then moves the SAME route to anthropic —
        // a registered format whose readers decline the same media type, so the reload
        // is accepted — and the same response is a NEW tuple (acme, anthropic, none):
        // the line must appear again, naming the new format. A once-key that drops the
        // format component keys both moments identically and suppresses the second line
        // for the whole process: the same suppression class the per-tuple rule above
        // forbids, invisible to cells whose tuples share one format and to the cap cell
        // whose tuples differ only in media type.
        var (host, client, reloadable, logs) = StartMeteringHost(ProxyEntries("openai"), reloadableSource: true);
        using (host)
        {
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("http://proxy/acme/thing")).StatusCode);

            reloadable!.Set("ReverseProxy:Routes:acme:Metadata:" + UsageKey, "anthropic");
            reloadable.Reload();
            await Task.Delay(500); // let YARP's reload loop apply the new route

            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("http://proxy/acme/thing")).StatusCode);

            var all = logs.Messages
                .Where(m => m.Contains("no registered reader accepts", StringComparison.Ordinal))
                .ToList();
            Assert.Equal(2, all.Count);
            Assert.Contains(all, l => l.Contains("route acme names usage format openai", StringComparison.Ordinal));
            var moved = Assert.Single(
                all,
                l => l.Contains("route acme names usage format anthropic", StringComparison.Ordinal));
            Assert.Contains("(none)", moved, StringComparison.Ordinal);
        }
    }

    /// <summary>Host reader whose selection question throws on its first meeting with
    /// the null media type a request carries, then declines it. The startup validator
    /// probes the two metered media types instead and sees only declines, so the host
    /// starts; per-request selection meets the throw once and a clean decline after —
    /// exactly the throw-then-genuine-mismatch sequence the cell above drives.</summary>
    private sealed class ThrowOnceSelectorReader : IUsageReader
    {
        private int thrown;

        public string Format => "openai";
        public bool CanRead(string? mediaType)
        {
            if (mediaType is null && Interlocked.Exchange(ref thrown, 1) == 0)
            {
                throw new InvalidOperationException("host reader cannot answer");
            }

            return false;
        }

        public void Observe(ReadOnlySpan<byte> utf8Chunk, bool endOfStream)
        {
        }

        public long? InputTokens { get; }
        public long? OutputTokens { get; }
    }

    /// <summary>Host reader for the startup cell above: openai on application/json, the
    /// built-in JSON reader's exact claim.</summary>
    private sealed class DuplicateOpenAiJsonReader : IUsageReader
    {
        public string Format => "openai";
        public bool CanRead(string? mediaType) =>
            mediaType is not null && mediaType.Equals("application/json", StringComparison.OrdinalIgnoreCase);
        public void Observe(ReadOnlySpan<byte> utf8Chunk, bool endOfStream)
        {
        }

        public long? InputTokens { get; }
        public long? OutputTokens { get; }
    }
}
