using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Logging;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage of <see cref="LoggerAuditSink"/>: the argument guards, the
/// structured-property shape a log aggregator consumes (EventName, per-field items,
/// the {OriginalFormat} terminator), and the one-line message renderer (null dash,
/// map braces, and the ToString-null fallback).
/// </summary>
public sealed class LoggerAuditSinkSurvivorTests
{
    private sealed class CapturingLogger : ILogger
    {
        public List<(LogLevel Level, List<KeyValuePair<string, object?>> Items, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var items = state is IEnumerable<KeyValuePair<string, object?>> pairs
                ? pairs.ToList()
                : [];
            Entries.Add((logLevel, items, formatter(state, exception)));
        }
    }

    private sealed class CapturingFactory(CapturingLogger logger) : ILoggerFactory
    {
        public string? CreatedCategory { get; private set; }

        public ILogger Logger { get; } = logger;

        public ILogger CreateLogger(string categoryName)
        {
            CreatedCategory = categoryName;
            return Logger;
        }

        public void AddProvider(ILoggerProvider provider)
        {
        }

        public void Dispose()
        {
        }
    }

    private static (LoggerAuditSink Sink, CapturingLogger Logger, CapturingFactory Factory) Create()
    {
        var logger = new CapturingLogger();
        var factory = new CapturingFactory(logger);
        return (new LoggerAuditSink(factory), logger, factory);
    }

    [Fact]
    public void Constructor_NullFactory_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new LoggerAuditSink(null!));
    }

    [Fact]
    public async Task WriteAsync_RejectsNullEventNameOrNullFields()
    {
        var (sink, _, _) = Create();

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => sink.WriteAsync(null!, new Dictionary<string, object?>(), default).AsTask());
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => sink.WriteAsync("credprox.audit.proxied", null!, default).AsTask());
    }

    [Fact]
    public async Task SinkLogsUnderTheAuditCategory_Information()
    {
        var (sink, logger, factory) = Create();

        await sink.WriteAsync("credprox.audit.proxied", new Dictionary<string, object?>(), default);

        Assert.Equal(LoggerAuditSink.CategoryName, factory.CreatedCategory);
        Assert.Equal("CredProx.Audit", LoggerAuditSink.CategoryName);
        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Information, entry.Level);
    }

    [Fact]
    public async Task StateCarriesEventNameFields_AndTheOriginalFormatTerminator()
    {
        var (sink, logger, _) = Create();
        var fields = new Dictionary<string, object?>
        {
            ["method"] = "GET",
            ["status"] = 200,
        };

        await sink.WriteAsync("credprox.audit.rejected", fields, default);

        var items = Assert.Single(logger.Entries).Items;
        Assert.Equal("EventName", items[0].Key); // the structured event-name property
        Assert.Equal("credprox.audit.rejected", items[0].Value);
        Assert.Equal("method", items[1].Key); // every field is a named property, in order
        Assert.Equal("GET", items[1].Value);
        Assert.Equal("status", items[2].Key);
        Assert.Equal(200, items[2].Value);
        Assert.Equal("{OriginalFormat}", items[^1].Key); // structured-logging terminator
        Assert.Equal("credprox.audit {EventName}", items[^1].Value);
        Assert.Equal(fields.Count + 2, items.Count);
    }

    [Fact]
    public async Task Message_RendersNullDash_MapBraces_AndNullToStringFallback()
    {
        var (sink, logger, _) = Create();
        var fields = new Dictionary<string, object?>
        {
            ["a"] = "text",
            ["b"] = null,
            ["c"] = 42,
            ["headers"] = new Dictionary<string, object?>
            {
                ["x"] = "1",
                ["y"] = null,
                ["z"] = new NullToString(),
            },
        };

        await sink.WriteAsync("evt", fields, default);

        Assert.Equal(
            "credprox.audit evt: a=text b=- c=42 headers={x=1, y=-, z=-}",
            Assert.Single(logger.Entries).Message);
    }

    private sealed class NullToString
    {
        public override string? ToString() => null;
    }
}
