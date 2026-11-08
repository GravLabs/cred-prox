using Microsoft.Extensions.Logging;

namespace CredProx.Tests;

/// <summary>
/// Minimal capturing <see cref="ILoggerFactory">: records (category, level, formatted
/// message) triples. Operator-facing log lines are behaviour — the mutation triage kills
/// statement-removal and string-replacement mutants by asserting the line actually
/// appears with its content, not just that the code path ran.
/// </summary>
internal sealed class CapturingLoggerFactory : ILoggerFactory
{
    public List<(string Category, LogLevel Level, string Message)> Entries { get; } = [];

    public ILogger CreateLogger(string categoryName) => new CapturingLogger(this, categoryName);

    public void AddProvider(ILoggerProvider provider)
    {
    }

    public void Dispose()
    {
    }

    private sealed class CapturingLogger(CapturingLoggerFactory parent, string category) : ILogger
    {
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
            lock (parent.Entries)
            {
                parent.Entries.Add((category, logLevel, formatter(state, exception)));
            }
        }
    }
}
