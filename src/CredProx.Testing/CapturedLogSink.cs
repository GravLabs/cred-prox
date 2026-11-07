using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;
using Xunit;

namespace CredProx.Testing;

/// <summary>
/// An <see cref="ILoggerProvider"/> that keeps every line the host logs — formatted
/// message, plus the exception text on its own line when one is attached — so a
/// conformance suite can assert the §5.2 rule that secret values never appear in logs at
/// any level.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class CapturedLogSink : ILoggerProvider
{
    private readonly object _gate = new();
    private readonly List<string> _lines = [];

    /// <summary>Every captured line, in order, as <c>[Level] category: message</c>.</summary>
    public IReadOnlyList<string> Lines
    {
        get { lock (_gate) { return [.. _lines]; } }
    }

    /// <summary>Drops the captured lines.</summary>
    public void Clear()
    {
        lock (_gate)
        {
            _lines.Clear();
        }
    }

    /// <summary>
    /// Fails with the first offending line when any captured line contains any of the
    /// given values. Empty values are ignored (every line contains the empty string).
    /// </summary>
    /// <param name="secretValues">The values that must never be logged.</param>
    public void AssertNoSecretValues(IEnumerable<string> secretValues)
    {
        ArgumentNullException.ThrowIfNull(secretValues);

        foreach (var value in secretValues.Where(v => !string.IsNullOrEmpty(v)))
        {
            var offender = Lines.FirstOrDefault(line => line.Contains(value, StringComparison.Ordinal));
            Assert.True(
                offender is null,
                $"A secret value appeared in the logs: {offender}");
        }
    }

    /// <inheritdoc />
    public ILogger CreateLogger(string categoryName) => new Sink(this, categoryName);

    /// <inheritdoc />
    public void Dispose()
    {
    }

    private sealed class Sink(CapturedLogSink owner, string category) : ILogger
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
            lock (owner._gate)
            {
                owner._lines.Add($"[{logLevel}] {category}: {formatter(state, exception)}");
                if (exception is not null)
                {
                    owner._lines.Add(exception.ToString());
                }
            }
        }
    }
}
