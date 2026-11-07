using System.Collections;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using CredProx.Abstractions;
using Microsoft.Extensions.Logging;

namespace CredProx;

/// <summary>
/// The built-in <see cref="IAuditSink"/>: writes each (already redacted) record as one
/// <c>Information</c> log entry under the <c>CredProx.Audit</c> category. The fields are
/// emitted as structured log properties, so any logger — console, OTel logs, a log
/// aggregator — receives them as key/value data rather than a flat string.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class LoggerAuditSink : IAuditSink
{
    /// <summary>The logger category audit records are written under.</summary>
    public const string CategoryName = "CredProx.Audit";

    private readonly ILogger _logger;

    /// <summary>Creates the sink over the application's logging.</summary>
    /// <param name="loggerFactory">The logger factory.</param>
    public LoggerAuditSink(ILoggerFactory loggerFactory)
    {
        ArgumentNullException.ThrowIfNull(loggerFactory);
        _logger = loggerFactory.CreateLogger(CategoryName);
    }

    /// <inheritdoc />
    public ValueTask WriteAsync(
        string eventName,
        IReadOnlyDictionary<string, object?> fields,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(eventName);
        ArgumentNullException.ThrowIfNull(fields);

        var state = new AuditLogState(eventName, fields);
        _logger.Log(LogLevel.Information, default, state, null, static (s, _) => s.Message);
        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// The record as a structured-log state: event name plus every field as a named
    /// property, with a human-readable one-line message for plain-text logs.
    /// </summary>
    private sealed class AuditLogState : IReadOnlyList<KeyValuePair<string, object?>>
    {
        private readonly List<KeyValuePair<string, object?>> _items;

        public AuditLogState(string eventName, IReadOnlyDictionary<string, object?> fields)
        {
            _items = new List<KeyValuePair<string, object?>>(fields.Count + 3)
            {
                new("EventName", eventName),
            };
            foreach (var field in fields)
            {
                _items.Add(new KeyValuePair<string, object?>(field.Key, field.Value));
            }

            _items.Add(new KeyValuePair<string, object?>("{OriginalFormat}", "credprox.audit {EventName}"));
            Message = Render(eventName, fields);
        }

        public string Message { get; }

        private static string Render(string eventName, IReadOnlyDictionary<string, object?> fields)
        {
            var message = new StringBuilder("credprox.audit ").Append(eventName).Append(':');
            foreach (var field in fields)
            {
                message.Append(' ').Append(field.Key).Append('=').Append(RenderValue(field.Value));
            }

            return message.ToString();
        }

        private static string RenderValue(object? value) => value switch
        {
            null => "-",
            string text => text,
            IDictionary<string, object?> map =>
                "{" + string.Join(", ", map.Select(e => e.Key + "=" + RenderValue(e.Value))) + "}",
            _ => value.ToString() ?? "-",
        };

        public KeyValuePair<string, object?> this[int index] => _items[index];

        public int Count => _items.Count;

        public IEnumerator<KeyValuePair<string, object?>> GetEnumerator() => _items.GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
