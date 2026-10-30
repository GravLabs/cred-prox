using BenchmarkDotNet.Attributes;
using CredProx;

namespace CredProx.Benchmarks;

/// <summary>
/// Audit redaction (plan §3.3 "Audit"): every audited request's field map is walked and
/// the configured headers and nested JSON fields are masked before any sink sees them.
/// The record is built fresh per operation — like the pipeline does per request — so the
/// measured cost includes the map the walk consumes.
/// </summary>
[MemoryDiagnoser]
public class AuditRedactorBenchmarks
{
    private static Dictionary<string, object?> BuildRecord() => new()
    {
        ["credential"] = "acme",
        ["caller"] = "agent-7",
        ["headers"] = new Dictionary<string, object?>
        {
            ["Authorization"] = "Bearer super-secret-token",
            ["X-Api-Key"] = "key-value",
            ["X-Trace"] = "trace-visible",
            ["Content-Type"] = "application/json",
        },
        ["body"] = new Dictionary<string, object?>
        {
            ["access_token"] = "tok-secret",
            ["profile"] = new Dictionary<string, object?>
            {
                ["refresh_token"] = "refresh-secret",
                ["display_name"] = "visible",
            },
        },
    };

    /// <summary>Header masking + recursive JSON-field walk over a typical audit record.</summary>
    [Benchmark]
    public IDictionary<string, object?> Redact()
    {
        var record = BuildRecord();
        AuditRedactor.Redact(record, AuditRedactor.DefaultRedactHeaders, AuditRedactor.DefaultRedactJsonFields);
        return record;
    }
}
