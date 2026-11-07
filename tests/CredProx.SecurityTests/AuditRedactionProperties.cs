using System.Text;
using CredProx;
using CredProx.Abstractions;
using FsCheck;
using FsCheck.Xunit;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace CredProx.SecurityTests;

/// <summary>
/// §5.2 "Audit" as properties: redacted header and JSON-field names never carry their
/// value to a sink whatever that value was, unredacted names are not over-masked, and the
/// caller key value never reaches a sink even when the key header is explicitly captured
/// (§5.2:367).
/// </summary>
public sealed class AuditRedactionProperties
{
    private sealed class CapturingSink : IAuditSink
    {
        public List<(string EventName, IReadOnlyDictionary<string, object?> Fields)> Records { get; } = [];

        public ValueTask WriteAsync(
            string eventName,
            IReadOnlyDictionary<string, object?> fields,
            CancellationToken cancellationToken)
        {
            Records.Add((eventName, fields));
            return ValueTask.CompletedTask;
        }

        // The record is written on response completion, which can land just after the
        // client sees the finished response.
        public async Task<(string EventName, IReadOnlyDictionary<string, object?> Fields)> WaitForRecordAsync()
        {
            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(10);
            while (DateTime.UtcNow < deadline)
            {
                if (Records.Count > 0)
                {
                    return Records[0];
                }

                await Task.Delay(10);
            }

            throw new TimeoutException("The audit record never arrived.");
        }
    }

    // Header-safe alphabet: the property is about arbitrary key content reaching the
    // sink, not about HTTP header grammar, which the client would enforce first.
    private static string Sanitize(string generated) =>
        new([.. generated.Where(char.IsLetterOrDigit)]);

    private static string Flatten(IReadOnlyDictionary<string, object?> fields)
    {
        var sb = new StringBuilder();
        Append(sb, fields);
        return sb.ToString();

        static void Append(StringBuilder sb, IReadOnlyDictionary<string, object?> map)
        {
            foreach (var (key, value) in map)
            {
                sb.Append(key).Append('=');
                if (value is IReadOnlyDictionary<string, object?> nested)
                {
                    Append(sb, nested);
                }
                else
                {
                    sb.Append(value);
                }
            }
        }
    }

    [Property(MaxTest = 200)]
    public void RedactedNames_NeverCarryTheirValue_UnredactedNamesSurvive(NonNull<string> generated)
    {
        var value = "val-" + Sanitize(generated.Get);
        var fields = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["headers"] = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["Authorization"] = "Bearer " + value,
                ["Cookie"] = value,
                ["X-Kept"] = value,
            },
            ["body"] = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["access_token"] = value,
                ["nested"] = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                {
                    ["private_key"] = value,
                },
            },
        };

        AuditRedactor.Redact(fields, AuditRedactor.DefaultRedactHeaders, AuditRedactor.DefaultRedactJsonFields);

        var headers = (IDictionary<string, object?>)fields["headers"]!;
        Assert.Equal(AuditRedactor.Masked, headers["Authorization"]);
        Assert.Equal(AuditRedactor.Masked, headers["Cookie"]);
        Assert.Equal(value, headers["X-Kept"]); // not a redacted name: untouched

        var body = (IDictionary<string, object?>)fields["body"]!;
        Assert.Equal(AuditRedactor.Masked, body["access_token"]);
        var nested = (IDictionary<string, object?>)body["nested"]!;
        Assert.Equal(AuditRedactor.Masked, nested["private_key"]); // masked at depth too
    }

    // Hosting a server per case is heavier than a unit call, so fewer cases — the
    // completion seam (Response.OnCompleted) only fires under a real server anyway.
    [Property(MaxTest = 50)]
    public async Task CallerKeyValue_NeverReachesASink_EvenWhenTheKeyHeadersAreCaptured(NonNull<string> generated)
    {
        var keyValue = "key-" + Sanitize(generated.Get);
        var sink = new CapturingSink();
        var recorder = new CredProxAuditRecorder(
            [sink],
            new CredProxAuditOptions { IncludeHeaders = ["X-CredProx-Key", "X-Caller-Key"] },
            TimeProvider.System,
            NullLogger<CredProxAuditRecorder>.Instance,
            new CredProxCoreOptions(),
            new CallerKeyOptions { HeaderName = "X-Caller-Key" });

        using var host = new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.Configure(app => app.Run(async context =>
                {
                    recorder.Begin(context);
                    await context.Response.WriteAsync("ok");
                }));
            })
            .Start();

        var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy/api/thing");
        request.Headers.Add("X-CredProx-Key", keyValue);
        request.Headers.Add("X-Caller-Key", keyValue);
        await host.GetTestClient().SendAsync(request);

        var record = await sink.WaitForRecordAsync();
        Assert.DoesNotContain(keyValue, Flatten(record.Fields), StringComparison.Ordinal);
    }
}
