using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http;

namespace CredProx;

/// <summary>
/// Writes the <c>application/problem+json</c> short-circuit responses of
/// <c>docs/credprox-plan.md</c> §3.4. Titles and codes are static strings chosen by the
/// caller; request values, secret references and exception messages never enter the body
/// (§5.2 "Diagnostics": secrets never appear in problem responses). Since M24 (§8.5)
/// every problem document carries a <c>type</c> distinguishing proxy failures from
/// vendor failures rewritten by the error normaliser.
/// </summary>
internal static class CredProxProblemResponses
{
    /// <summary>
    /// RFC 7807 <c>type</c> of every problem the proxy itself produced (§8.5). A URN,
    /// not a URL: the identifier must not depend on any host being reachable.
    /// </summary>
    internal const string ProxyErrorType = "urn:credprox:errors:proxy";

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static async ValueTask WriteAsync(
        HttpResponse response,
        int statusCode,
        string code,
        string title,
        CancellationToken cancellationToken = default,
        TimeSpan? retryAfter = null,
        IReadOnlyDictionary<string, object?>? extensions = null)
    {
        ArgumentNullException.ThrowIfNull(response);

        if (response.HasStarted)
        {
            return; // cannot rewrite; the abort flag already stopped the pipeline
        }

        response.Clear();
        response.StatusCode = statusCode;
        response.ContentType = "application/problem+json";

        if (retryAfter is { } after)
        {
            // After Clear() (it wipes headers) and before the body write (it flushes them).
            var seconds = (long)Math.Ceiling(after.TotalSeconds);
            response.Headers.RetryAfter = seconds < 1 ? "1" : seconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        var problem = new ProblemDetails
        {
            Type = ProxyErrorType,
            Status = statusCode,
            Title = title,
            Extensions = { ["code"] = code },
        };

        if (extensions is not null)
        {
            // Structured members for machine readers (M19: the consent problem's
            // authorize_url). Values are static per call site — never request data.
            foreach (var (key, value) in extensions)
            {
                problem.Extensions[key] = value;
            }
        }

        await JsonSerializer
            .SerializeAsync(response.Body, problem, SerializerOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Builds the same problem body as an <see cref="HttpResponseMessage"/> for the
    /// outbound pipeline (throttle 429, circuit-open 503): YARP forwards it to the
    /// caller unchanged.
    /// </summary>
    public static HttpResponseMessage CreateResponse(int statusCode, string code, string title)
    {
        ArgumentException.ThrowIfNullOrEmpty(code);
        ArgumentException.ThrowIfNullOrEmpty(title);

        var problem = new ProblemDetails
        {
            Type = ProxyErrorType,
            Status = statusCode,
            Title = title,
            Extensions = { ["code"] = code },
        };

        return new HttpResponseMessage((HttpStatusCode)statusCode)
        {
            Content = new StringContent(
                JsonSerializer.Serialize(problem, SerializerOptions),
                Encoding.UTF8,
                "application/problem+json"),
        };
    }

    /// <summary>
    /// Serializes one problem document to UTF-8 bytes — the shape the error normaliser
    /// (M24) puts in place of a vendor error body. Extension values are static per call
    /// site or the vendor's own (already-scrubbed) payload.
    /// </summary>
    internal static byte[] CreateProblemBytes(
        string type,
        int statusCode,
        string title,
        Dictionary<string, object?> extensions)
    {
        ArgumentException.ThrowIfNullOrEmpty(type);
        ArgumentException.ThrowIfNullOrEmpty(title);

        var problem = new ProblemDetails
        {
            Type = type,
            Status = statusCode,
            Title = title,
        };

        foreach (var (key, value) in extensions)
        {
            problem.Extensions[key] = value;
        }

        return JsonSerializer.SerializeToUtf8Bytes(problem, SerializerOptions);
    }

    internal sealed class ProblemDetails
    {
        public string? Type { get; set; }

        public string? Title { get; set; }

        public int? Status { get; set; }

        public string? Detail { get; set; }

        public string? Instance { get; set; }

        public Dictionary<string, object?> Extensions { get; set; } = [];
    }
}
