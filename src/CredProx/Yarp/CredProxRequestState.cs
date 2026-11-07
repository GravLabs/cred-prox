using System.Diagnostics.CodeAnalysis;
using System.Net.Http;
using Microsoft.AspNetCore.Http;

namespace CredProx;

/// <summary>
/// The per-request CredProx state, set on the <see cref="HttpContext"/> by the CredProx
/// transform before the request pipeline runs. It gives <see cref="Abstractions.IRequestFeature"/>
/// implementations — whose contract is the inbound <see cref="HttpContext"/> (§3.5) —
/// access to the outbound <see cref="HttpRequestMessage"/> they shape, and it is the
/// short-circuit point: a feature that calls <see cref="AbortAsync(int, string, string, TimeSpan?)"/>
/// stops the pipeline and YARP skips the forward (the response is set, which the
/// forwarder honors).
/// </summary>
/// <remarks>
/// Written by the core transform provider; read by features (built-in and plugin).
/// </remarks>
[Experimental("CREDPROX001")]
public sealed class CredProxRequestState
{
    internal CredProxRequestState(HttpContext httpContext, HttpRequestMessage proxyRequest)
    {
        HttpContext = httpContext;
        ProxyRequest = proxyRequest;
    }

    /// <summary>The inbound request this state belongs to.</summary>
    public HttpContext HttpContext { get; }

    /// <summary>
    /// The outbound request being built. Header hygiene and credential attachment operate
    /// on it; the caller's <c>Authorization</c> is replaced, never merged, by the attacher.
    /// </summary>
    public HttpRequestMessage ProxyRequest { get; }

    /// <summary>
    /// The upstream response, set by <see cref="ResponseDispatchHandler"/> at the end of
    /// the outbound pipeline — after refresh-on-401 settled and before YARP copies
    /// anything to the caller (M20, plan §8.2); <see langword="null"/> until then.
    /// Response features (<see cref="Abstractions.IResponseFeature"/>) read and reshape
    /// the response through this — a feature that wraps the body stream takes ownership.
    /// </summary>
    public HttpResponseMessage? ProxyResponse { get; internal set; }

    /// <summary>
    /// Set by a destination feature to override the outbound address prefix for this
    /// request; applied to the transform context after the pipeline runs.
    /// </summary>
    public string? DestinationPrefix { get; set; }

    /// <summary>
    /// The final outbound path, after every YARP path transform has run. Set by the core
    /// transform provider before the pipeline. YARP assembles
    /// <see cref="HttpRequestMessage.RequestUri"/> only after all transforms complete, so
    /// a feature that signs or inspects the outbound path must read this — on the live
    /// pipeline <see cref="ProxyRequest"/>.<c>RequestUri</c> is still <see langword="null"/>
    /// while features run.
    /// </summary>
    public string? OutboundPath { get; internal set; }

    /// <summary>
    /// The final outbound query (leading <c>?</c> included, <see langword="null"/> when
    /// empty), after every YARP query transform has run; see <see cref="OutboundPath"/>
    /// for why <see cref="ProxyRequest"/> cannot answer this during the pipeline.
    /// </summary>
    public string? OutboundQuery { get; internal set; }

    /// <summary>
    /// The request's partition value once admitted by an allow-list; <see langword="null"/>
    /// until then. Nothing may use a partition value that is not in this property —
    /// admission is the only way it gets set.
    /// </summary>
    public string? Partition { get; internal set; }

    /// <summary>The admitted destination entry, when a destination feature resolved one.</summary>
    public DestinationEntry? Destination { get; internal set; }

    /// <summary>
    /// Set once a feature short-circuited the request; the pipeline stops and the forward
    /// is skipped.
    /// </summary>
    public bool IsAborted { get; private set; }

    /// <summary>
    /// Short-circuits the request with a <c>application/problem+json</c> response carrying
    /// the CredProx error code (§3.4). The response is written immediately; the pipeline
    /// stops after this feature returns.
    /// </summary>
    /// <param name="statusCode">The HTTP status to return.</param>
    /// <param name="code">The <c>credprox.*</c> error code; never contains request values.</param>
    /// <param name="title">A static, caller-safe description.</param>
    /// <param name="retryAfter">
    /// Optional <c>Retry-After</c> value in seconds (M15 caller budgets, §3.4); omitted for
    /// every other abort.
    /// </param>
    /// <returns>Completes when the response is written.</returns>
    public ValueTask AbortAsync(int statusCode, string code, string title, TimeSpan? retryAfter = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(code);
        ArgumentException.ThrowIfNullOrEmpty(title);

        if (IsAborted)
        {
            return ValueTask.CompletedTask; // first abort wins
        }

        IsAborted = true;
        return CredProxProblemResponses.WriteAsync(
            HttpContext.Response, statusCode, code, title, default, retryAfter);
    }

    /// <summary>
    /// Aborts with extra structured problem members (M19 consent signalling, §8.3): the
    /// members join the body after <c>code</c> for machine readers. Internal by design —
    /// plugin features use the public overload; the built-in consent mapping carries the
    /// only extension member the core writes (<c>authorize_url</c>).
    /// </summary>
    internal ValueTask AbortAsync(
        int statusCode,
        string code,
        string title,
        IReadOnlyDictionary<string, object?> extensions)
    {
        ArgumentException.ThrowIfNullOrEmpty(code);
        ArgumentException.ThrowIfNullOrEmpty(title);
        ArgumentNullException.ThrowIfNull(extensions);

        if (IsAborted)
        {
            return ValueTask.CompletedTask; // first abort wins
        }

        IsAborted = true;
        return CredProxProblemResponses.WriteAsync(
            HttpContext.Response, statusCode, code, title, default, null, extensions);
    }
}
