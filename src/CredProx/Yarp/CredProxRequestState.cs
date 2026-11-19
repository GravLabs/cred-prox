using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Net.Http;
using Microsoft.AspNetCore.Http;

namespace CredProx;

/// <summary>
/// The per-request CredProx state, set on the <see cref="HttpContext"/> by the CredProx
/// transform before the request pipeline runs. It gives <see cref="Abstractions.IRequestFeature"/>
/// implementations — whose contract is the inbound <see cref="HttpContext"/> —
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
    internal CredProxRequestState(
        HttpContext httpContext,
        HttpRequestMessage proxyRequest,
        bool forwarderBodyShape = false)
    {
        HttpContext = httpContext;
        ProxyRequest = proxyRequest;
        _forwarderBodyShape = forwarderBodyShape;
    }

    // How a feature that has fully read the request body hands the measured bytes to
    // the outbound pipeline (see MeasureOutgoingBodyAsync). The core sets the shape
    // when it builds the state: on the forwarder the copy configures the inbound
    // request the forwarder pumps at send time (replacing the forwarded Content after
    // the transforms is refused); hosts built without it keep the replace-the-content
    // shape, where ProxyRequest.Content becomes the measured copy. A flag, never a
    // delegate: a per-request delegate here costs every CredProx-routed request a
    // closure it never used (~113 B), and CredProxRequestStateShapeTests fails the
    // battery if a delegate ever rides this state again.
    private readonly bool _forwarderBodyShape;

    /// <summary>
    /// The measured-body hand-off seam for features that need the whole outbound body
    /// (a signing stage computing <c>bodyHash</c>, for example): counts the bytes out,
    /// up to <paramref name="maxBytes"/>, and installs the measured copy as the body
    /// that flows onward. On the forwarder the outgoing content is a one-shot view of
    /// the request body — reading it would burn the single serialization the forwarder
    /// pumps at send time — so the counted read takes the request body itself and the
    /// copy is installed back on the request the forwarder pumps, with the measured
    /// content length. Other hosts read <see cref="ProxyRequest"/>.<c>Content</c>, and
    /// it becomes a byte copy carrying the original headers except the framing ones,
    /// which would contradict the measured length.
    /// <para>
    /// The contract of <see langword="null"/> is narrow on purpose: it is returned only
    /// when this method counted more than <paramref name="maxBytes"/> itself — the cap
    /// is measured here, never declared by the content — so a caller answers an overrun
    /// with <c>413</c> without inspecting any exception's shape. Any other read failure
    /// propagates with its own cause, and on an overrun or a failure the body onward is
    /// untouched.
    /// </para>
    /// </summary>
    /// <param name="maxBytes">The most bytes this hand-off may buffer.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>
    /// The measured body bytes; <see langword="null"/> only when the counted size
    /// passed <paramref name="maxBytes"/>.
    /// </returns>
    public async Task<byte[]?> MeasureOutgoingBodyAsync(long maxBytes, CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(maxBytes);
        if (_forwarderBodyShape)
        {
            // Forwarder host: the outgoing content belongs to the forwarder and is
            // serialized exactly once, so the read takes — and the copy re-installs on —
            // the stream the forwarder pumps at send time. The exact hashed bytes flow
            // to the upstream and the measured length goes on the forwarder's own
            // content, which travels as the outbound Content-Length; framing headers
            // live on the message, which the forwarder already owns, and the content
            // reference stays the forwarder's, so its guard holds.
            var measured = await ReadUpToCapAsync(HttpContext.Request.Body, maxBytes, cancellationToken)
                .ConfigureAwait(false);
            if (measured is not null)
            {
                HttpContext.Request.Body = new MemoryStream(measured);
                if (ProxyRequest.Content is { } outgoing)
                {
                    outgoing.Headers.ContentLength = measured.LongLength;
                }
            }

            return measured;
        }

        if (ProxyRequest.Content is not { } content)
        {
            return [];
        }

        var copied = await ReadUpToCapAsync(content, maxBytes, cancellationToken).ConfigureAwait(false);
        if (copied is null)
        {
            return null;
        }

        var buffered = new ByteArrayContent(copied);
        foreach (var header in content.Headers)
        {
            if (!string.Equals(header.Key, "Content-Length", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(header.Key, "Transfer-Encoding", StringComparison.OrdinalIgnoreCase))
            {
                buffered.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
        }

        ProxyRequest.Content = buffered;
        return copied;
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
    /// anything to the caller; <see langword="null"/> until then.
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
    /// the CredProx error code. The response is written immediately; the pipeline
    /// stops after this feature returns.
    /// </summary>
    /// <param name="statusCode">The HTTP status to return.</param>
    /// <param name="code">The <c>credprox.*</c> error code; never contains request values.</param>
    /// <param name="title">A static, caller-safe description.</param>
    /// <param name="retryAfter">
    /// Optional <c>Retry-After</c> value in seconds (caller budgets); omitted for
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
    /// Aborts with extra structured problem members (consent signalling): the
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

    /// <summary>
    /// Copies the content through <see cref="HttpContent.CopyToAsync(Stream, CancellationToken)"/> —
    /// the one read path every <see cref="HttpContent"/> supports, including the
    /// forwarder's own content type, whose stream shortcut throws — counting every byte;
    /// a counted size past <paramref name="maxBytes"/> yields <see langword="null"/> and
    /// any other failure propagates with its own cause.
    /// </summary>
    private static async Task<byte[]?> ReadUpToCapAsync(HttpContent content, long maxBytes, CancellationToken cancellationToken)
    {
        using var buffer = new BoundedCountingStream(maxBytes);
        try
        {
            await content.CopyToAsync(buffer, cancellationToken).ConfigureAwait(false);
        }
        catch (BodyOverCapException)
        {
            return null;
        }

        return buffer.WrittenBytes();
    }

    /// <summary>
    /// The same counted copy over a bare stream — the request body the forwarder pumps
    /// at send time, when reading the one-shot outgoing content would burn the
    /// forwarder's only serialization.
    /// </summary>
    private static async Task<byte[]?> ReadUpToCapAsync(Stream body, long maxBytes, CancellationToken cancellationToken)
    {
        using var buffer = new BoundedCountingStream(maxBytes);
        try
        {
            await body.CopyToAsync(buffer, cancellationToken).ConfigureAwait(false);
        }
        catch (BodyOverCapException)
        {
            return null;
        }

        return buffer.WrittenBytes();
    }

    /// <summary>Thrown by <see cref="BoundedCountingStream"/> the moment a write would
    /// carry the count past the cap; the copy stops there and nothing over the cap is kept.</summary>
    private sealed class BodyOverCapException : Exception
    {
        public BodyOverCapException()
            : base("The content is larger than the configured body cap.")
        {
        }
    }

    /// <summary>
    /// A write-only sink that counts every byte and refuses any write crossing
    /// <paramref name="maxBytes"/> with <see cref="BodyOverCapException"/> before storing
    /// any of it — the cap is measured by the reader, never declared by the content.
    /// </summary>
    private sealed class BoundedCountingStream(long maxBytes) : Stream
    {
        private readonly MemoryStream _inner = new();
        private long _count;
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override void Write(byte[] buffer, int offset, int count) =>
            Append(buffer.AsSpan(offset, count));
        public override void Write(ReadOnlySpan<byte> buffer) => Append(buffer);
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            Write(buffer, offset, count);
            return Task.CompletedTask;
        }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Write(buffer.Span);
            return ValueTask.CompletedTask;
        }
        public override void Flush()
        {
        }
        public override long Length => _inner.Length;
        public override long Position
        {
            get => _inner.Length;
            set => throw new NotSupportedException();
        }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public byte[] WrittenBytes() => _inner.ToArray();
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _inner.Dispose();
            }

            base.Dispose(disposing);
        }
        private void Append(ReadOnlySpan<byte> bytes)
        {
            if (_count + bytes.Length > maxBytes)
            {
                throw new BodyOverCapException();
            }

            _inner.Write(bytes);
            _count += bytes.Length;
        }
    }
}
