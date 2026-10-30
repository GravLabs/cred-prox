using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text;

namespace CredProx.Testing;

/// <summary>
/// A scriptable stand-in for the proxied vendor API: records every forwarded request and
/// answers from an enqueued script or a default <c>200 {}</c>. Lets a plugin author drive
/// refresh-on-401 and failure scenarios (reject the first token, then accept) without a
/// network.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class FakeUpstream : HttpMessageHandler
{
    private readonly object _gate = new();
    private readonly Queue<Func<HttpRequestMessage, HttpResponseMessage>> _script = new();
    private readonly List<HttpRequestMessage> _requests = [];
    private int _callCount;

    /// <summary>Used when the script is empty. Default <c>200 {}</c>.</summary>
    public Func<HttpRequestMessage, HttpResponseMessage> Responder { get; set; } =
        _ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{}", Encoding.UTF8, "application/json"),
        };

    /// <summary>Every request that reached the upstream, in order.</summary>
    public IReadOnlyList<HttpRequestMessage> Requests
    {
        get { lock (_gate) { return [.. _requests]; } }
    }

    /// <summary>How many requests arrived since construction or the last <see cref="Reset"/>.</summary>
    public int CallCount
    {
        get { lock (_gate) { return _callCount; } }
    }

    /// <summary>Queues the next answer.</summary>
    /// <param name="statusCode">The response status.</param>
    /// <param name="body">The response body.</param>
    public void Enqueue(HttpStatusCode statusCode, string body)
    {
        lock (_gate)
        {
            _script.Enqueue(_ => new HttpResponseMessage(statusCode)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            });
        }
    }

    /// <summary>Queues a computed answer.</summary>
    /// <param name="responder">Computes the response for the request.</param>
    public void Enqueue(Func<HttpRequestMessage, HttpResponseMessage> responder)
    {
        ArgumentNullException.ThrowIfNull(responder);
        lock (_gate)
        {
            _script.Enqueue(responder);
        }
    }

    /// <summary>Empties the script and the recorded traffic.</summary>
    public void Reset()
    {
        lock (_gate)
        {
            _script.Clear();
            _requests.Clear();
            _callCount = 0;
        }
    }

    /// <inheritdoc />
    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Func<HttpRequestMessage, HttpResponseMessage> answer;
        lock (_gate)
        {
            _callCount++;
            _requests.Add(request);
            answer = _script.Count > 0 ? _script.Dequeue() : Responder;
        }

        return Task.FromResult(answer(request));
    }
}
