using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text;

namespace CredProx.Testing;

/// <summary>
/// A scriptable stand-in for a vendor token endpoint: records every request (and its
/// captured body) and answers from an enqueued script, a custom <see cref="Responder"/>,
/// or a default <c>200 {"access_token":"tok-&lt;n&gt;","expires_in":3600}</c> that hands
/// out a fresh token per call. Plug it into an <see cref="System.Net.Http.IHttpClientFactory"/>
/// (see <see cref="StubHttpClientFactory"/>) to host a credential provider without a network.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class FakeTokenServer : HttpMessageHandler
{
    private readonly object _gate = new();
    private readonly Queue<Func<int, HttpResponseMessage>> _script = new();
    private readonly List<HttpRequestMessage> _requests = [];
    private readonly List<string?> _bodies = [];
    private int _callCount;

    /// <summary>
    /// Used when the script is empty and no <see cref="Responder"/> is set: a fresh
    /// <c>access_token</c> per call so cache behavior is observable in the token value.
    /// </summary>
    public Func<HttpRequestMessage, int, HttpResponseMessage>? Responder { get; set; }

    /// <summary>Every request the provider sent, in order.</summary>
    public IReadOnlyList<HttpRequestMessage> Requests
    {
        get { lock (_gate) { return [.. _requests]; } }
    }

    /// <summary>The captured body text of every request, in order (<see langword="null"/> for bodyless ones).</summary>
    public IReadOnlyList<string?> RequestBodies
    {
        get { lock (_gate) { return [.. _bodies]; } }
    }

    /// <summary>How many token calls arrived since construction or the last <see cref="Reset"/>.</summary>
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

    /// <summary>Queues a computed answer; the parameter is the 1-based call number.</summary>
    /// <param name="responder">Computes the response for the call.</param>
    public void Enqueue(Func<int, HttpResponseMessage> responder)
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
            _bodies.Clear();
            _callCount = 0;
        }
    }

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        // Capture the body before any handler can consume it: providers send form content,
        // and the recorded text is what failure-hygiene assertions scan.
        string? body = null;
        if (request.Content is not null)
        {
            body = await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        }

        Func<int, HttpResponseMessage> answer;
        int call;
        lock (_gate)
        {
            _callCount++;
            call = _callCount;
            _requests.Add(request);
            _bodies.Add(body);
            answer = _script.Count > 0
                ? _script.Dequeue()
                : callNumber => Responder?.Invoke(request, callNumber) ?? DefaultToken(callNumber);
        }

        return answer(call);
    }

    private static HttpResponseMessage DefaultToken(int callNumber) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(
            $$"""{"access_token":"tok-{{callNumber}}","expires_in":3600}""",
            Encoding.UTF8,
            "application/json"),
    };
}
