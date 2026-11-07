using System.Net;
using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;

namespace CredProx.Tests;

/// <summary>
/// An <see cref="HttpMessageHandler"/> that records every request (and its body) and
/// answers from a responder, so providers can be tested against the real
/// <see cref="HttpClient"/> stack without a network.
/// </summary>
internal sealed class StubHttpHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, int, HttpResponseMessage> _responder;

    public StubHttpHandler(Func<HttpRequestMessage, int, HttpResponseMessage> responder)
    {
        _responder = responder;
    }

    public StubHttpHandler(HttpStatusCode status, string body)
        : this((_, _) => new HttpResponseMessage(status) { Content = new StringContent(body) })
    {
    }

    public List<HttpRequestMessage> Requests { get; } = [];

    public List<string?> Bodies { get; } = [];

    /// <summary>
    /// When <see langword="false"/> the body is never read — like the real
    /// <c>SocketsHttpHandler</c>, which streams it. Reading via
    /// <see cref="HttpContent.ReadAsStringAsync"/> would buffer a
    /// <see cref="StreamContent"/> and set its <c>ContentLength</c>, hiding the
    /// unknown-length shape from the code under test.
    /// </summary>
    public bool CaptureBodies { get; init; } = true;

    public string? Body(int index) => Bodies[index];

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        // Run off the caller's thread so a responder that blocks (single-flight tests)
        // cannot deadlock the thread that issued the request.
        await Task.Yield();

        var index = Requests.Count;
        Requests.Add(request);
        Bodies.Add(CaptureBodies && request.Content is not null
            ? await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false)
            : null);
        return _responder(request, index);
    }
}

/// <summary>An <see cref="IHttpClientFactory"/> handing out one client over a fixed handler.</summary>
internal sealed class StubHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
{
    private readonly HttpClient _client = new(handler);

    public HttpClient CreateClient(string name) => _client;
}

/// <summary>
/// A non-seekable, length-unknown view over a stream, so <see cref="StreamContent"/>
/// reports a null <c>ContentLength</c> — the streamed/unbuffered body shape §5.2 says is
/// never retried.
/// </summary>
internal sealed class ForwardOnlyStream(Stream inner) : Stream
{
    public override bool CanRead => inner.CanRead;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override void Flush() => inner.Flush();

    public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            inner.Dispose();
        }

        base.Dispose(disposing);
    }
}

/// <summary>
/// Builds real <see cref="ISecretAccessor"/> instances over in-memory configuration, using
/// the production <see cref="ConfigurationSecretSource"/> and
/// <see cref="SecretAccessorFactory"/> so scoping is exercised, not faked.
/// </summary>
internal static class TestSecrets
{
    /// <summary>
    /// An accessor scoped to <c>CredProx:Credentials:test</c>, whose section holds
    /// <paramref name="credentialSection"/> and whose secret values come from
    /// <paramref name="secretValues"/> (keyed by reference name without the <c>secret:</c> prefix).
    /// </summary>
    public static ISecretAccessor AccessorFor(
        Dictionary<string, string?> credentialSection,
        Dictionary<string, string?>? secretValues = null)
    {
        var configuration = ConfigurationFor(credentialSection, secretValues);
        return new SecretAccessorFactory(new ConfigurationSecretSource(configuration))
            .CreateAccessor(configuration.GetSection("CredProx:Credentials:test"));
    }

    public static IConfiguration ConfigurationFor(
        Dictionary<string, string?> credentialSection,
        Dictionary<string, string?>? secretValues = null)
    {
        var entries = new Dictionary<string, string?>();
        foreach (var (key, value) in credentialSection)
        {
            entries[$"CredProx:Credentials:test:{key}"] = value;
        }

        if (secretValues is not null)
        {
            foreach (var (key, value) in secretValues)
            {
                entries[$"CredProx:Secrets:{key}"] = value;
            }
        }

        return new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
    }
}
