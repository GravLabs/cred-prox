using System.Diagnostics.CodeAnalysis;

namespace CredProx.Testing;

/// <summary>
/// An <see cref="IHttpClientFactory"/> that hands every client the same handler — the
/// seam that points a credential provider's token calls at a <see cref="FakeTokenServer"/>
/// (or any recording handler) without touching the network.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class StubHttpClientFactory : IHttpClientFactory
{
    private readonly HttpMessageHandler _handler;

    /// <summary>
    /// Creates the factory over the given handler. The factory does not own the handler;
    /// clients are created without a dispose handler.
    /// </summary>
    /// <param name="handler">The handler every created client uses.</param>
    public StubHttpClientFactory(HttpMessageHandler handler)
    {
        _handler = handler ?? throw new ArgumentNullException(nameof(handler));
    }

    /// <inheritdoc />
    public HttpClient CreateClient(string name) => new(_handler, disposeHandler: false);
}
