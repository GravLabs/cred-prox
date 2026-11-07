using System.Net;
using System.Net.Http;
using CredProx;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The resolver composition mode of <see cref="TokenRefreshHandler"/> (per-cluster use in
/// <see cref="CredProxForwarderHttpClientFactory"/>): the credential was already attached
/// before the first send, the handler only acts on a 401 for requests carrying targets,
/// and the retried clone keeps <c>Version</c>, <c>VersionPolicy</c> and the typed message
/// <c>Options</c> (M3 review carry F4).
/// </summary>
public sealed class TokenRefreshHandlerResolverTests
{
    private int _acquireCount;
    private int _invalidateCount;

    private TokenRefreshTargets Targets(Queue<string> tokens) => new(
        _ =>
        {
            _acquireCount++;
            return new ValueTask<string>(tokens.Dequeue());
        },
        invalidate: () => _invalidateCount++,
        attach: (request, value) => request.Headers.Authorization = new("Bearer", value));

    [Fact]
    public async Task RequestWithoutTargets_PassesThroughUntouched()
    {
        var handler = new TokenRefreshHandler(_ => null, new RefreshOn401Options())
        {
            InnerHandler = new StubHttpHandler(HttpStatusCode.Unauthorized, "nope"),
        };
        var client = new HttpClient(handler);

        var response = await client.GetAsync("https://vendor.example/api");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(0, _acquireCount);
    }

    [Fact]
    public async Task ResolverMode_DoesNotAcquireBeforeFirstSend()
    {
        var targets = Targets(new Queue<string>(["token-2"]));
        var inner = new StubHttpHandler((_, index) =>
            new HttpResponseMessage(index == 0 ? HttpStatusCode.Unauthorized : HttpStatusCode.OK));
        var handler = new TokenRefreshHandler(_ => targets, new RefreshOn401Options())
        {
            InnerHandler = inner,
        };
        var client = new HttpClient(handler);

        var request = new HttpRequestMessage(HttpMethod.Get, "https://vendor.example/api");
        request.Headers.Authorization = new("Bearer", "already-attached");
        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, _acquireCount); // only the refresh acquire, none before the first send
        Assert.Equal(1, _invalidateCount);
        Assert.Equal("Bearer token-2", inner.Requests[1].Headers.Authorization!.ToString());
    }

    [Fact]
    public async Task RetriedClone_KeepsVersionPolicyAndTypedOptions()
    {
        var targets = Targets(new Queue<string>(["token-2"]));
        var inner = new StubHttpHandler((_, index) =>
            new HttpResponseMessage(index == 0 ? HttpStatusCode.Unauthorized : HttpStatusCode.OK));
        var handler = new TokenRefreshHandler(_ => targets, new RefreshOn401Options())
        {
            InnerHandler = inner,
        };
        var client = new HttpClient(handler);

        var request = new HttpRequestMessage(HttpMethod.Get, "https://vendor.example/api")
        {
            Version = new Version(2, 0),
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };
        request.Options.Set(CredProxRequestOptions.TokenRefresh, targets);
        request.Options.Set(new HttpRequestOptionsKey<string>("CredProx.TestString"), "kept");

        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var retry = inner.Requests[1];
        Assert.Equal(new Version(2, 0), retry.Version);
        Assert.Equal(HttpVersionPolicy.RequestVersionExact, retry.VersionPolicy);
        Assert.True(retry.Options.TryGetValue(CredProxRequestOptions.TokenRefresh, out var carried));
        Assert.Same(targets, carried);
        Assert.True(retry.Options.TryGetValue(
            new HttpRequestOptionsKey<string>("CredProx.TestString"), out var carriedString));
        Assert.Equal("kept", carriedString);
    }
}
