using System.Net;
using System.Text;
using CredProx;
using CredProx.Abstractions;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// §5.2 "Refresh on 401" row: invalidate → refetch → retry once; a second 401 is returned,
/// never looped; non-idempotent requests are not retried by default, and only within the
/// buffer limit when enabled.
/// </summary>
public sealed class TokenRefreshHandlerTests
{
    private int _acquireCount;
    private int _invalidateCount;

    private Func<CancellationToken, ValueTask<string>> Acquire(Queue<string> tokens) =>
        _ =>
        {
            _acquireCount++;
            return new ValueTask<string>(tokens.Dequeue());
        };

    private void Invalidate() => _invalidateCount++;

    private static void AttachWithToken(HttpRequestMessage request, string token)
    {
        request.Headers.Remove("Authorization");
        request.Headers.Add("Authorization", $"Bearer {token}");
    }

    [Fact]
    public async Task Get_401ThenSuccess_RetriesWithFreshToken()
    {
        var tokens = new Queue<string>(["token-1", "token-2"]);
        var handler = new TokenRefreshHandler(Acquire(tokens), Invalidate, AttachWithToken, new RefreshOn401Options())
        {
            InnerHandler = new StubHttpHandler((_, index) =>
                new HttpResponseMessage(index == 0 ? HttpStatusCode.Unauthorized : HttpStatusCode.OK)),
        };
        var client = new HttpClient(handler);

        var response = await client.GetAsync("https://vendor.example/api");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(2, _acquireCount);
        Assert.Equal(1, _invalidateCount);
    }

    [Fact]
    public async Task Second401_IsReturnedWithoutLooping()
    {
        var tokens = new Queue<string>(["token-1", "token-2"]);
        var inner = new StubHttpHandler((_, _) => new HttpResponseMessage(HttpStatusCode.Unauthorized));
        var handler = new TokenRefreshHandler(Acquire(tokens), Invalidate, AttachWithToken, new RefreshOn401Options())
        {
            InnerHandler = inner,
        };
        var client = new HttpClient(handler);

        var response = await client.GetAsync("https://vendor.example/api");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(2, inner.Requests.Count); // exactly one retry
        Assert.Equal(2, _acquireCount);
    }

    [Fact]
    public async Task Success_IsPassedThroughWithoutInvalidation()
    {
        var tokens = new Queue<string>(["token-1"]);
        var handler = new TokenRefreshHandler(Acquire(tokens), Invalidate, AttachWithToken, new RefreshOn401Options())
        {
            InnerHandler = new StubHttpHandler(HttpStatusCode.OK, "fine"),
        };
        var client = new HttpClient(handler);

        var response = await client.GetAsync("https://vendor.example/api");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(0, _invalidateCount);
        Assert.Equal(1, _acquireCount);
    }

    [Fact]
    public async Task Post_IsNotRetriedByDefault()
    {
        var tokens = new Queue<string>(["token-1"]);
        var inner = new StubHttpHandler((_, _) => new HttpResponseMessage(HttpStatusCode.Unauthorized));
        var handler = new TokenRefreshHandler(Acquire(tokens), Invalidate, AttachWithToken, new RefreshOn401Options())
        {
            InnerHandler = inner,
        };
        var client = new HttpClient(handler);

        var response = await client.PostAsync("https://vendor.example/api", new StringContent("payload"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Single(inner.Requests);
        Assert.Equal(0, _invalidateCount);
    }

    [Fact]
    public async Task Post_WithRetryEnabled_BodyIsBufferedAndReplayed()
    {
        var tokens = new Queue<string>(["token-1", "token-2"]);
        var inner = new StubHttpHandler((_, index) =>
            new HttpResponseMessage(index == 0 ? HttpStatusCode.Unauthorized : HttpStatusCode.OK));
        var handler = new TokenRefreshHandler(
            Acquire(tokens), Invalidate, AttachWithToken,
            new RefreshOn401Options { RetryNonIdempotent = true })
        {
            InnerHandler = inner,
        };
        var client = new HttpClient(handler);

        var response = await client.PostAsync(
            "https://vendor.example/api",
            new StringContent("payload", Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(2, inner.Requests.Count);
        Assert.Equal("payload", inner.Body(1));
        Assert.Equal("application/json", inner.Requests[1].Content!.Headers.ContentType!.MediaType);
        Assert.Equal("Bearer token-2", inner.Requests[1].Headers.Authorization!.ToString());
    }

    [Fact]
    public async Task Post_BodyOverLimit_IsNotRetried()
    {
        var tokens = new Queue<string>(["token-1"]);
        var inner = new StubHttpHandler((_, _) => new HttpResponseMessage(HttpStatusCode.Unauthorized));
        var handler = new TokenRefreshHandler(
            Acquire(tokens), Invalidate, AttachWithToken,
            new RefreshOn401Options { RetryNonIdempotent = true, MaxRetriedBodyBytes = 8 })
        {
            InnerHandler = inner,
        };
        var client = new HttpClient(handler);

        var response = await client.PostAsync("https://vendor.example/api", new StringContent("this body is far too long"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Single(inner.Requests);
        Assert.Equal(0, _invalidateCount);
    }

    [Fact]
    public async Task Post_StreamedBodyWithoutLength_IsNeverBufferedOrRetried()
    {
        // §5.2: a non-idempotent request with an unbuffered body is not retried — even
        // with RetryNonIdempotent on, an unknown ContentLength is treated as over-cap
        // and the stream is never read into memory.
        var tokens = new Queue<string>(["token-1"]);
        var inner = new StubHttpHandler((_, _) => new HttpResponseMessage(HttpStatusCode.Unauthorized))
        {
            CaptureBodies = false, // streaming handler: never reads the body, keeps ContentLength null
        };
        var handler = new TokenRefreshHandler(
            Acquire(tokens), Invalidate, AttachWithToken,
            new RefreshOn401Options { RetryNonIdempotent = true })
        {
            InnerHandler = inner,
        };
        var client = new HttpClient(handler);

        var content = new StreamContent(new ForwardOnlyStream(new MemoryStream("payload"u8.ToArray())));
        var response = await client.PostAsync("https://vendor.example/api", content);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Single(inner.Requests);
        Assert.Equal(0, _invalidateCount);
    }

    [Fact]
    public void Constructor_RejectsNullArguments()
    {
        Assert.Throws<ArgumentNullException>(() => new TokenRefreshHandler(null!, () => { }, (r, t) => { }, new RefreshOn401Options()));
        Assert.Throws<ArgumentNullException>(() => new TokenRefreshHandler(_ => default, null!, (r, t) => { }, new RefreshOn401Options()));
        Assert.Throws<ArgumentNullException>(() => new TokenRefreshHandler(_ => default, () => { }, null!, new RefreshOn401Options()));
        Assert.Throws<ArgumentNullException>(() => new TokenRefreshHandler(_ => default, () => { }, (r, t) => { }, null!));
    }

    // ---- M19 consent signalling during refresh (§8.3) ----

    [Fact]
    public async Task ConsentDuringRefresh_ReturnsUpstreamUnauthorized_NoRetryNoThrow()
    {
        // Consent is interactive: the refresh cannot succeed. The handler returns the
        // upstream's own 401 untouched — no 500 escapes to the caller, and the retry
        // never leaves the handler.
        var inner = new StubHttpHandler((_, _) => new HttpResponseMessage(HttpStatusCode.Unauthorized));
        var acquireCount = 0;
        var handler = new TokenRefreshHandler(
            _ =>
            {
                acquireCount++;
                if (acquireCount > 1)
                {
                    throw new ConsentRequiredException("https://id.example/authorize", "consent");
                }
                return new ValueTask<string>("token-1");
            },
            Invalidate, AttachWithToken, new RefreshOn401Options())
        {
            InnerHandler = inner,
        };
        var client = new HttpClient(handler);

        var response = await client.GetAsync("https://vendor.example/api");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Single(inner.Requests);      // the retry never went upstream
        Assert.Equal(1, _invalidateCount);  // the rejected cached token was still dropped
    }

    [Fact]
    public async Task OtherAcquireFailureDuringRefresh_StillPropagates()
    {
        // The consent catch is exact: every other provider failure keeps its old path —
        // the exception reaches the caller and the 401 response is discarded.
        var inner = new StubHttpHandler((_, _) => new HttpResponseMessage(HttpStatusCode.Unauthorized));
        var acquireCount = 0;
        var handler = new TokenRefreshHandler(
            _ =>
            {
                acquireCount++;
                if (acquireCount > 1)
                {
                    throw new InvalidOperationException("token store down");
                }
                return new ValueTask<string>("token-1");
            },
            Invalidate, AttachWithToken, new RefreshOn401Options())
        {
            InnerHandler = inner,
        };
        var client = new HttpClient(handler);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.GetAsync("https://vendor.example/api"));
        Assert.Single(inner.Requests);
    }

    [Fact]
    public async Task StandaloneInitialAcquireConsent_PropagatesToCaller()
    {
        // Standalone composition: the caller owns the handler and receives the typed
        // exception to map as they see fit — only the proxy path maps it to a problem.
        var handler = new TokenRefreshHandler(
            _ => throw new ConsentRequiredException("https://id.example/authorize", "consent"),
            Invalidate, AttachWithToken, new RefreshOn401Options())
        {
            InnerHandler = new StubHttpHandler(HttpStatusCode.OK, "fine"),
        };
        var client = new HttpClient(handler);

        await Assert.ThrowsAsync<ConsentRequiredException>(
            () => client.GetAsync("https://vendor.example/api"));
    }
}
