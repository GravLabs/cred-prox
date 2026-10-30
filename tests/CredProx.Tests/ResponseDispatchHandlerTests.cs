using System.Net;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The M20 dispatcher's own contract (review F1 included): the settled response is
/// published to the features, requests without CredProx state pass through, and the
/// fail-closed path neither forwards bytes nor leaks the abandoned upstream response.
/// </summary>
public sealed class ResponseDispatchHandlerTests
{
    private sealed class StubInnerHandler(HttpResponseMessage response) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) => Task.FromResult(response);
    }

    private sealed class ThrowingResponseFeature : IResponseFeature
    {
        public ValueTask ApplyAsync(HttpContext context, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("feature failed");
    }

    private sealed class CancelThrowingFeature : IResponseFeature
    {
        public ValueTask ApplyAsync(HttpContext context, CancellationToken cancellationToken) =>
            throw new OperationCanceledException(cancellationToken);
    }

    private sealed class RecordingResponseFeature(HttpResponseMessage?[] sink) : IResponseFeature
    {
        public ValueTask ApplyAsync(HttpContext context, CancellationToken cancellationToken)
        {
            sink[0] = context.Features.Get<CredProxRequestState>()?.ProxyResponse;
            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// A request carrying CredProx state, stashed the way the transform provider stashes
    /// it: on <c>request.Options</c> for the dispatcher and in <c>Features</c> for the
    /// features themselves.
    /// </summary>
    private static HttpRequestMessage RequestWithState(out CredProxRequestState state)
    {
        var context = new DefaultHttpContext();
        var request = new HttpRequestMessage(HttpMethod.Get, "http://proxy/api");
        state = new CredProxRequestState(context, request);
        context.Features.Set(state);
        request.Options.Set(CredProxRequestOptions.RequestState, state);
        return request;
    }

    private static (HttpMessageInvoker Invoker, HttpResponseMessage Upstream) InvokerWith(
        CredProxPipeline pipeline, HttpMessageHandler? inner = null)
    {
        var upstream = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("upstream"),
        };
        var handler = new ResponseDispatchHandler(
            inner ?? new StubInnerHandler(upstream),
            pipeline,
            NullLogger<ResponseDispatchHandler>.Instance);
        return (new HttpMessageInvoker(handler, disposeHandler: true), upstream);
    }

    [Fact]
    public async Task FeatureFailure_FailsClosed_AndDisposesTheAbandonedResponse()
    {
        var upstream = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("raw bytes"),
        };
        using var handler = new ResponseDispatchHandler(
            new StubInnerHandler(upstream),
            new CredProxPipeline([], [], [new ThrowingResponseFeature()]),
            NullLogger<ResponseDispatchHandler>.Instance);
        using var invoker = new HttpMessageInvoker(handler, disposeHandler: false);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => invoker.SendAsync(RequestWithState(out _), CancellationToken.None));

        // F1: the discarded upstream response is disposed, not handed to the GC —
        // reading its content after the failure now throws ObjectDisposedException.
        await Assert.ThrowsAsync<ObjectDisposedException>(
            () => upstream.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task CancellationAfterResponse_StillDisposesTheSettledResponse()
    {
        var upstream = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("raw bytes"),
        };
        using var handler = new ResponseDispatchHandler(
            new StubInnerHandler(upstream),
            new CredProxPipeline([], [], [new CancelThrowingFeature()]),
            NullLogger<ResponseDispatchHandler>.Instance);
        using var invoker = new HttpMessageInvoker(handler, disposeHandler: false);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => invoker.SendAsync(RequestWithState(out _), CancellationToken.None));

        await Assert.ThrowsAsync<ObjectDisposedException>(
            () => upstream.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Features_SeeTheSettledResponseOnTheState()
    {
        var seen = new HttpResponseMessage?[1];
        var pipeline = new CredProxPipeline([], [], [new RecordingResponseFeature(seen)]);
        var (invoker, upstream) = InvokerWith(pipeline);
        using (invoker)
        {
            var response = await invoker.SendAsync(RequestWithState(out var state), CancellationToken.None);

            Assert.Same(upstream, response);
            Assert.Same(response, seen[0]);
            Assert.Same(response, state.ProxyResponse);
        }
    }

    [Fact]
    public async Task RequestWithoutCredProxState_PassesThroughUntouched()
    {
        var (invoker, _) = InvokerWith(new CredProxPipeline([], [], [new ThrowingResponseFeature()]));
        using (invoker)
        {
            // No RequestState stashed: not our request — the throwing feature never runs.
            var response = await invoker.SendAsync(
                new HttpRequestMessage(HttpMethod.Get, "http://proxy/api"), CancellationToken.None);

            Assert.Equal("upstream", await response.Content.ReadAsStringAsync());
        }
    }
}
