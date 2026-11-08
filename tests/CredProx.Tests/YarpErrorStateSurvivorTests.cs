using System.Text;
using CredProx;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage of the problem-document writer, the metadata readers and the request
/// state's abort path: the write clears whatever the pipeline wrote before it, Retry-After
/// floors at one second, guards reject empty code/title before any write decision, and the
/// first abort wins — a second abort must not rewrite the caller's answer.
/// </summary>
public sealed class YarpErrorStateSurvivorTests
{
    private static DefaultHttpContext NewContext(out MemoryStream body)
    {
        body = new MemoryStream();
        return new DefaultHttpContext { Response = { Body = body } };
    }

    private static string BodyOf(MemoryStream body) => Encoding.UTF8.GetString(body.ToArray());

    private sealed class StartedResponseFeature : IHttpResponseFeature
    {
        public int StatusCode { get; set; } = StatusCodes.Status200OK;

        public string? ContentType { get; set; }

        public bool HasStarted => true;

        public string? ReasonPhrase { get; set; }

        public IHeaderDictionary Headers { get; set; } = new HeaderDictionary();

        public Stream Body { get; set; } = new MemoryStream();

        public void OnCompleted(Func<object, Task> callback, object state)
        {
        }

        public void OnStarting(Func<object, Task> callback, object state)
        {
        }
    }

    [Fact]
    public async Task Write_NullResponse_Throws()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => CredProxProblemResponses
                .WriteAsync(null!, 500, "credprox.triage", "T")
                .AsTask());
    }

    [Fact]
    public async Task Write_HasStarted_LeavesTheResponseAlone()
    {
        // Bytes are already on the wire: the abort flag stopped the pipeline, and the
        // writer must not touch the response (no clear, no status change).
        var context = new DefaultHttpContext();
        var feature = new StartedResponseFeature();
        context.Features.Set<IHttpResponseFeature>(feature);

        await CredProxProblemResponses.WriteAsync(context.Response, 503, "credprox.triage", "T");

        Assert.Equal(StatusCodes.Status200OK, feature.StatusCode);
        Assert.Equal(0, feature.Body.Length);
    }

    [Fact]
    public async Task Write_ClearsWhateverCameBefore()
    {
        var context = NewContext(out var body);
        context.Response.StatusCode = StatusCodes.Status418ImATeapot;
        context.Response.Headers["X-Pre"] = "leftover";

        await CredProxProblemResponses.WriteAsync(context.Response, 400, "credprox.triage", "Triaged");

        Assert.Equal(400, context.Response.StatusCode);
        Assert.False(context.Response.Headers.ContainsKey("X-Pre"));
        Assert.Equal("application/problem+json", context.Response.ContentType);
        var json = BodyOf(body);
        Assert.Contains("credprox.triage", json, StringComparison.Ordinal);
        Assert.Contains("Triaged", json, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Write_RetryAfter_FloorsAtOne_AndPassesLargerValues()
    {
        // Sub-second (or zero) waits must still claim one second; a real wait renders
        // verbatim in the invariant culture.
        var shortContext = NewContext(out _);
        await CredProxProblemResponses.WriteAsync(
            shortContext.Response, 429, "credprox.throttled", "Slow down", retryAfter: TimeSpan.Zero);
        Assert.Equal("1", shortContext.Response.Headers.RetryAfter);

        var longContext = NewContext(out _);
        await CredProxProblemResponses.WriteAsync(
            longContext.Response, 429, "credprox.throttled", "Slow down", retryAfter: TimeSpan.FromSeconds(5));
        Assert.Equal("5", longContext.Response.Headers.RetryAfter);
    }

    [Fact]
    public async Task Write_Extensions_JoinTheProblemMembers()
    {
        var context = NewContext(out var body);

        await CredProxProblemResponses.WriteAsync(
            context.Response,
            403,
            "credprox.consent_required",
            "Consent",
            extensions: new Dictionary<string, object?> { ["authorize_url"] = "https://consent.invalid/x" });

        Assert.Contains("authorize_url", BodyOf(body), StringComparison.Ordinal);
    }

    [Fact]
    public async Task CreateResponse_Guards_AndWritesTheSameProblemShape()
    {
        Assert.Throws<ArgumentNullException>(() => CredProxProblemResponses.CreateResponse(503, null!, "T"));
        Assert.Throws<ArgumentException>(() => CredProxProblemResponses.CreateResponse(503, "", "T"));
        Assert.Throws<ArgumentNullException>(() => CredProxProblemResponses.CreateResponse(503, "credprox.x", null!));
        Assert.Throws<ArgumentException>(() => CredProxProblemResponses.CreateResponse(503, "credprox.x", ""));

        var response = CredProxProblemResponses.CreateResponse(503, "credprox.open", "Circuit open");

        Assert.Equal(System.Net.HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType!.MediaType);
        var json = await response.Content.ReadAsStringAsync();
        Assert.Contains("credprox.open", json, StringComparison.Ordinal);
        Assert.Contains("Circuit open", json, StringComparison.Ordinal);
    }

    [Fact]
    public void CreateProblemBytes_GuardsItsArguments()
    {
        Assert.Throws<ArgumentNullException>(
            () => CredProxProblemResponses.CreateProblemBytes(null!, 502, "T", new()));
        Assert.Throws<ArgumentException>(
            () => CredProxProblemResponses.CreateProblemBytes("", 502, "T", new()));
        Assert.Throws<ArgumentNullException>(
            () => CredProxProblemResponses.CreateProblemBytes("t", 502, null!, new()));
        Assert.Throws<ArgumentException>(
            () => CredProxProblemResponses.CreateProblemBytes("t", 502, "", new()));
    }

    // ---- metadata readers ----

    [Fact]
    public void Metadata_ReadersGuardTheirContext()
    {
        Assert.Throws<ArgumentNullException>(() => CredProxMetadata.GetRouteMetadata(null!));
        Assert.Throws<ArgumentNullException>(() => CredProxMetadata.GetClusterMetadata(null!));
    }

    // ---- request state abort ----

    private static (CredProxRequestState State, DefaultHttpContext Context, MemoryStream Body) State()
    {
        var context = NewContext(out var body);
        return (
            new CredProxRequestState(context, new HttpRequestMessage(HttpMethod.Get, "https://vendor.invalid/x")),
            context,
            body);
    }

    [Fact]
    public async Task Abort_GuardsRunBeforeAnythingElse()
    {
        var (state, _, _) = State();

        await Assert.ThrowsAsync<ArgumentException>(
            () => state.AbortAsync(400, "", "T").AsTask());
        await Assert.ThrowsAsync<ArgumentException>(
            () => state.AbortAsync(400, "credprox.x", "").AsTask());
        Assert.False(state.IsAborted); // a rejected guard never flips the flag

        var extensions = new Dictionary<string, object?> { ["k"] = "v" };
        await Assert.ThrowsAsync<ArgumentException>(
            () => state.AbortAsync(400, "", "T", extensions).AsTask());
        await Assert.ThrowsAsync<ArgumentException>(
            () => state.AbortAsync(400, "credprox.x", "", extensions).AsTask());
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => state.AbortAsync(400, "credprox.x", "T", (IReadOnlyDictionary<string, object?>)null!).AsTask());
        Assert.False(state.IsAborted);
    }

    [Fact]
    public async Task Abort_SecondAbortDoesNotRewriteTheFirstAnswer()
    {
        var (state, context, body) = State();

        await state.AbortAsync(400, "credprox.first", "First");

        Assert.True(state.IsAborted);
        Assert.Contains("credprox.first", BodyOf(body), StringComparison.Ordinal);

        await state.AbortAsync(500, "credprox.second", "Second");

        Assert.Equal(400, context.Response.StatusCode);
        Assert.DoesNotContain("credprox.second", BodyOf(body), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Abort_ExtensionsOverload_FirstAbortWinsToo()
    {
        var (state, _, body) = State();
        await state.AbortAsync(403, "credprox.first", "First");
        var before = BodyOf(body);

        await state.AbortAsync(
            503, "credprox.second", "Second", new Dictionary<string, object?> { ["authorize_url"] = "x" });

        Assert.Equal(before, BodyOf(body));
    }
}
