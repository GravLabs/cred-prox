using System.Net;
using System.Text;
using CredProx.Testing;
using Microsoft.Extensions.Logging;
using Xunit;

namespace CredProx.ConformanceTests;

/// <summary>
/// §5.2 "the Testing package is tested": the helper pieces plugin authors build their
/// suites on — the fake servers' scripting/recording and the log sink's capture and
/// secret assertion. A broken helper silently weakens every suite that uses it, so the
/// helpers get their own direct checks, not just incidental coverage from the built-ins.
/// </summary>
public sealed class TestingHelperTests
{
    [Fact]
    public async Task FakeUpstream_DefaultAnswers200EmptyJson()
    {
        var upstream = new FakeUpstream();
        using var client = new HttpClient(upstream);

        var response = await client.GetAsync("http://vendor.example/api");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("{}", await response.Content.ReadAsStringAsync());
        Assert.Equal(1, upstream.CallCount);
        Assert.Single(upstream.Requests);
    }

    [Fact]
    public async Task FakeUpstream_ScriptDrivesFirstThenResponderTakesOver()
    {
        var upstream = new FakeUpstream();
        using var client = new HttpClient(upstream);

        upstream.Enqueue(HttpStatusCode.Unauthorized, """{"error":"expired"}""");
        upstream.Enqueue(static req => new HttpResponseMessage(HttpStatusCode.NoContent)
        {
            RequestMessage = req,
        });
        upstream.Responder = static _ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);

        var first = await client.GetAsync("http://vendor.example/api");
        var second = await client.PostAsync("http://vendor.example/api", new StringContent("body"));
        var third = await client.GetAsync("http://vendor.example/anything");

        Assert.Equal(HttpStatusCode.Unauthorized, first.StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, second.StatusCode);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, third.StatusCode);
        Assert.Equal(3, upstream.CallCount);
        Assert.Equal(HttpMethod.Post, upstream.Requests[1].Method);

        upstream.Reset();
        Assert.Equal(0, upstream.CallCount);
        Assert.Empty(upstream.Requests);
    }

    [Fact]
    public async Task FakeTokenServer_DefaultHandsOutAFreshTokenPerCall()
    {
        var server = new FakeTokenServer();
        using var client = new HttpClient(server);

        var first = await client.PostAsync(
            "http://vendor.example/oauth/token",
            new FormUrlEncodedContent(new Dictionary<string, string> { ["grant_type"] = "client_credentials" }));
        var second = await client.PostAsync(
            "http://vendor.example/oauth/token",
            new StringContent("grant_type=other"));

        Assert.Contains("tok-1", await first.Content.ReadAsStringAsync());
        Assert.Contains("tok-2", await second.Content.ReadAsStringAsync());
        Assert.Equal(2, server.CallCount);
        Assert.Equal(2, server.Requests.Count);
        Assert.StartsWith("grant_type=client_credentials", server.RequestBodies[0]!);
        Assert.Equal("grant_type=other", server.RequestBodies[1]);
    }

    [Fact]
    public async Task FakeTokenServer_ScriptThenResetThenCustomResponder()
    {
        var server = new FakeTokenServer();
        using var client = new HttpClient(server);

        server.Enqueue(HttpStatusCode.BadRequest, """{"error":"invalid_client"}""");
        server.Enqueue(static _ => new HttpResponseMessage(HttpStatusCode.TooManyRequests));

        var rejected = await client.PostAsync("http://vendor.example/oauth/token", new StringContent("x"));
        var throttled = await client.PostAsync("http://vendor.example/oauth/token", new StringContent("x"));
        Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, throttled.StatusCode);

        server.Reset();
        server.Responder = static (_, callNumber) => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                $$"""{"access_token":"custom-{{callNumber}}","expires_in":60}""",
                Encoding.UTF8,
                "application/json"),
        };

        var custom = await client.PostAsync("http://vendor.example/oauth/token", new StringContent("x"));

        Assert.Contains("custom-1", await custom.Content.ReadAsStringAsync());
        Assert.Equal(1, server.CallCount); // counted fresh after Reset
    }

    [Fact]
    public void CapturedLogSink_CapturesLinesAndExceptionsAndAsserts()
    {
        var sink = new CapturedLogSink();
        using var factory = LoggerFactory.Create(b => b.AddProvider(sink));
        var logger = factory.CreateLogger("Test.Category");

        logger.LogInformation("hello {Value}", 42);
        logger.LogError(new InvalidOperationException("bad"), "failed");

        Assert.Contains("[Information] Test.Category: hello 42", sink.Lines);
        Assert.Contains(sink.Lines, static l => l.Contains("System.InvalidOperationException: bad", StringComparison.Ordinal));

        sink.AssertNoSecretValues(["s3cret", string.Empty]); // absent value and empty value both pass

        var offender = Assert.ThrowsAny<Exception>(() => sink.AssertNoSecretValues(["hello"]));
        Assert.Contains("secret value appeared", offender.Message!, StringComparison.OrdinalIgnoreCase);

        sink.Clear();
        Assert.Empty(sink.Lines);
        sink.Dispose();
    }
}
