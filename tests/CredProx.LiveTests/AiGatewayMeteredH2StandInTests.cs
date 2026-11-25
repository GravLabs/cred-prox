using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Xunit;
using Xunit.Abstractions;
namespace CredProx.LiveTests;

// The offline repro for the live metered failure (row 2026-11-23, merge held): the real
// Anthropic run proxied POST /ai/v1/messages 200 with usage in the body, yet produced no
// audit line and no metric points, and even the audited GET never reached the console
// exporter. The offline stand-in never drove this shape: StubApi speaks HTTP/1.1 with
// Content-Length framing, and its /v1/messages is SSE without usage. This cell drives the
// shipped sample host against an in-process HTTP/2-cleartext vendor stand-in that mirrors
// the real one: GET /v1/models answers JSON with Content-Length, POST /v1/messages answers
// application/json carrying a usage report with NO Content-Length (the real h2 responses
// end by stream termination), and the route is usage-opted-in so the metering leg installs
// its peek on both responses. Offline always: no vendor env needed, no traffic leaves.
[Collection("AiGateway")]
[Trait("Layer", "Offline")]
public sealed class AiGatewayMeteredH2StandInTests
{
    private const int VendorPort = 8098;
    private const int HostPort = 5091;
    private const string VendorUrl = "http://localhost:8098";
    private const string HostUrl = "http://localhost:5091";
    // a planted fake of the same shape as the fixture's; never a real key
    private const string VendorFakeKey = "sk-ant-h2standinfake-ZZZZZZZZZZZZZZZZZZZZZZ";

    private readonly AiGatewayFixture _fixture;
    private readonly ITestOutputHelper _output;

    public AiGatewayMeteredH2StandInTests(AiGatewayFixture fixture, ITestOutputHelper output)
    {
        _fixture = fixture;
        _output = output;
    }

    [Fact]
    public async Task MeteredCalls_OverHttp2VendorStandIn_AuditAndTokenCountersReachTheConsoleExporter()
    {
        LiveHosts.EnsurePortsFree(VendorPort, HostPort);
        using var vendor = await StartVendorStandInAsync();
        var callerKey = "h2-metered-" + Guid.NewGuid().ToString("N");
        var secrets = new List<string> { VendorFakeKey };
        var env = new Dictionary<string, string>
        {
            ["Urls"] = HostUrl,
            ["CredProx__Secrets__ai-provider-key"] = VendorFakeKey,
            ["CredProx__Destinations__ai__Template"] = VendorUrl + "/",
            ["ReverseProxy__Clusters__ai__Destinations__ai__Address"] = VendorUrl + "/",
            // cleartext HTTP/2 needs exact versioning on the outbound request
            ["ReverseProxy__Clusters__ai__HttpRequest__Version"] = "2",
            ["ReverseProxy__Clusters__ai__HttpRequest__VersionPolicy"] = "RequestVersionExact",
            ["CredProx__Credentials__ai-provider__Name"] = "x-api-key",
            ["CredProx__Credentials__ai-provider__Prefix"] = "",
            ["ReverseProxy__Routes__ai__Transforms__1__RequestHeader"] = "anthropic-version",
            ["ReverseProxy__Routes__ai__Transforms__1__Set"] = "2023-06-01",
            ["CredProx__Callers__h2-metered__Keys__0__KeyId"] = "h2-metered-key-1",
            ["CredProx__Callers__h2-metered__Keys__0__KeyHash"] = AiGatewayFixture.CallerKeyConfig(callerKey),
            ["CredProx__Callers__h2-metered__Operations__0__Route"] = "ai",
            ["CredProx__Callers__h2-metered__Operations__0__Methods__0"] = "GET",
            ["CredProx__Callers__h2-metered__Operations__0__Paths__0"] = "/ai/v1/models",
            ["CredProx__Callers__h2-metered__Operations__1__Route"] = "ai",
            ["CredProx__Callers__h2-metered__Operations__1__Methods__0"] = "POST",
            ["CredProx__Callers__h2-metered__Operations__1__Paths__0"] = "/ai/v1/messages",
            ["Metrics__Console"] = "true",
            ["OTEL_METRIC_EXPORT_INTERVAL"] = "1000",
        };
        var host = _fixture.StartHost(env, secrets, HostPort);
        try
        {
            await _fixture.WaitForHostAsync(host, HostUrl);
            using var client = new HttpClient { BaseAddress = new Uri(HostUrl) };
            var models = await client.SendAsync(NewRequest(HttpMethod.Get, "/ai/v1/models", callerKey));
            var modelsBody = await models.Content.ReadAsStringAsync();
            Assert.True(
                (int)models.StatusCode == 200,
                $"models list answered {(int)models.StatusCode}: "
                + SecretLeakScanner.Sanitize(modelsBody, secrets) + "\n"
                + SecretLeakScanner.Sanitize(host.Stdout + host.Stderr, secrets));
            var post = NewRequest(HttpMethod.Post, "/ai/v1/messages", callerKey);
            post.Content = new StringContent(
                "{\"model\":\"claude-3-5-sonnet\",\"max_tokens\":1,\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}",
                Encoding.UTF8,
                "application/json");
            var answered = await client.SendAsync(post);
            var answeredBody = await answered.Content.ReadAsStringAsync();
            Assert.True(
                (int)answered.StatusCode == 200,
                $"metered call answered {(int)answered.StatusCode}: "
                + SecretLeakScanner.Sanitize(answeredBody, secrets) + "\n"
                + SecretLeakScanner.Sanitize(host.Stdout + host.Stderr, secrets));
            Assert.Contains("\"usage\"", answeredBody, StringComparison.Ordinal);
            // the live failure signature, asserted one step at a time so the output names
            // the first leg that died: the POST's audit line, then the request counter,
            // then the provider's own token report. The failure text is built AT FAILURE
            // TIME (the live cell's was built at call time) and always carries stderr and
            // the host's exit state — a dead host must announce itself, not spin.
            await LiveHosts.WaitUntilAsync(
                () => Task.FromResult(LiveHosts.ContainsOnOneLine(
                    host.Stdout, "credprox.proxied_call: caller=h2-metered", "method=POST")),
                "the POST never reached the audit recorder on completion",
                host, secrets, 12);
            await LiveHosts.WaitUntilAsync(
                () => Task.FromResult(LiveHosts.CounterValue(host.Stdout, "credprox.requests") > 0),
                "no credprox.requests point on the console exporter",
                host, secrets, 12);
            await LiveHosts.WaitUntilAsync(
                () => Task.FromResult(
                    LiveHosts.CounterValue(host.Stdout, "credprox.usage.input_tokens") > 0
                    && LiveHosts.CounterValue(host.Stdout, "credprox.usage.output_tokens") > 0),
                "token counters never showed non-zero values on the console exporter",
                host, secrets, 12);
            var inputs = LiveHosts.CounterValue(host.Stdout, "credprox.usage.input_tokens");
            var outputs = LiveHosts.CounterValue(host.Stdout, "credprox.usage.output_tokens");
            _output.WriteLine($"OBSERVED metered_calls=2 billable_calls=1 input_tokens={inputs} output_tokens={outputs}");
            var log = host.Stdout + host.Stderr;
            Assert.Empty(SecretLeakScanner.FindLeaks(log, secrets));
            Assert.DoesNotContain(callerKey, log, StringComparison.Ordinal);
        }
        finally
        {
            TryStop(host.Process);
        }
    }

    private static void TryStop(System.Diagnostics.Process process)
    {
        try
        {
            process.Kill(entireProcessTree: true);
            process.WaitForExit(5000);
        }
        catch (InvalidOperationException)
        {
            // already exited
        }
    }

    // The vendor stand-in: cleartext HTTP/2 on its own socket, responses framed the way
    // the real backend frames them — GET JSON gets its Content-Length, POST JSON ends by
    // stream termination (Kestrel emits no framing header for an unknown-length h2
    // response). Both endpoints require the provider key the gateway injected.
    private static async Task<IHost> StartVendorStandInAsync()
    {
        var builder = WebApplication.CreateSlimBuilder();
        // the stand-in's own logger stays on: when its handler throws, the unhandled
        // exception must surface in the test output instead of only a bare 500
        builder.Logging.ClearProviders();
        builder.Logging.AddSimpleConsole(o => o.SingleLine = true);
        builder.WebHost.ConfigureKestrel(options => options.ListenLocalhost(
            VendorPort, listen => listen.Protocols = HttpProtocols.Http2));
        var app = builder.Build();
        app.MapGet("/v1/models", async context =>
        {
            if (context.Request.Headers["x-api-key"] != VendorFakeKey)
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("""{"error":{"type":"authentication_error"}}""");
                return;
            }

            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                """{"data":[{"type":"model","id":"claude-3-5-sonnet","display_name":"Claude 3.5 Sonnet"}],"has_more":false}""");
        });
        app.MapPost("/v1/messages", async context =>
        {
            if (context.Request.Headers["x-api-key"] != VendorFakeKey)
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("""{"error":{"type":"authentication_error"}}""");
                return;
            }

            // the request body is not read here; Kestrel drains it on completion, which
            // is all the gateway's counting stream needs the send leg to have pushed
            try
            {
                // unknown length by default: Kestrel ends an h2 response with no
                // content-length by stream termination, as the real vendor does
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(
                    """{"id":"msg_h2standin","type":"message","role":"assistant","model":"claude-3-5-sonnet","content":[{"type":"text","text":"Hi"}],"stop_reason":"end_turn","usage":{"input_tokens":9,"output_tokens":7}}""");
            }
            catch (Exception ex)
            {
                // xunit swallows the stand-in's console; surface the fault through the
                // body so it reaches the caller and the assertion's failure text
                context.Response.Clear();
                context.Response.StatusCode = 500;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(
                    "{\"debug_error\":\"" + ex.GetType().Name + ": " + ex.Message.Replace("\\", "/").Replace("\"", "'") + "\"}");
            }
        });
        await app.StartAsync();
        return app;
    }

    private static HttpRequestMessage NewRequest(HttpMethod method, string path, string callerKey)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.Add("X-CredProx-Key", callerKey);
        return request;
    }
}
