using System.IO.Compression;
using System.Net.Http.Headers;
using System.Text;
using CredProx;
using FsCheck;
using FsCheck.Xunit;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace CredProx.SecurityTests;

/// <summary>
/// §8.2 as a property: whatever the credential value is and wherever the upstream
/// reflects it back — plain body, gzipped body, SSE event, response header — the
/// caller-facing response never contains the value, and the redaction marker shows the
/// scrub fired.
/// </summary>
public sealed class ResponseScrubProperties
{
    private static HttpResponseMessage Scrub(
        string body,
        string secret,
        string contentType,
        byte[]? rawBody = null,
        Action<HttpResponseMessage>? configure = null)
    {
        var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK)
        {
            Content = rawBody is null ? new StringContent(body) : new ByteArrayContent(rawBody),
        };
        response.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType);
        configure?.Invoke(response); // the echo must exist before the scrubber runs

        var context = new DefaultHttpContext();
        context.Features.Set(
            new CredProxRequestState(context, new HttpRequestMessage(HttpMethod.Get, "http://upstream/api"))
            {
                ProxyResponse = response,
            });
        CredProxInjectedSecrets.GetOrCreate(context).Register(secret);

        var feature = new ResponseScrubFeature(
            new CredProxScrubbingOptions(), NullLogger<ResponseScrubFeature>.Instance);
        feature.ApplyAsync(context, CancellationToken.None).GetAwaiter().GetResult();
        return response;
    }

    [Property(MaxTest = 200)]
    public void ReflectedInTheBody_NeverReachesTheCaller(NonNull<string> generated)
    {
        var secret = "s3cr3t-" + generated.Get;
        var response = Scrub($"error page echoed: {secret} back to you", secret, "text/plain");

        var body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        Assert.DoesNotContain(secret, body, StringComparison.Ordinal);
        Assert.Contains("[redacted]", body, StringComparison.Ordinal);
    }

    [Property(MaxTest = 200)]
    public void ReflectedInAGzippedBody_NeverReachesTheCaller(NonNull<string> generated)
    {
        var secret = "s3cr3t-" + generated.Get;
        using var compressed = new MemoryStream();
        using (var gzip = new GZipStream(compressed, CompressionMode.Compress, leaveOpen: true))
        {
            gzip.Write(Encoding.UTF8.GetBytes($"stack: {secret} crashed"));
        }

        var response = Scrub(
            body: string.Empty,
            secret,
            "text/plain",
            rawBody: compressed.ToArray(),
            configure: r => r.Content.Headers.TryAddWithoutValidation("Content-Encoding", "gzip"));

        var body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        Assert.DoesNotContain(secret, body, StringComparison.Ordinal);
        Assert.Contains("[redacted]", body, StringComparison.Ordinal);
        // Forwarded decompressed — no hidden recompression keeping the value encoded.
        Assert.Empty(response.Content.Headers.ContentEncoding);
    }

    [Property(MaxTest = 200)]
    public void ReflectedInAnEventStreamEvent_NeverReachesTheCaller(NonNull<string> generated)
    {
        // Newlines inside the secret would split it across event boundaries — that is
        // the framing's documented residue — so this property speaks to within-event
        // reflection: CR and LF are taken out of the generated shape.
        var secret = "s3cr3t-" + generated.Get.Replace("\r", "|").Replace("\n", "|");
        var response = Scrub(
            $"event: error\ndata: you sent Bearer {secret}\n\ndata: done\n\n",
            secret,
            "text/event-stream");

        var body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        Assert.DoesNotContain(secret, body, StringComparison.Ordinal);
        Assert.Contains("[redacted]", body, StringComparison.Ordinal);
        // The framing survives scrubbing byte-for-byte outside the secret.
        Assert.Contains("event: error\ndata: you sent Bearer ", body, StringComparison.Ordinal);
        Assert.EndsWith("data: done\n\n", body, StringComparison.Ordinal);
    }

    [Property(MaxTest = 200)]
    public void ReflectedInAResponseHeader_NeverReachesTheCaller(NonNull<string> generated)
    {
        var secret = "s3cr3t-" + generated.Get;
        var response = Scrub(
            "ok",
            secret,
            "text/plain",
            configure: r => r.Headers.TryAddWithoutValidation("X-Echo", $"Bearer {secret}"));

        Assert.DoesNotContain(secret, response.Headers.ToString(), StringComparison.Ordinal);
        Assert.Contains("[redacted]", response.Headers.GetValues("X-Echo").Single(), StringComparison.Ordinal);
    }
}
