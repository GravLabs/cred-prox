using System.Net;
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
/// §8.5 as a property (M24): whatever the credential value and whatever the vendor's
/// error body, the normalised problem document never carries the secret — the embed
/// consumes only already-scrubbed bytes — and the cap-overflow passthrough replays the
/// vendor's body byte for byte, whatever those bytes are.
/// </summary>
public sealed class ErrorNormalisationProperties
{
    private static HttpResponseMessage ScrubThenNormalise(string body, string secret, string contentType)
    {
        var response = new HttpResponseMessage(HttpStatusCode.InternalServerError)
        {
            Content = new StringContent(body),
        };
        response.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType);

        var context = new DefaultHttpContext();
        context.Request.Method = "GET";
        context.Features.Set(
            new CredProxRequestState(context, new HttpRequestMessage(HttpMethod.Get, "http://upstream/api"))
            {
                ProxyResponse = response,
            });
        CredProxInjectedSecrets.GetOrCreate(context).Register(secret);

        // The production order, mirrored: scrubber first, normaliser second.
        new ResponseScrubFeature(
                new CredProxScrubbingOptions(), NullLogger<ResponseScrubFeature>.Instance)
            .ApplyAsync(context, CancellationToken.None).GetAwaiter().GetResult();
        new ErrorNormalisationFeature(
                new CredProxErrorsOptions(), NullLogger<ErrorNormalisationFeature>.Instance)
            .ApplyAsync(context, CancellationToken.None).GetAwaiter().GetResult();
        return response;
    }

    [Property(MaxTest = 200)]
    public void NormalisedDetail_NeverCarriesTheSecret(NonNull<string> generated)
    {
        var secret = "s3cr3t-" + generated.Get;
        var response = ScrubThenNormalise($"error page: you sent {secret}", secret, "text/plain");

        var body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        Assert.DoesNotContain(secret, body, StringComparison.Ordinal);
        // The uniform document landed, carrying the already-redacted payload.
        Assert.Contains("[redacted]", body, StringComparison.Ordinal);
        Assert.Contains("urn:credprox:errors:vendor", body, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
    }

    [Property(MaxTest = 200)]
    public void NormalisedJsonDetail_NeverCarriesTheSecret(NonNull<string> generated)
    {
        // The vendor's JSON error echoing the credential; whatever the generated value
        // does to the JSON's validity, the parsed-object or raw-text embed stays clean.
        var secret = "s3cr3t-" + generated.Get;
        var response = ScrubThenNormalise(
            "{\"echo\":\"" + secret + "\"}", secret, "application/json");

        var body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        Assert.DoesNotContain(secret, body, StringComparison.Ordinal);
        Assert.Contains("credprox.vendor_error", body, StringComparison.Ordinal);
    }

    [Property(MaxTest = 100)]
    public async Task OverflowedBody_ReplaysEveryGeneratedByte(byte[] generated)
    {
        if (generated.Length == 0)
        {
            return;
        }

        // A body beyond the cap must reach the caller exactly as generated — the
        // buffered prefix plus the unread remainder, no truncation, no re-encoding.
        var raw = new StreamContent(new MemoryStream(generated));
        raw.Headers.ContentType = MediaTypeHeaderValue.Parse("text/plain");
        raw.Headers.ContentLength = null;
        var response = new HttpResponseMessage(HttpStatusCode.InternalServerError) { Content = raw };

        var context = new DefaultHttpContext();
        context.Request.Method = "GET";
        context.Features.Set(
            new CredProxRequestState(context, new HttpRequestMessage(HttpMethod.Get, "http://upstream/api"))
            {
                ProxyResponse = response,
            });

        await new ErrorNormalisationFeature(
            new CredProxErrorsOptions { MaxNormalisedBodyBytes = generated.Length / 2 },
            NullLogger<ErrorNormalisationFeature>.Instance).ApplyAsync(context, CancellationToken.None);

        Assert.Equal(generated, await response.Content.ReadAsByteArrayAsync());
    }
}
