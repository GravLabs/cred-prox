using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using CredProx;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// A vendor that serialises an echoed credential through a JSON encoder emitting
/// <c>\uXXXX</c> escapes (System.Text.Json escapes +, &lt;, &gt;, &amp; by default,
/// and base64 secrets routinely contain + and /) must not reach the caller either.
/// The scrubber matches through an unescaped view but replaces spans in the ORIGINAL
/// escaped bytes, so the response body stays exactly as parseable as it arrived.
/// </summary>
public sealed class JsonEscapedEchoTests
{
    private const string B64ish = "YWJj+de/f==ghij";
    private const string Ascii = "SUPERVENDORCRED123";

    private static ResponseScrubFeature Feature() =>
        new(new CredProxScrubbingOptions { Enabled = true }, NullLogger<ResponseScrubFeature>.Instance);

    private static HttpResponseMessage JsonResponse(string body)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body) };
        response.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/json");
        return response;
    }

    private static async Task<string> Scrubbed(string body, string secret)
    {
        var response = JsonResponse(body);
        var context = new DefaultHttpContext();
        var state = new CredProxRequestState(context, new HttpRequestMessage(HttpMethod.Get, "http://upstream/api"))
        {
            ProxyResponse = response,
        };
        context.Features.Set(state);
        CredProxInjectedSecrets.GetOrCreate(context).Register(secret);
        await Feature().ApplyAsync(context, CancellationToken.None);
        return await response.Content.ReadAsStringAsync();
    }

    // ---- the controls: what already works must keep working ----

    [Fact]
    public async Task PlainEcho_Control_StillScrubbed()
    {
        Assert.Equal("""{"k":"[redacted]"}""", await Scrubbed("""{"k":"YWJj+de/f==ghij"}""", B64ish));
    }

    [Fact]
    public async Task UrlEncodedEcho_Control_StillScrubbed()
    {
        Assert.Equal("""{"u":"[redacted]"}""", await Scrubbed("""{"u":"YWJj%2Bde%2Ff%3D%3Dghij"}""", B64ish));
    }

    // ---- the escaped shapes that currently walk through ----

    [Fact]
    public async Task EscapedEcho_LowercaseHex_Scrubbed_AndBodyStillParses()
    {
        var scrubbed = await Scrubbed("""{"k":"YWJj\u002bde\u002ff\u003d\u003dghij"}""", B64ish);
        Assert.Equal("""{"k":"[redacted]"}""", scrubbed);
        using var _ = JsonDocument.Parse(scrubbed); // the replacement landed in the original bytes
    }

    [Fact]
    public async Task EscapedEcho_UppercaseHexWithRawTail_Scrubbed()
    {
        Assert.Equal(
            """{"k":"[redacted]"}""",
            await Scrubbed("""{"k":"YWJj\u002Bde/f==ghij"}""", B64ish));
    }

    [Fact]
    public async Task EscapedEcho_SplitAcrossBothHexCases_Scrubbed()
    {
        Assert.Equal(
            """{"a":"[redacted]","b":"[redacted]"}""",
            await Scrubbed("""{"a":"YWJj\u002bde/f==ghij","b":"YWJj\u002Bde/f==ghij"}""", B64ish));
    }

    [Fact]
    public async Task EscapedEcho_AsciiSecretLeadingChar_Scrubbed()
    {
        Assert.Equal(
            """{"k":"[redacted]"}""",
            await Scrubbed("""{"k":"\u0053UPERVENDORCRED123"}""", Ascii));
    }

    // ---- multi-byte secret characters match through escapes too ----

    [Fact]
    public async Task EscapedEcho_TwoAndThreeByteSecretChars_Scrubbed_AndBodyStillParses()
    {
        var scrubbed = await Scrubbed(
            """{"k":"key-\u00e4-\u4e2d-value"}""", "key-ä-中-value");
        Assert.Equal("""{"k":"[redacted]"}""", scrubbed);
        using var _ = JsonDocument.Parse(scrubbed);
    }

    [Fact]
    public async Task EscapedEcho_SurrogatePairSecret_Scrubbed_AndBodyStillParses()
    {
        var scrubbed = await Scrubbed(
            """{"k":"\ud83d\ude00-cred"}""", char.ConvertFromUtf32(0x1F600) + "-cred");
        Assert.Equal("""{"k":"[redacted]"}""", scrubbed);
        using var _ = JsonDocument.Parse(scrubbed);
    }

    // ---- malformed escapes are ordinary text, never an exception ----

    [Fact]
    public async Task MalformedEscapes_NeverThrow_AndRawEchoInSameBodyStillScrubbed()
    {
        var scrubbed = await Scrubbed(
            """{"n":"tail\uXYZ and \u and \00 and \ud800 and \ud800\u0041","k":"YWJj+de/f==ghij"}""", B64ish);
        Assert.Equal("""{"n":"tail\uXYZ and \u and \00 and \ud800 and \ud800\u0041","k":"[redacted]"}""", scrubbed);
    }

    // ---- the error path: the normaliser must only ever see a scrubbed body ----

    [Fact]
    public async Task VendorError_EscapedEcho_VendorDetailCarriesNoSecret()
    {
        var response = new HttpResponseMessage(HttpStatusCode.InternalServerError)
        {
            Content = new StringContent("""{"k":"YWJj\u002Bde/f==ghij"}"""),
        };
        response.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/json");
        var context = M4Contexts.Create(out _);
        context.Features.Get<CredProxRequestState>()!.ProxyResponse = response;
        CredProxInjectedSecrets.GetOrCreate(context).Register(B64ish);

        // The live pipeline's order: scrub first, normalise second.
        await Feature().ApplyAsync(context, CancellationToken.None);
        await new ErrorNormalisationFeature(
            new CredProxErrorsOptions { Enabled = true, MaxNormalisedBodyBytes = 8192 },
            NullLogger<ErrorNormalisationFeature>.Instance)
            .ApplyAsync(context, CancellationToken.None);

        using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(
            "[redacted]",
            problem.RootElement
                .GetProperty("extensions")
                .GetProperty("vendor_detail")
                .GetProperty("k")
                .GetString());
    }
}
