using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using CredProx;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M47 security finding F-3: <c>CredProx:Scrubbing:FailClosed</c> (opt-in, default off).
/// When on, a response whose body the scrubber cannot inspect is refused with a
/// <c>credprox.response_uninspectable</c> problem response instead of forwarded — the
/// four classes the pass-through warning already names, on success and error responses
/// alike. Honest status: a refused 2xx/3xx is answered 502 (CredProx never reports
/// success for bytes it withheld); a vendor 4xx/5xx keeps its status, the problem body
/// in place of the withheld bytes. A response with <b>no body</b> is never refused —
/// nothing is to inspect: an empty body, a HEAD response, and a bodiless redirect all
/// pass unchanged (an unknown-length body is decided by whether any body byte arrives).
/// Default-off behaviour stays byte-identical, and a refusal document is never
/// re-normalised as a vendor error.
/// </summary>
public sealed class ScrubFailClosedTests
{
    private const string Secret = "SUPERVENDORCRED123";

    private static ResponseScrubFeature FailClosedFeature(ILogger<ResponseScrubFeature>? logger = null) =>
        new(new CredProxScrubbingOptions { Enabled = true, FailClosed = true },
            logger ?? NullLogger<ResponseScrubFeature>.Instance);

    private static HttpResponseMessage Body(
        string? mediaTypeOrNull,
        string body,
        HttpStatusCode status = HttpStatusCode.OK,
        string? contentEncoding = null)
    {
        var response = new HttpResponseMessage(status) { Content = new StringContent(body) };
        if (mediaTypeOrNull is null)
        {
            response.Content.Headers.ContentType = null;
        }
        else
        {
            response.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(mediaTypeOrNull);
        }

        if (contentEncoding is not null)
        {
            response.Content.Headers.TryAddWithoutValidation("Content-Encoding", contentEncoding);
        }

        return response;
    }

    private static DefaultHttpContext Context(HttpResponseMessage response)
    {
        var context = new DefaultHttpContext();
        var state = new CredProxRequestState(context, new HttpRequestMessage(HttpMethod.Get, "http://upstream/api"))
        {
            ProxyResponse = response,
        };

        context.Features.Set(state);
        CredProxInjectedSecrets.GetOrCreate(context).Register(Secret);
        return context;
    }

    private static void AssertRefusal(HttpResponseMessage response, int expectedStatus, string expectedClass)
    {
        Assert.Equal(expectedStatus, (int)response.StatusCode);
        Assert.StartsWith("application/problem+json", response.Content.Headers.ContentType!.ToString(),
            StringComparison.Ordinal);
        using var document = JsonDocument.Parse(response.Content.ReadAsStringAsync().GetAwaiter().GetResult());
        var root = document.RootElement;
        // The shipped CredProx problem shape nests extension members under "extensions"
        // (CredProxProblemResponses.ProblemDetails serializes the dictionary as one member).
        var extensions = root.GetProperty("extensions");
        Assert.Equal("urn:credprox:errors:proxy", root.GetProperty("type").GetString());
        Assert.Equal(expectedStatus, root.GetProperty("status").GetInt32());
        Assert.Equal("credprox.response_uninspectable", extensions.GetProperty("code").GetString());
        Assert.Equal(expectedClass, extensions.GetProperty("response_class").GetString());
    }

    [Fact]
    public async Task NonTextMedia_FailClosed_RefusesWithProblemDocument_NamingTheClass()
    {
        var response = Body("application/octet-stream", $"echo:{Secret}");

        await FailClosedFeature().ApplyAsync(Context(response), CancellationToken.None);

        AssertRefusal(response, 502, "non-text-media-type"); // honest status: a refused success is 502
        Assert.DoesNotContain(Secret, await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task MissingMedia_FailClosed_Refuses_NamingTheMissingType()
    {
        var response = Body(null, $"echo:{Secret}");

        await FailClosedFeature().ApplyAsync(Context(response), CancellationToken.None);

        AssertRefusal(response, 502, "no-media-type");
    }

    [Fact]
    public async Task UnknownEncoding_FailClosed_Refuses_WithoutLeakingTheEcho()
    {
        var response = Body("text/plain", $"echo:{Secret}", contentEncoding: "zzz-unknown");

        await FailClosedFeature().ApplyAsync(Context(response), CancellationToken.None);

        AssertRefusal(response, 502, "unknown-content-encoding");
    }

    [Fact]
    public async Task ZstdEncoding_FailClosed_Refuses()
    {
        // The encoding the docs name as the residue: nothing decodes it, so with
        // FailClosed on it is refused like any unknown encoding, never forwarded.
        var response = Body("text/plain", $"echo:{Secret}", contentEncoding: "zstd");

        await FailClosedFeature().ApplyAsync(Context(response), CancellationToken.None);

        AssertRefusal(response, 502, "unknown-content-encoding");
    }

    [Fact]
    public async Task ChainedEncoding_FailClosed_Refuses()
    {
        var response = Body("text/plain", $"echo:{Secret}", contentEncoding: "gzip, zzz-unknown");

        await FailClosedFeature().ApplyAsync(Context(response), CancellationToken.None);

        AssertRefusal(response, 502, "chained-content-encoding");
    }

    [Fact]
    public async Task ErrorPath_FailClosed_RefusalSurvivesNormalisation_Verbatim()
    {
        // The live order: scrubber first, normaliser second. The refusal is CredProx's
        // own problem shape — it must not be re-wrapped as a vendor error document.
        var response = Body("application/octet-stream", $"echo:{Secret}", HttpStatusCode.InternalServerError);
        var context = Context(response);

        await FailClosedFeature().ApplyAsync(context, CancellationToken.None);
        await new ErrorNormalisationFeature(
            new CredProxErrorsOptions { Enabled = true },
            NullLogger<ErrorNormalisationFeature>.Instance).ApplyAsync(context, CancellationToken.None);

        Assert.Equal(500, (int)response.StatusCode); // a vendor error keeps its status
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain(Secret, body, StringComparison.Ordinal);
        Assert.DoesNotContain("vendor_detail", body, StringComparison.Ordinal);
        using var document = JsonDocument.Parse(body);
        Assert.Equal("urn:credprox:errors:proxy", document.RootElement.GetProperty("type").GetString());
        Assert.Equal("credprox.response_uninspectable",
            document.RootElement.GetProperty("extensions").GetProperty("code").GetString());
    }

    [Fact]
    public async Task VendorErrorStatus_FailClosed_KeepsStatus_AndRefusesBody()
    {
        // The (c) boundary: 4xx is the vendor's own error class and survives; only a
        // refused 2xx/3xx is rewritten to 502.
        var response = Body("application/octet-stream", $"echo:{Secret}", HttpStatusCode.NotFound);

        await FailClosedFeature().ApplyAsync(Context(response), CancellationToken.None);

        AssertRefusal(response, 404, "non-text-media-type");
        Assert.DoesNotContain(Secret, await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task BodilessRedirect_FailClosed_ForwardsUnchanged()
    {
        // Nothing to inspect means nothing to refuse — redirects keep working with the
        // option on (the lead's named pin).
        var response = Body(null, string.Empty, HttpStatusCode.Found);
        response.Headers.Location = new Uri("https://vendor.example/where");
        var context = Context(response);

        await FailClosedFeature().ApplyAsync(context, CancellationToken.None);

        Assert.Equal((int)HttpStatusCode.Found, (int)response.StatusCode);
        Assert.Equal("https://vendor.example/where", response.Headers.Location!.ToString());
        Assert.Empty(await response.Content.ReadAsStringAsync());
        Assert.Null(context.Features.Get<ScrubRefusalMarker>());
    }

    [Fact]
    public async Task NoContent_FailClosed_ForwardsUnchanged()
    {
        var response = Body(null, string.Empty, HttpStatusCode.NoContent);
        var context = Context(response);

        await FailClosedFeature().ApplyAsync(context, CancellationToken.None);

        Assert.Equal((int)HttpStatusCode.NoContent, (int)response.StatusCode);
        Assert.Null(context.Features.Get<ScrubRefusalMarker>());
    }

    [Fact]
    public async Task UnknownLengthEmptyBody_FailClosed_ForwardsUnchanged()
    {
        // Chunked/unknown length is decided by whether any body byte arrives: none do.
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(Array.Empty<byte>()),
        };
        response.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/octet-stream");
        response.Content.Headers.ContentLength = null;
        var context = Context(response);

        await FailClosedFeature().ApplyAsync(context, CancellationToken.None);

        Assert.Equal(200, (int)response.StatusCode);
        Assert.Empty(await response.Content.ReadAsStringAsync());
        Assert.Null(context.Features.Get<ScrubRefusalMarker>());
    }

    [Fact]
    public async Task UnknownLengthBodyWithBytes_FailClosed_Refused()
    {
        // The other half of the probe choice: an unknown-length body that does carry
        // bytes is refused like any other uninspectable body.
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(Encoding.UTF8.GetBytes($"echo:{Secret}")),
        };
        response.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/octet-stream");
        response.Content.Headers.ContentLength = null;

        await FailClosedFeature().ApplyAsync(Context(response), CancellationToken.None);

        AssertRefusal(response, 502, "non-text-media-type");
        Assert.DoesNotContain(Secret, await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task HeadRequest_FailClosed_IsNeverRefused()
    {
        // A HEAD response carries no body whatever its headers claim.
        var response = Body("application/octet-stream", $"echo:{Secret}");
        var context = Context(response);
        context.Request.Method = HttpMethods.Head;

        await FailClosedFeature().ApplyAsync(context, CancellationToken.None);

        Assert.Equal(200, (int)response.StatusCode);
        Assert.Null(context.Features.Get<ScrubRefusalMarker>());
    }

    [Fact]
    public async Task RedirectWithBody_FailClosed_RefusedAsBadGateway()
    {
        // A redirect that does carry uninspectable bytes is a refusal like any other;
        // the response-level Location header is untouched (same doctrine as
        // normalisation: only the content is replaced).
        var response = Body(null, $"echo:{Secret}", HttpStatusCode.Found);
        response.Headers.Location = new Uri("https://vendor.example/where");

        await FailClosedFeature().ApplyAsync(Context(response), CancellationToken.None);

        AssertRefusal(response, 502, "no-media-type");
        Assert.Equal("https://vendor.example/where", response.Headers.Location!.ToString());
        Assert.DoesNotContain(Secret, await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ForwardedNonEmptyBody_FailClosed_IsByteIdentical()
    {
        // The one-byte witness is read only where the refusal replaces the body outright
        // or the forward leaves an empty body — so no byte the caller should receive can
        // be dropped or reordered by it. A clean, unknown-length, text-like body is the
        // forwarded non-empty case: it must arrive byte for byte.
        var payload = "report=clean;value=42;nothing-secret-here";
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(payload, Encoding.UTF8, "text/plain"),
        };
        response.Content.Headers.ContentLength = null;

        await FailClosedFeature().ApplyAsync(Context(response), CancellationToken.None);

        Assert.Equal(payload, await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task FailClosedOff_BodyStillPassesThroughByteIdentical_AndWarns()
    {
        // The no-opt-in promise: default options keep today's byte-identical forward
        // and the one-per-route-and-shape warning.
        var logs = new Capturing();
        var feature = new ResponseScrubFeature(new CredProxScrubbingOptions { Enabled = true }, logs);
        var echo = $"echo:{Secret}";
        var response = Body("application/octet-stream", echo);

        await feature.ApplyAsync(Context(response), CancellationToken.None);

        Assert.Equal(echo, await response.Content.ReadAsStringAsync());
        Assert.Single(logs.Entries, e => e.Level == LogLevel.Warning);
    }

    [Fact]
    public async Task TextEcho_FailClosed_StillScrubbedNotRefused()
    {
        // Over-refusal guard: an inspectable body is scrubbed, never refused.
        var response = Body("text/plain", $"echo:{Secret}");

        await FailClosedFeature().ApplyAsync(Context(response), CancellationToken.None);

        Assert.Equal("echo:[redacted]", await response.Content.ReadAsStringAsync());
        Assert.Equal("text/plain", response.Content.Headers.ContentType!.MediaType);
    }

    /// <summary>Minimal <see cref="ILogger{TCategoryName}"/> capture for the
    /// feature constructor argument.</summary>
    // ---- M47 F-3 follow-through: the refusal says REFUSED, and a declared charset
    // the matcher cannot read joins the refused classes when the option is on ----

    private static HttpResponseMessage Utf16Body(string body, HttpStatusCode status = HttpStatusCode.OK)
    {
        // Real UTF-16 bytes: the scrubber's byte matcher cannot see the echo in them.
        var response = new HttpResponseMessage(status)
        {
            Content = new ByteArrayContent(Encoding.Unicode.GetBytes(body)),
        };
        response.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/json; charset=utf-16");
        return response;
    }

    [Fact]
    public async Task DeclaredNonUtf8Charset_FailClosed_Refuses_NamingTheClass()
    {
        // A declared charset outside the matcher's UTF-8/ASCII set is uninspectable by
        // the same matcher the rest of the pipeline uses: a UTF-16 body carrying the
        // echo survives scrubbing byte-identical today. With FailClosed on it is
        // refused, not forwarded.
        var response = Utf16Body($"echo:{Secret}");

        await FailClosedFeature().ApplyAsync(Context(response), CancellationToken.None);

        AssertRefusal(response, 502, "non-utf8-charset");
        Assert.DoesNotContain(Secret, await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task DeclaredNonUtf8Charset_FailClosedOff_StillForwards_Untouched()
    {
        // Default mode is unchanged: the same response forwards; nothing is refused.
        var response = Utf16Body($"echo:{Secret}");
        var context = Context(response);

        await new ResponseScrubFeature(
                new CredProxScrubbingOptions { Enabled = true },
                NullLogger<ResponseScrubFeature>.Instance)
            .ApplyAsync(context, CancellationToken.None);

        Assert.Equal(200, (int)response.StatusCode);
        Assert.DoesNotContain("problem+json", response.Content.Headers.ContentType?.ToString() ?? "",
            StringComparison.Ordinal);
        Assert.Contains(Secret, await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task DeclaredNonUtf8Charset_FailClosed_HeadResponse_StillForwards()
    {
        // A bodyless response is never refused whatever its charset — nothing to inspect.
        var response = Body("application/json; charset=utf-16", $"echo:{Secret}");
        var context = Context(response);
        context.Request.Method = HttpMethods.Head;

        await FailClosedFeature().ApplyAsync(context, CancellationToken.None);

        Assert.Equal(200, (int)response.StatusCode);
    }

    [Fact]
    public async Task FailClosedRefusal_LogsOneWarning_SayingRefused_NotForwarded()
    {
        // Low-3: today the refusal's only log line claims the body "was forwarded
        // untouched" — the opposite of what happened. A refusal logs ONE warning that
        // says it refused and names the response class and the route.
        var logs = new Capturing();
        var response = Body(null, $"echo:{Secret}");
        var context = Context(response);
        context.Features.Get<CredProxRequestState>()!.Destination =
            new DestinationEntry("api-route", new DestinationDefinition(), null);

        await new ResponseScrubFeature(
                new CredProxScrubbingOptions { Enabled = true, FailClosed = true }, logs)
            .ApplyAsync(context, CancellationToken.None);

        AssertRefusal(response, 502, "no-media-type");
        var warning = Assert.Single(logs.Entries, e => e.Level == LogLevel.Warning);
        Assert.Contains("refused", warning.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("api-route", warning.Message, StringComparison.Ordinal);
        Assert.Contains("media type", warning.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("forwarded untouched", warning.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, warning.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task FailClosed_BodylessForward_StillLogsForwardedUntouched()
    {
        // The "forwarded untouched" wording stays true where the response really is
        // forwarded: a HEAD response under FailClosed forwards and says so.
        var logs = new Capturing();
        var response = Body(null, $"echo:{Secret}");
        var context = Context(response);
        context.Request.Method = HttpMethods.Head;

        await new ResponseScrubFeature(
                new CredProxScrubbingOptions { Enabled = true, FailClosed = true }, logs)
            .ApplyAsync(context, CancellationToken.None);

        Assert.Equal(200, (int)response.StatusCode);
        var warning = Assert.Single(logs.Entries, e => e.Level == LogLevel.Warning);
        Assert.Contains("forwarded untouched", warning.Message, StringComparison.Ordinal);
    }

    // ---- M47 rounds 2-3 (2026-11-20):
    // the scrubber's OWN readable-charset rule. The byte matcher reads only the EXACT
    // published single-byte names on IsCharsetReadable — utf-8/ascii, iso-8859-1..11 and
    // 13..16, windows-1250..1258 — so those bodies are scrubbed and never refused, with
    // the option on or off. Prefix extensions (iso-8859-99) and alias spellings (latin1,
    // cp1252) are deliberately NOT on the list. A body in ANY other declared charset
    // (utf-16/32 family, quoted or not, and every unknown name) forwards with a warning
    // when the option is off and is refused when it is on. RFC 9110 allows the quoted
    // charset form and MediaTypeHeaderValue hands the quotes through (measured), so the
    // name is matched after stripping one pair of surrounding double quotes. ----

    private static HttpResponseMessage ReadableBody(string charset, string body)
    {
        // Real single-byte-family bytes: the 0xE9 filler is 'é' in iso-8859-1, iso-8859-15
        // and windows-1252 alike, and the ASCII echo is byte-identical in all of them.
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(Encoding.Latin1.GetBytes(body)),
        };
        response.Content.Headers.ContentType = MediaTypeHeaderValue.Parse($"application/json; charset={charset}");
        return response;
    }

    [Theory]
    [InlineData("iso-8859-1")]
    [InlineData("ISO-8859-1")]
    [InlineData("iso-8859-15")]
    [InlineData("windows-1252")]
    public async Task ReadableCharset_FailClosed_IsScrubbed_NotRefused(string charset)
    {
        // The matcher reads these bytes: today the gate reuses the error-normalisation
        // predicate and refuses them anyway — the availability regression for the very
        // operator who opted in.
        var response = ReadableBody(charset, $"note=café echo:{Secret}");

        await FailClosedFeature().ApplyAsync(Context(response), CancellationToken.None);

        var text = Encoding.Latin1.GetString(await response.Content.ReadAsByteArrayAsync());
        Assert.Contains("echo:[redacted]", text, StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, text, StringComparison.Ordinal);
        Assert.Contains("café", text, StringComparison.Ordinal); // filler survives byte-identical
        Assert.Equal(200, (int)response.StatusCode);
    }

    [Fact]
    public async Task QuotedUtf8Charset_FailClosed_IsScrubbed_NotRefused()
    {
        // charset="utf-8" with the quotes is an ordinary vendor header (RFC 9110);
        // .NET keeps the quote characters in CharSet, so the match must strip them.
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(Encoding.UTF8.GetBytes($"echo:{Secret}")),
        };
        response.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(@"application/json; charset=""utf-8""");

        await FailClosedFeature().ApplyAsync(Context(response), CancellationToken.None);

        Assert.Equal(200, (int)response.StatusCode);
        Assert.Equal("echo:[redacted]", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task QuotedIso88591Charset_FailClosed_IsScrubbed_NotRefused()
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(Encoding.Latin1.GetBytes("note=café " + $"echo:{Secret}")),
        };
        response.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(@"application/json; charset=""ISO-8859-1""");

        await FailClosedFeature().ApplyAsync(Context(response), CancellationToken.None);

        Assert.Equal(200, (int)response.StatusCode);
        var text = Encoding.Latin1.GetString(await response.Content.ReadAsByteArrayAsync());
        Assert.Contains("echo:[redacted]", text, StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UnreadableCharset_FailClosedOff_ForwardsAndWarns_LikeEveryPassThroughClass()
    {
        // The class is operator-visible in BOTH modes: off forwards and logs the
        // pass-through warning once per route; on refuses and logs the refusal line.
        // Today the whole branch sits behind the FailClosed conjunct: off mode is silent.
        var logs = new Capturing();
        var payload = $"echo:{Secret}";
        var response = Utf16Body(payload);
        var context = Context(response);
        context.Features.Get<CredProxRequestState>()!.Destination =
            new DestinationEntry("api-route", new DestinationDefinition(), null);

        await new ResponseScrubFeature(new CredProxScrubbingOptions { Enabled = true }, logs)
            .ApplyAsync(context, CancellationToken.None);

        Assert.Equal(200, (int)response.StatusCode);
        Assert.Equal(Encoding.Unicode.GetBytes(payload), await response.Content.ReadAsByteArrayAsync());
        var warning = Assert.Single(logs.Entries, e => e.Level == LogLevel.Warning);
        Assert.Contains("searched as-is", warning.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, warning.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ProbeBodylessUnreadableCharset_FailClosedOn_WarnsNoBodyPresent_NotSearchedAsIs()
    {
        // The option-on probe answers "zero bytes" (unknown length, empty stream — the
        // line-156 ContentLength==0 return cannot reach this branch), so the response is
        // forwarded, never refused — and the warning says no body was present instead of
        // claiming a search of bytes that are not there. The early return skips the
        // matcher, so no body-scrubbed line is logged at any level. GET, not HEAD: the
        // probe path is exercised here, the protocol path has its own cell.
        var logs = new Capturing();
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(new byte[0]),
        };
        response.Content.Headers.ContentLength = null;
        response.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/json; charset=utf-16");
        var context = Context(response);
        context.Features.Get<CredProxRequestState>()!.Destination =
            new DestinationEntry("api-route", new DestinationDefinition(), null);

        await new ResponseScrubFeature(
                new CredProxScrubbingOptions { Enabled = true, FailClosed = true }, logs)
            .ApplyAsync(context, CancellationToken.None);

        Assert.Equal(200, (int)response.StatusCode);
        Assert.Empty(await response.Content.ReadAsByteArrayAsync());
        var warning = Assert.Single(logs.Entries, e => e.Level == LogLevel.Warning);
        Assert.Contains("no response body was present to search", warning.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("searched as-is", warning.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, warning.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(logs.Entries, e => e.Message.Contains("passed the credential scrubber", StringComparison.Ordinal));
    }

    [Fact]
    public async Task HeadDeclaredLengthUnreadableCharset_FailClosedOn_KeepsLengthAndScrubsHeaders()
    {
        // What a real HEAD looks like: the response declares a non-zero Content-Length
        // while carrying no bytes (a HEAD echoes the GET's length). HEAD is bodiless by
        // IsBodylessAsync's own rule, so the option-on branch never refuses it, names
        // the absence, and returns after header scrubbing: the declared length stays
        // 15 (the matcher's framing rewrite is skipped) and a credential echoed in a
        // response header is still redacted. The early return also means no body-scrub
        // line can appear beside the no-body message.
        var logs = new Capturing();
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(new byte[0]),
        };
        response.Content.Headers.ContentLength = 15;
        response.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/json; charset=utf-16");
        response.Headers.TryAddWithoutValidation("X-Vendor-Note", $"echo:{Secret}");
        var context = Context(response);
        context.Request.Method = HttpMethods.Head;
        context.Features.Get<CredProxRequestState>()!.Destination =
            new DestinationEntry("api-route", new DestinationDefinition(), null);

        await new ResponseScrubFeature(
                new CredProxScrubbingOptions { Enabled = true, FailClosed = true }, logs)
            .ApplyAsync(context, CancellationToken.None);

        Assert.Equal(200, (int)response.StatusCode);
        Assert.Equal(15, response.Content.Headers.ContentLength);
        var note = string.Join(",", response.Headers.GetValues("X-Vendor-Note"));
        Assert.Contains("echo:[redacted]", note, StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, note, StringComparison.Ordinal);
        var warning = Assert.Single(
            logs.Entries, e => e.Level == LogLevel.Warning && e.Message.Contains("charset", StringComparison.Ordinal));
        Assert.Contains("no response body was present to search", warning.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("searched as-is", warning.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(logs.Entries, e => e.Message.Contains("passed the credential scrubber", StringComparison.Ordinal));
    }

    [Fact]
    public async Task BodilessThenBodySameRoute_UnreadableCharset_BothShapesWarn()
    {
        // The bodiless message has its OWN dedupe shape: on one route and one feature
        // instance, a HEAD (no-body message) followed by a GET with real bytes
        // (searched-as-is message) must BOTH be logged — with one shared shape key the
        // second warning is swallowed (witnessed at 7f6e743: expected 2, actual 1).
        var logs = new Capturing();
        var feature = new ResponseScrubFeature(new CredProxScrubbingOptions { Enabled = true }, logs);

        var head = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(new byte[0]),
        };
        head.Content.Headers.ContentLength = 15;
        head.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/json; charset=utf-16");
        var headContext = Context(head);
        headContext.Request.Method = HttpMethods.Head;
        headContext.Features.Get<CredProxRequestState>()!.Destination =
            new DestinationEntry("api-route", new DestinationDefinition(), null);
        await feature.ApplyAsync(headContext, CancellationToken.None);

        var body = Utf16Body($"echo:{Secret}");
        var bodyContext = Context(body);
        bodyContext.Features.Get<CredProxRequestState>()!.Destination =
            new DestinationEntry("api-route", new DestinationDefinition(), null);
        await feature.ApplyAsync(bodyContext, CancellationToken.None);

        var warnings = logs.Entries.Where(e => e.Level == LogLevel.Warning).ToList();
        Assert.Equal(2, warnings.Count);
        Assert.Contains(warnings, w => w.Message.Contains("no response body was present to search", StringComparison.Ordinal));
        Assert.Contains(warnings, w => w.Message.Contains("searched as-is", StringComparison.Ordinal));
    }

    [Fact]
    public async Task UnreadableCharset_ScrubbingDisabled_IsSilentAndByteIdentical()
    {
        // The both-modes visibility rule lives where the feature inspects. With
        // Scrubbing off nothing is inspected: byte-identical and no warning.
        var logs = new Capturing();
        var payload = $"echo:{Secret}";
        var response = Utf16Body(payload);

        await new ResponseScrubFeature(
                new CredProxScrubbingOptions { Enabled = false, FailClosed = false }, logs)
            .ApplyAsync(Context(response), CancellationToken.None);

        Assert.Equal(200, (int)response.StatusCode);
        Assert.Equal(Encoding.Unicode.GetBytes(payload), await response.Content.ReadAsByteArrayAsync());
        Assert.DoesNotContain(logs.Entries, e => e.Level == LogLevel.Warning);
    }

    [Theory]
    [InlineData("utf-16le", "")]
    [InlineData("utf-32", "")]
    [InlineData("iso-2022-jp", "ascii-looking")] // stateful: stays out of the allowlist
    [InlineData("zzz-not-a-charset", "ascii-looking")]
    [InlineData("iso-8859-99", "ascii-looking")] // inside the old family prefix, but no such name was ever published
    [InlineData("iso-8859-", "ascii-looking")] // the bare prefix is not a charset name
    [InlineData("iso-8859-12", "ascii-looking")] // reserved and then withdrawn, never published: refusing it is the permanent record, not a gap
    [InlineData("windows-12599", "ascii-looking")] // windows-1250..1258 is the complete published set; this pins the top edge
    [InlineData("latin1", "ascii-looking")] // alias spellings are deliberately not on the readable list — canonical names only
    [InlineData("cp1252", "ascii-looking")]
    public async Task UnreadableCharset_FailClosed_Refused_NamingTheClass(string charset, string _)
    {
        // Unknown and stateful names refuse through the name branch — nothing here ever
        // resolves an Encoding, so a bogus name refuses rather than throws.
        var payload = $"echo:{Secret}";
        var bytes = charset switch
        {
            "utf-16le" => Encoding.Unicode.GetBytes(payload),
            "utf-32" => Encoding.UTF32.GetBytes(payload),
            _ => Encoding.ASCII.GetBytes(payload),
        };
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) };
        response.Content.Headers.ContentType = MediaTypeHeaderValue.Parse($"application/json; charset={charset}");

        await FailClosedFeature().ApplyAsync(Context(response), CancellationToken.None);

        AssertRefusal(response, 502, "non-utf8-charset");
    }

    [Fact]
    public async Task AliasCharset_FailClosedOff_IsSearchedAsIs_EchoRemovedAndWarned()
    {
        // A guard, not a witness — green before and after the exact-list change: it
        // pins the shipped alias sentence's default-mode half in the repo. An alias
        // body is NOT skipped — the gate warns once per route and shape and the byte
        // matcher still reads the single-byte ASCII bytes, so an ASCII echo is
        // removed. An edit that returns after the warning without scrubbing reddens
        // exactly this cell (the utf-16 cells above cannot catch it: their bytes are
        // identical scrubbed or not).
        var logs = new Capturing();
        var response = ReadableBody("latin1", $"echo:{Secret}");
        var context = Context(response);
        context.Features.Get<CredProxRequestState>()!.Destination =
            new DestinationEntry("api-route", new DestinationDefinition(), null);

        await new ResponseScrubFeature(new CredProxScrubbingOptions { Enabled = true }, logs)
            .ApplyAsync(context, CancellationToken.None);

        Assert.Equal(200, (int)response.StatusCode);
        var text = Encoding.Latin1.GetString(await response.Content.ReadAsByteArrayAsync());
        Assert.Equal("echo:[redacted]", text);
        var warning = Assert.Single(logs.Entries, e => e.Level == LogLevel.Warning);
        Assert.DoesNotContain(Secret, warning.Message, StringComparison.Ordinal);
        // The corrected success-path debug line is load-bearing here: this cell scrubs
        // for real, so the replacement path must log that the body passed the scrubber.
        Assert.Contains(logs.Entries, e => e.Level == LogLevel.Debug && e.Message.Contains("passed the credential scrubber", StringComparison.Ordinal));
    }

    [Fact]
    public async Task QuotedPaddedUtf8Charset_FailClosed_IsScrubbed_NotRefused()
    {
        // charset=" utf-8 ": the parser keeps the quotes AND the inner padding
        // (measured), so the predicate's post-strip Trim is wire-reachable, and this
        // arm is what dies alone (200 to 502) if that Trim is ever dropped.
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(Encoding.UTF8.GetBytes($"echo:{Secret}")),
        };
        response.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(@"application/json; charset="" utf-8 """);

        await FailClosedFeature().ApplyAsync(Context(response), CancellationToken.None);

        Assert.Equal(200, (int)response.StatusCode);
        // Read raw bytes and decode by hand: ReadAsStringAsync resolves the raw
        // ' utf-8 ' charset through BCL and throws on an invalid encoding name.
        Assert.Equal("echo:[redacted]", Encoding.UTF8.GetString(await response.Content.ReadAsByteArrayAsync()));
    }

    [Fact]
    public async Task ReadableCharset_FailClosedOff_IsStillScrubbed()
    {
        // Off mode is unchanged for readable charsets: the echo is scrubbed, it does not
        // reach the caller.
        var response = ReadableBody("iso-8859-1", $"echo:{Secret}");

        await new ResponseScrubFeature(
                new CredProxScrubbingOptions { Enabled = true },
                NullLogger<ResponseScrubFeature>.Instance)
            .ApplyAsync(Context(response), CancellationToken.None);

        var text = Encoding.Latin1.GetString(await response.Content.ReadAsByteArrayAsync());
        Assert.Equal("echo:[redacted]", text);
    }

    private sealed class Capturing : ILogger<ResponseScrubFeature>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception)));
    }
}
