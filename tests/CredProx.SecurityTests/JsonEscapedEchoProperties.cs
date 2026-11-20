using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using CredProx;
using FsCheck;
using FsCheck.Xunit;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace CredProx.SecurityTests;

/// <summary>
/// Property form of the escaped-echo rule: whatever the credential value is, and whatever
/// subset of its characters the vendor's JSON encoder renders as backslash-u escapes (in
/// lower- or upper-case hex), none of the raw, URL-encoded or escaped renderings may reach
/// the caller — and the scrubbed body must still be parseable JSON.
/// </summary>
public sealed class JsonEscapedEchoProperties
{
    private static string ScrubbedBody(string body, string secret)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body) };
        response.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/json");

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
        return response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
    }

    private static string RenderJsonEscaped(string value, int salt)
    {
        var sb = new StringBuilder();
        for (var i = 0; i < value.Length; i++)
        {
            var c = value[i];
            if (((salt >> (i % 30)) & 1) == 1)
            {
                sb.Append("\\u").Append(((int)c).ToString(((salt >> 15) & 1) == 1 ? "X4" : "x4"));
            }
            else
            {
                sb.Append(c);
            }
        }
        return sb.ToString();
    }

    [Property(MaxTest = 200)]
    public void RawUrlEncodedAndEscapedRenderings_NeverSurvive(NonNull<string> generated, int salt)
    {
        var sanitized = new string(
            generated.Get.Where(c => !char.IsControl(c) && c != '"' && c != '\\').ToArray());
        var secret = "s3cr3t-" + sanitized + "+/=";
        foreach (var body in new[]
                 {
                     $$"""{"k":"{{secret}}"}""",
                     $$"""{"k":"{{Uri.EscapeDataString(secret)}}"}""",
                     $$"""{"k":"{{RenderJsonEscaped(secret, salt)}}"}""",
                 })
        {
            var scrubbed = ScrubbedBody(body, secret);
            Assert.DoesNotContain(secret, scrubbed, StringComparison.Ordinal);
            Assert.Contains("[redacted]", scrubbed, StringComparison.Ordinal);
            using var _ = JsonDocument.Parse(scrubbed);
        }
    }
}
