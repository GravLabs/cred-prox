using System.Reflection;
using CredProx;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The one shape the raw-value arm exists for: a registered secret that contains '+',
/// echoed in the query in its raw form. The decoded arm replaces '+' with ' ' before
/// matching, so ONLY the raw arm can see this. Base64 secrets (client secrets,
/// assertions, login passwords) routinely contain '+'. This is a permanent pin:
/// deleting the raw arm must cost a test, not ride through CI green (M47, F-9).
/// </summary>
public sealed class ReviewProbePlusTests
{
    private const string Secret = "a+b/c==BASE64SHAPE";

    private static readonly MethodInfo Sanitize =
        typeof(CredentialAttachFeature).GetMethod("SanitizeAuthorizeUrl", BindingFlags.NonPublic | BindingFlags.Static)!;

    [Theory]
    [InlineData("https://id.example/authorize?state=" + Secret)]        // raw, '+' untouched
    [InlineData("https://id.example/authorize?state=x" + Secret)]      // embedded in a longer value
    public void PlusBearingSecret_EchoedRaw_IsDropped(string url)
    {
        var context = new DefaultHttpContext();
        CredProxInjectedSecrets.GetOrCreate(context).Register(Secret);
        var args = new object?[] { context, new object(), url, null };
        var relayed = (string?)Sanitize.Invoke(null, args);
        Assert.Null(relayed); // dies under a mutant that drops the raw arm
    }
}
