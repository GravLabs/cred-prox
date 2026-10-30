using System.Text;
using CredProx;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The shared retry clone (§8.4): every retry attempt sends a clone because a sent
/// <see cref="HttpRequestMessage"/> cannot be resent. Headers, version and the message
/// <c>Options</c> must survive the copy — the credential and refresh features stash their
/// per-request state there — and the body must come from the pre-captured buffer.
/// </summary>
public sealed class ProxyRequestClonerTests
{
    [Fact]
    public void Clone_CopiesMethodUriVersionAndHeaders()
    {
        var request = new HttpRequestMessage(HttpMethod.Put, "https://vendor.example/api?x=1")
        {
            Version = new Version(2, 0),
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };
        request.Headers.Add("X-Trace", "abc");
        request.Headers.Add("Authorization", "Bearer token-1");

        var clone = ProxyRequestCloner.Clone(request, body: null);

        Assert.Equal(HttpMethod.Put, clone.Method);
        Assert.Equal(request.RequestUri, clone.RequestUri);
        Assert.Equal(new Version(2, 0), clone.Version);
        Assert.Equal(HttpVersionPolicy.RequestVersionExact, clone.VersionPolicy);
        Assert.Equal("abc", Assert.Single(clone.Headers.GetValues("X-Trace")));
        Assert.Equal("Bearer token-1", Assert.Single(clone.Headers.GetValues("Authorization")));
        Assert.Null(clone.Content);
    }

    [Fact]
    public async Task Clone_CarriesBufferedBodyWithContentHeaders()
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "https://vendor.example/api")
        {
            Content = new StringContent("payload", Encoding.UTF8, "application/json"),
        };
        var body = Encoding.UTF8.GetBytes("payload");

        var clone = ProxyRequestCloner.Clone(request, body);

        Assert.NotNull(clone.Content);
        Assert.Equal("application/json", clone.Content.Headers.ContentType?.MediaType);
        Assert.Equal("payload", await clone.Content.ReadAsStringAsync());
    }

    [Fact]
    public void Clone_RoundTripsTypedOptions()
    {
        var stringKey = new HttpRequestOptionsKey<string>("string-option");
        var intKey = new HttpRequestOptionsKey<int>("int-option");
        var request = new HttpRequestMessage(HttpMethod.Get, "https://vendor.example/api");
        request.Options.Set(stringKey, "value");
        request.Options.Set(intKey, 42);

        var clone = ProxyRequestCloner.Clone(request, body: null);

        Assert.True(clone.Options.TryGetValue(stringKey, out var stringValue));
        Assert.Equal("value", stringValue);
        Assert.True(clone.Options.TryGetValue(intKey, out var intValue));
        Assert.Equal(42, intValue);
    }

    [Fact]
    public void Clone_NullRequest_Throws() =>
        Assert.Throws<ArgumentNullException>(() => ProxyRequestCloner.Clone(null!, null));
}
