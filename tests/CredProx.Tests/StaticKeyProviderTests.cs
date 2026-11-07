using CredProx;
using CredProx.Abstractions;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// §5.2 "Static key" row: the key resolves from a <c>secret:</c> reference or a literal,
/// and placement overwrites an existing header or query parameter instead of duplicating it.
/// </summary>
public sealed class StaticKeyProviderTests
{
    private static CredentialRequestContext Context() =>
        new() { CredentialName = "api-key", Partition = null };

    [Fact]
    public async Task SecretReference_ResolvesThroughScopedAccessor()
    {
        var provider = new StaticKeyProvider();
        var secrets = TestSecrets.AccessorFor(
            new() { ["Secret"] = "secret:api-key" },
            new() { ["api-key"] = "key-value-1" });

        var value = await provider.GetCredentialAsync(
            new StaticKeyOptions { Secret = "secret:api-key", Name = "X-Api-Key" }, secrets, Context(), default);

        Assert.Equal("key-value-1", value);
    }

    [Fact]
    public async Task Literal_IsUsedAsIs()
    {
        var provider = new StaticKeyProvider();

        var value = await provider.GetCredentialAsync(
            new StaticKeyOptions { Secret = "plain-key", Name = "X-Api-Key" },
            TestSecrets.AccessorFor(new()), Context(), default);

        Assert.Equal("plain-key", value);
    }

    [Fact]
    public async Task MissingSecret_FailsNamingTheCredential()
    {
        var provider = new StaticKeyProvider();

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetCredentialAsync(
                new StaticKeyOptions { Name = "X-Api-Key" },
                TestSecrets.AccessorFor(new()), Context(), default).AsTask());

        Assert.Contains("api-key", error.Message);
    }

    [Fact]
    public async Task UnresolvableSecret_FailsWithoutLeaking()
    {
        var provider = new StaticKeyProvider();
        var secrets = TestSecrets.AccessorFor(new() { ["Secret"] = "secret:api-key" }); // value absent

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetCredentialAsync(
                new StaticKeyOptions { Secret = "secret:api-key", Name = "X-Api-Key" },
                secrets, Context(), default).AsTask());

        Assert.Contains("api-key", error.Message);
    }
}

/// <summary>
/// Placement semantics shared by every credential type (§5.2: overwritten, not duplicated;
/// §3.4: Authorization is replaced, not merged).
/// </summary>
public sealed class CredentialAttacherTests
{
    [Fact]
    public void Header_ReplacesExistingValue()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "https://vendor.example/api");
        request.Headers.Add("Authorization", "caller-supplied");

        CredentialAttacher.Apply(request, CredentialLocation.Header, "Authorization", "new-token", "Bearer ");

        Assert.Equal(["Bearer new-token"], request.Headers.GetValues("Authorization"));
    }

    [Fact]
    public void Header_WithoutPrefix_WritesRawValue()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "https://vendor.example/api");

        CredentialAttacher.Apply(request, CredentialLocation.Header, "X-Api-Key", "key-1");

        Assert.Equal("key-1", Assert.Single(request.Headers.GetValues("X-Api-Key")));
    }

    [Fact]
    public void Query_ReplacesExistingParameterAndKeepsOthers()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "https://vendor.example/api?api_key=old&keep=yes");

        CredentialAttacher.Apply(request, CredentialLocation.Query, "api_key", "new key&value");

        var query = System.Web.HttpUtility.ParseQueryString(request.RequestUri!.Query);
        Assert.Equal("new key&value", query["api_key"]); // replaced, not duplicated
        Assert.Equal("yes", query["keep"]);
        Assert.Single(
            request.RequestUri.Query.Split('?')[1].Split('&'),
            part => part.StartsWith("api_key=", StringComparison.Ordinal));
    }

    [Fact]
    public void Query_AddsParameterWhenAbsent()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "https://vendor.example/api");

        CredentialAttacher.Apply(request, CredentialLocation.Query, "api_key", "k1");

        Assert.Equal("https://vendor.example/api?api_key=k1", request.RequestUri!.ToString());
    }

    [Fact]
    public void Query_WithoutUri_Fails()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, (string?)null);

        Assert.Throws<InvalidOperationException>(() =>
            CredentialAttacher.Apply(request, CredentialLocation.Query, "api_key", "k1"));
    }

    [Fact]
    public void Cookie_ReplacesEntireCallerCookieHeader()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "https://vendor.example/api");
        request.Headers.Add("Cookie", "theme=dark; CRMSESSION=caller-forged");

        CredentialAttacher.Apply(request, CredentialLocation.Cookie, "CRMSESSION", "session-1");

        // Never merged: the caller's own cookies must not ride along to the vendor.
        Assert.Equal("CRMSESSION=session-1", Assert.Single(request.Headers.GetValues("Cookie")));
    }

    [Fact]
    public void Cookie_AddsHeaderWhenAbsent()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "https://vendor.example/api");

        CredentialAttacher.Apply(request, CredentialLocation.Cookie, "CRMSESSION", "session-1");

        Assert.Equal("CRMSESSION=session-1", Assert.Single(request.Headers.GetValues("Cookie")));
    }

    [Theory]
    [InlineData("value;evil=1")] // cookie smuggling: a second pair in one header
    [InlineData("value\r\nX-Injected: 1")] // request splitting
    [InlineData("value\nX-Injected: 1")]
    [InlineData("value\0evil")]
    [InlineData("value\u007fevil")] // DEL: headers are ASCII-clean framing (N2)
    [InlineData("valué")] // Latin-1 supplement: cannot round-trip Latin-1 header bytes (N2)
    [InlineData("valueḀ")] // beyond Latin-1 (N2)
    [InlineData("value😀")] // astral pair: mangled by header framing (N2)
    public void Cookie_RejectsUnsafeValue(string value)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "https://vendor.example/api");

        Assert.Throws<ArgumentException>(() =>
            CredentialAttacher.Apply(request, CredentialLocation.Cookie, "CRMSESSION", value));
    }

    [Theory]
    [InlineData("bad name")]
    [InlineData("bad;name")]
    [InlineData("bad,name")]
    [InlineData("")]
    public void Cookie_RejectsInvalidName(string name)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "https://vendor.example/api");

        Assert.Throws<ArgumentException>(() =>
            CredentialAttacher.Apply(request, CredentialLocation.Cookie, name, "session-1"));
    }

    [Fact]
    public void Cookie_AcceptsTypicalVendorCookieNames()
    {
        Assert.True(CredentialAttacher.IsValidCookieName("CRMSESSION"));
        Assert.True(CredentialAttacher.IsValidCookieName("JSESSIONID"));
        Assert.True(CredentialAttacher.IsValidCookieName("auth-token_v2"));
    }
}
