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
        // The two failure messages are different diagnoses ('nothing configured' vs
        // 'reference does not resolve'); pin which one this input must produce.
        Assert.Contains("no Secret configured", error.Message, StringComparison.Ordinal);
    }

    // M31 mutation triage: argument guards whose removal stays silent on the
    // literal-secret path, so the assertion is the exception itself.
    [Fact]
    public async Task NullOptions_Throws_NamingOptions()
    {
        var provider = new StaticKeyProvider();

        var ex = await Assert.ThrowsAsync<ArgumentNullException>(() =>
            provider.GetCredentialAsync(
                null!, TestSecrets.AccessorFor(new()), Context(), default).AsTask());

        Assert.Equal("options", ex.ParamName);
    }

    [Fact]
    public async Task NullSecrets_Throws_NamingSecrets()
    {
        var provider = new StaticKeyProvider();

        var ex = await Assert.ThrowsAsync<ArgumentNullException>(() =>
            provider.GetCredentialAsync(
                new StaticKeyOptions { Secret = "plain-key", Name = "X-Api-Key" },
                null!, Context(), default).AsTask());

        Assert.Equal("secrets", ex.ParamName);
    }

    [Fact]
    public async Task NullContext_Throws_NamingContext()
    {
        var provider = new StaticKeyProvider();

        var ex = await Assert.ThrowsAsync<ArgumentNullException>(() =>
            provider.GetCredentialAsync(
                new StaticKeyOptions { Secret = "plain-key", Name = "X-Api-Key" },
                TestSecrets.AccessorFor(new()), null!, default).AsTask());

        Assert.Equal("context", ex.ParamName);
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

    // M31 fuzz triage: an empty credential value used to 'succeed' while attaching
    // nothing (the BCL header store refuses to hold an empty value for known names,
    // and nothing reaches the wire). Every placement must refuse it by name instead.
    [Theory]
    [InlineData(CredentialLocation.Header)]
    [InlineData(CredentialLocation.Cookie)]
    [InlineData(CredentialLocation.Query)]
    public void EmptyValue_IsRefused_NamingValue(CredentialLocation location)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "https://vendor.example/api");

        var ex = Assert.Throws<ArgumentException>(
            () => CredentialAttacher.Apply(request, location, "X-Api-Key", string.Empty));

        Assert.Equal("value", ex.ParamName);
    }

    // Well-formed but restricted header names are refused as documented ArgumentExceptions,
    // never as a raw BCL 'Misused header name' InvalidOperationException at request time.
    [Fact]
    public void RestrictedHeaderName_IsRefused_NamingName()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "https://vendor.example/api");

        var ex = Assert.Throws<ArgumentException>(
            () => CredentialAttacher.Apply(request, CredentialLocation.Header, "Content-Length", "k"));

        Assert.Equal("name", ex.ParamName);
        Assert.Contains("cannot be used as a credential header name", ex.Message, StringComparison.Ordinal);
    }

    // M31 fuzz P-5: well-formed, unrestricted names that the BCL header store PARSES
    // ('te', ...) used to accept a credential whose stored — and therefore wire — form
    // differed from what was configured ('te' + "\ta " came back as "a"). Placement
    // read-backs and refuses: the credential reaches the vendor byte-identical or not at all.
    [Theory]
    [InlineData("te", "\ta ")]  // parses, but re-serializes as "a" — the read-back refuse
    [InlineData("te", "a b")]   // outside the parsed grammar — the raw FormatException translated
    public void BclParsedHeaderName_WouldNotPreserveValue_IsRefused_NamingName(string name, string value)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "https://vendor.example/api");

        var ex = Assert.Throws<ArgumentException>(
            () => CredentialAttacher.Apply(request, CredentialLocation.Header, name, value));

        Assert.Equal("name", ex.ParamName);
        Assert.False(request.Headers.Contains(name)); // a refused placement leaves nothing behind
    }

    // The probe must not over-refuse: names whose parsed form IS the value (and unknown
    // names, stored verbatim) still attach exactly once verbatim.
    [Theory]
    [InlineData("te", "trail")]
    [InlineData("X-Api-Key", "key-1")]
    public void HeaderName_KeptVerbatim_StillAttaches(string name, string value)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "https://vendor.example/api");

        CredentialAttacher.Apply(request, CredentialLocation.Header, name, value);

        Assert.Equal(value, Assert.Single(request.Headers.GetValues(name)));
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
    public void Query_WithoutUri_Fails_NamingTheMissingUri()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, (string?)null);

        var ex = Assert.Throws<InvalidOperationException>(() =>
            CredentialAttacher.Apply(request, CredentialLocation.Query, "api_key", "k1"));

        Assert.Contains("no URI to attach a query credential", ex.Message, StringComparison.Ordinal);
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

    // --- M31 mutation triage: guards and boundaries that survived because no
    // assertion pinned exception type, paramName, message, or the exact boundary
    // character. ---

    [Fact]
    public void NullRequest_Throws_NamingRequest()
    {
        var ex = Assert.Throws<ArgumentNullException>(() =>
            CredentialAttacher.Apply(null!, CredentialLocation.Header, "X-Api-Key", "v"));

        Assert.Equal("request", ex.ParamName);
    }

    // The BCL header store would throw its own ArgumentNullException('name') for a
    // header placement, so the null-name guard is proven via cookie placement,
    // where its absence would surface as the cookie-name ArgumentException instead.
    [Fact]
    public void Cookie_NullName_Throws_NamingName()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "https://vendor.example/api");

        var ex = Assert.Throws<ArgumentNullException>(() =>
            CredentialAttacher.Apply(request, CredentialLocation.Cookie, null!, "v"));

        Assert.Equal("name", ex.ParamName);
    }

    [Fact]
    public void Cookie_NullValue_Throws_NamingValue()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "https://vendor.example/api");

        var ex = Assert.Throws<ArgumentNullException>(() =>
            CredentialAttacher.Apply(request, CredentialLocation.Cookie, "CRMSESSION", null!));

        Assert.Equal("value", ex.ParamName);
    }

    [Fact]
    public void Cookie_InvalidName_MessageNamesRfc6265()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "https://vendor.example/api");

        var ex = Assert.Throws<ArgumentException>(() =>
            CredentialAttacher.Apply(request, CredentialLocation.Cookie, "bad name", "v"));

        Assert.Contains("not a valid RFC 6265 cookie name", ex.Message, StringComparison.Ordinal);
    }

    // Cookie placement must not touch the request URI (falls through to the query
    // rebuild if the branch's return disappears).
    [Fact]
    public void Cookie_Placement_LeavesRequestUriUntouched()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "https://vendor.example/api?keep=yes");

        CredentialAttacher.Apply(request, CredentialLocation.Cookie, "CRMSESSION", "session-1");

        Assert.Equal("https://vendor.example/api?keep=yes", request.RequestUri!.ToString());
    }

    // Boundary characters: '(' is tspecial #1 (IndexOf == 0 defeats an off-by-one
    // scan), DEL (0x7f) is refused by the ASCII rule's boundary.
    [Theory]
    [InlineData("(x")]
    [InlineData("a\u007fb")]
    public void IsValidCookieName_RejectsBoundaryCharacters(string name) =>
        Assert.False(CredentialAttacher.IsValidCookieName(name));

    [Fact]
    public void IsValidCookieName_EmptyOrNull_False()
    {
        Assert.False(CredentialAttacher.IsValidCookieName(string.Empty));
        Assert.False(CredentialAttacher.IsValidCookieName(null!));
    }

    // The refusal message is the operator's fix-it text: all three consequences
    // must survive edits.
    [Fact]
    public void Cookie_UnsafeValueMessage_NamesAllThreeConsequences()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "https://vendor.example/api");

        var ex = Assert.Throws<ArgumentException>(() =>
            CredentialAttacher.Apply(request, CredentialLocation.Cookie, "CRMSESSION", "value;evil=1"));

        Assert.Contains("must be ASCII", ex.Message, StringComparison.Ordinal);
        Assert.Contains("split the request", ex.Message, StringComparison.Ordinal);
        Assert.Contains("Latin-1 framing", ex.Message, StringComparison.Ordinal);
    }
}
