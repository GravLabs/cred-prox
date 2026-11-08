using System.Text;
using CredProx;
using CredProx.Abstractions;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage for <see cref="HmacProvider"/>: identity, argument guards,
/// and both unresolved-key diagnoses asserted by message.
/// </summary>
public sealed class HmacProviderM31Tests
{
    private static CredentialRequestContext Context() =>
        new() { CredentialName = "test", Partition = null };

    [Fact]
    public void Type_IsHmac()
    {
        Assert.Equal("Hmac", new HmacProvider().Type);
    }

    [Fact]
    public async Task NullOptions_Throws_NamingOptions()
    {
        var ex = await Assert.ThrowsAsync<ArgumentNullException>(() =>
            new HmacProvider().GetCredentialAsync(null!, TestSecrets.AccessorFor(new()), Context(), default).AsTask());

        Assert.Equal("options", ex.ParamName);
    }

    [Fact]
    public async Task NullSecrets_Throws_NamingSecrets()
    {
        var ex = await Assert.ThrowsAsync<ArgumentNullException>(() =>
            new HmacProvider().GetCredentialAsync(new HmacOptions { Secret = "k" }, null!, Context(), default).AsTask());

        Assert.Equal("secrets", ex.ParamName);
    }

    [Fact]
    public async Task NullContext_Throws_NamingContext()
    {
        var ex = await Assert.ThrowsAsync<ArgumentNullException>(() =>
            new HmacProvider().GetCredentialAsync(new HmacOptions { Secret = "k" }, TestSecrets.AccessorFor(new()), null!, default).AsTask());

        Assert.Equal("context", ex.ParamName);
    }

    [Fact]
    public async Task MissingSecret_FailsNamingTheCredential()
    {
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new HmacProvider().GetCredentialAsync(new HmacOptions(), TestSecrets.AccessorFor(new()), Context(), default).AsTask());

        Assert.Contains("credential 'test' has no Secret configured", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SecretReference_ToEmptyValue_FailsAsDoesNotResolve()
    {
        // Distinct from 'no Secret configured': a reference that resolves to nothing
        // must say so, so the operator checks the secret store, not the config.
        var secrets = TestSecrets.AccessorFor(
            new() { ["Secret"] = "secret:hkey" },
            new() { ["hkey"] = string.Empty });

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new HmacProvider().GetCredentialAsync(
                new HmacOptions { Secret = "secret:hkey" }, secrets, Context(), default).AsTask());

        Assert.Contains("credential 'test' does not resolve", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("no Secret configured", ex.Message, StringComparison.Ordinal);
    }
}

/// <summary>
/// M31 mutation triage for <see cref="HmacSigner"/>: the empty-string fallbacks of the
/// canonical builder (no-URI path/query, unknown kind, missing header), the multi-value
/// header join separator, the header: argument rules, and every unsupported-enum-value
/// diagnosis in the signer, hasher, timestamp and encoder.
/// </summary>
public sealed class HmacSignerM31Tests
{
    private static HmacOptions Options() => new() { Separator = "|" };

    private static string Canonical(HmacComponentKind kind, string argument = "", HttpRequestMessage? request = null, HmacOptions? options = null) =>
        HmacSigner.BuildCanonicalString([(kind, argument)], request ?? new HttpRequestMessage(HttpMethod.Get, "https://vendor.example/api"), [], options ?? Options(), DateTimeOffset.UnixEpoch);

    [Fact]
    public void TryParseComponent_KnownNames_HaveEmptyArguments()
    {
        Assert.True(HmacSigner.TryParseComponent("method", out var kind, out var argument));
        Assert.Equal(HmacComponentKind.Method, kind);
        Assert.Equal(string.Empty, argument); // the out-param contract every non-header component relies on
    }

    [Theory]
    [InlineData("header:X-Sig", "X-Sig")]
    [InlineData("header:  X-Sig  ", "X-Sig")]
    public void TryParseComponent_Header_NamesArgument(string token, string expected)
    {
        Assert.True(HmacSigner.TryParseComponent(token, out var kind, out var argument));
        Assert.Equal(HmacComponentKind.Header, kind);
        Assert.Equal(expected, argument);
    }

    [Theory]
    [InlineData("header:")]
    [InlineData("header:   ")]
    public void TryParseComponent_HeaderWithoutName_IsNotValid(string token)
    {
        // :43 boundary (argument.Length > 0): a header component that names no header
        // must be refused at parse time, not sign an empty header lookup.
        Assert.False(HmacSigner.TryParseComponent(token, out _, out _));
    }

    // Live-pipeline shape: RequestUri is null while features run; the part is the
    // empty string, never a placeholder.
    [Fact]
    public void NoRequestUri_PathFallsBackToEmpty() =>
        Assert.Equal(string.Empty,
            Canonical(HmacComponentKind.Path, request: new HttpRequestMessage(HttpMethod.Get, (string?)null)));

    [Fact]
    public void NoRequestUri_QueryFallsBackToEmpty() =>
        Assert.Equal(string.Empty,
            Canonical(HmacComponentKind.Query, request: new HttpRequestMessage(HttpMethod.Get, (string?)null)));

    [Fact]
    public void UnknownComponentKind_ContributesEmpty()
    {
        var canonical = Canonical((HmacComponentKind)99);

        Assert.Equal(string.Empty, canonical);
    }

    [Fact]
    public void Header_MultipleValues_JoinWithComma_RequestThenContent()
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "https://vendor.example/api")
        {
            Content = new StringContent("body"),
        };
        request.Headers.Add("X-List", "a");
        request.Headers.Add("X-List", "b");
        request.Content.Headers.Add("X-Content-List", "c");
        request.Content.Headers.Add("X-Content-List", "d");

        var canonical = HmacSigner.BuildCanonicalString(
            [(HmacComponentKind.Header, "X-List"), (HmacComponentKind.Header, "X-Content-List")],
            request, [], Options(), DateTimeOffset.UnixEpoch);

        // The vendor reads the merged header set in wire order: request headers first.
        Assert.Equal("a,b|c,d", canonical);
    }

    [Fact]
    public void Header_Missing_ContributesEmpty()
    {
        Assert.Equal(string.Empty, Canonical(HmacComponentKind.Header, "X-Nope"));
    }

    [Fact]
    public void Sign_UndefinedAlgorithm_FailsNamingIt()
    {
        var options = Options();
        options.Algorithm = (HmacAlgorithm)99;

        var ex = Assert.Throws<InvalidOperationException>(() => HmacSigner.Sign("canonical", "key", options));

        Assert.Contains("Unsupported HMAC algorithm '99'", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void BodyHash_UndefinedAlgorithm_FailsNamingIt()
    {
        var options = Options();
        options.Algorithm = (HmacAlgorithm)99;

        var ex = Assert.Throws<InvalidOperationException>(() =>
            HmacSigner.BuildCanonicalString([(HmacComponentKind.BodyHash, "")],
                new HttpRequestMessage(HttpMethod.Get, "https://vendor.example/api"), Encoding.UTF8.GetBytes("body"),
                options, DateTimeOffset.UnixEpoch));

        Assert.Contains("Unsupported HMAC algorithm '99'", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void FormatTimestamp_UndefinedFormat_FailsNamingIt()
    {
        var ex = Assert.Throws<InvalidOperationException>(() =>
            HmacSigner.FormatTimestamp(DateTimeOffset.UnixEpoch, (HmacTimestampFormat)99));

        Assert.Contains("Unsupported timestamp format '99'", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Sign_UndefinedSignatureEncoding_FailsNamingIt()
    {
        var options = Options();
        options.Encoding = (HmacSignatureEncoding)99;

        var ex = Assert.Throws<InvalidOperationException>(() => HmacSigner.Sign("canonical", "key", options));

        Assert.Contains("Unsupported signature encoding '99'", ex.Message, StringComparison.Ordinal);
    }
}
