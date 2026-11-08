using CredProx;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// Startup validation for <see cref="LoginExchangeOptions"/> (§8.1 session-cookie login):
/// header placement stays as before, cookie placement must name its cookie coherently
/// (Name or ResponseField, a valid RFC 6265 name, no prefix), and query placement is
/// refused for this type.
/// </summary>
public sealed class LoginExchangeOptionsValidatorTests
{
    private static LoginExchangeOptions Valid() => new()
    {
        LoginEndpoint = "https://vendor.example/login",
        Form = new LoginExchangeCredentials { User = "u", Password = "p" },
        Response = LoginExchangeResponse.Cookie,
        ResponseField = "CRMSESSION",
    };

    [Fact]
    public void AcceptsClassicHeaderConfig()
    {
        var options = Valid();
        options.Response = LoginExchangeResponse.RawBody;
        options.ResponseField = null;

        Assert.True(new LoginExchangeOptionsValidator().Validate("c", options).Succeeded);
    }

    [Fact]
    public void AcceptsCookieConfig_NamedByResponseField()
    {
        var options = Valid();
        options.Location = CredentialLocation.Cookie;

        Assert.True(new LoginExchangeOptionsValidator().Validate("c", options).Succeeded);
    }

    [Fact]
    public void AcceptsCookieConfig_NamedByName_WithJsonPathExtraction()
    {
        var options = Valid();
        options.Location = CredentialLocation.Cookie;
        options.Response = LoginExchangeResponse.JsonPath;
        options.ResponseField = "token";
        options.Name = "CRMSESSION";

        Assert.True(new LoginExchangeOptionsValidator().Validate("c", options).Succeeded);
    }

    [Fact]
    public void RejectsQueryLocation()
    {
        var options = Valid();
        options.Location = CredentialLocation.Query;

        var result = new LoginExchangeOptionsValidator().Validate("c", options);

        Assert.False(result.Succeeded);
        Assert.Contains("Query", result.FailureMessage!, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectsCookieConfig_WithoutAnyName()
    {
        var options = Valid();
        options.Location = CredentialLocation.Cookie;
        options.Response = LoginExchangeResponse.RawBody;
        options.ResponseField = null;

        Assert.False(new LoginExchangeOptionsValidator().Validate("c", options).Succeeded);
    }

    [Fact]
    public void RejectsCookieConfig_WithInvalidCookieName()
    {
        var options = Valid();
        options.Location = CredentialLocation.Cookie;
        options.Name = "bad name";

        Assert.False(new LoginExchangeOptionsValidator().Validate("c", options).Succeeded);
    }

    [Fact]
    public void RejectsCookieConfig_WithAttachPrefix()
    {
        var options = Valid();
        options.Location = CredentialLocation.Cookie;
        options.AttachPrefix = "Bearer";

        Assert.False(new LoginExchangeOptionsValidator().Validate("c", options).Succeeded);
    }

    [Fact]
    public void CookiePlacement_EffectiveAttachmentUsesResponseFieldName_AndNoPrefix()
    {
        var options = Valid();
        options.Location = CredentialLocation.Cookie;
        options.AttachPrefix = "Bearer"; // invalid combo, but the fallback must not smuggle it either

        var attachment = (IHasAttachment)options;

        Assert.Equal(CredentialLocation.Cookie, attachment.Location);
        Assert.Equal("CRMSESSION", attachment.Name);
        Assert.Null(attachment.Prefix);
    }

    [Fact]
    public void HeaderPlacement_EffectiveAttachmentKeepsAuthorizationDefault()
    {
        var options = Valid();
        options.Response = LoginExchangeResponse.RawBody;
        options.ResponseField = null;

        var attachment = (IHasAttachment)options;

        Assert.Equal(CredentialLocation.Header, attachment.Location);
        Assert.Equal("Authorization", attachment.Name);
        Assert.Null(attachment.Prefix);
    }

    [Fact]
    public void HeaderPlacement_NameOverride_AndPrefix_AreHonoured()
    {
        var options = Valid();
        options.Response = LoginExchangeResponse.RawBody;
        options.ResponseField = null;
        options.Name = "X-Session";
        options.AttachPrefix = "Bearer";

        var attachment = (IHasAttachment)options;

        Assert.Equal("X-Session", attachment.Name);
        Assert.Equal("Bearer ", attachment.Prefix);
    }

    // --- M31 mutation triage: the cookie rules fired but no assertion pinned WHICH
    // message the operator gets (survivors :59, :65, :69), and two rules never fired
    // at all (NoCoverage :47 missing endpoint, :75 unsupported method). Each failure
    // message is the operator's fix-it text; a mutant blanking it must not survive. ---

    [Fact]
    public void RejectsMissingLoginEndpoint_MessageNamesTheKey()
    {
        var options = Valid();
        options.LoginEndpoint = null;

        var result = new LoginExchangeOptionsValidator().Validate("c", options);

        Assert.False(result.Succeeded);
        Assert.Contains("LoginEndpoint is required", result.FailureMessage!, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("PUT")]
    [InlineData("delete")]
    [InlineData("")]
    public void RejectsUnsupportedMethod_MessageNamesTheVerbs(string method)
    {
        var options = Valid();
        options.Method = method;

        var result = new LoginExchangeOptionsValidator().Validate("c", options);

        Assert.False(result.Succeeded);
        Assert.Contains("is not supported; use GET or POST", result.FailureMessage!, StringComparison.Ordinal);
    }

    [Fact]
    public void CookieWithAttachPrefix_MessageExplainsRawCookie()
    {
        var options = Valid();
        options.Location = CredentialLocation.Cookie;
        options.AttachPrefix = "Bearer";

        var result = new LoginExchangeOptionsValidator().Validate("c", options);

        Assert.Contains("AttachPrefix is not supported when Location is Cookie; a cookie carries the raw value",
            result.FailureMessage!, StringComparison.Ordinal);
    }

    [Fact]
    public void CookieWithoutAnyName_MessageNamesBothKeysAndWhy()
    {
        var options = Valid();
        options.Location = CredentialLocation.Cookie;
        options.Response = LoginExchangeResponse.RawBody;
        options.ResponseField = null;

        var result = new LoginExchangeOptionsValidator().Validate("c", options);

        Assert.Contains("Name or ResponseField is required when Location is Cookie: the cookie to replay must be named",
            result.FailureMessage!, StringComparison.Ordinal);
    }

    [Fact]
    public void CookieInvalidName_MessageNamesTheCookieAndRfc6265()
    {
        var options = Valid();
        options.Location = CredentialLocation.Cookie;
        options.Name = "bad name";

        var result = new LoginExchangeOptionsValidator().Validate("c", options);

        Assert.Contains("Cookie name 'bad name' is not a valid RFC 6265 cookie name",
            result.FailureMessage!, StringComparison.Ordinal);
    }
}
