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
}
