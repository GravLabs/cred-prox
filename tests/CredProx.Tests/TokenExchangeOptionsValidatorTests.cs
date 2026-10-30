using CredProx;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// §3.6 startup validation for <see cref="TokenExchangeOptions"/>: the validation source
/// (Authority XOR Issuer+JwksUri — each direction fails at startup, never at runtime),
/// the mandatory inbound Audience, and the exchange essentials.
/// </summary>
public sealed class TokenExchangeOptionsValidatorTests
{
    private static TokenExchangeOptions Valid() => new()
    {
        Issuer = "https://idp.example",
        JwksUri = "https://idp.example/jwks",
        Audience = "credprox-api",
        TokenEndpoint = "https://idp.example/token",
        ClientId = "cid",
    };

    [Fact]
    public void AcceptsExplicitJwksConfig()
    {
        Assert.True(new TokenExchangeOptionsValidator().Validate("c", Valid()).Succeeded);
    }

    [Fact]
    public void AcceptsAuthorityConfig_WithoutIssuerOrTokenEndpoint()
    {
        var options = Valid();
        options.Issuer = null;
        options.JwksUri = null;
        options.Authority = "https://idp.example";
        options.TokenEndpoint = null; // discovered

        Assert.True(new TokenExchangeOptionsValidator().Validate("c", options).Succeeded);
    }

    [Fact]
    public void RejectsNeitherValidationSource()
    {
        var options = Valid();
        options.JwksUri = null;

        Assert.Contains("Authority or Issuer+JwksUri", string.Join(" ",
            new TokenExchangeOptionsValidator().Validate("c", options).Failures!));
    }

    [Fact]
    public void RejectsBothValidationSources()
    {
        var options = Valid();
        options.Authority = "https://idp.example";

        Assert.Contains("mutually exclusive", string.Join(" ",
            new TokenExchangeOptionsValidator().Validate("c", options).Failures!));
    }

    [Fact]
    public void RejectsIssuerWithoutJwksUri()
    {
        var options = Valid();
        options.JwksUri = null;
        options.TokenEndpoint = "https://idp.example/token";

        Assert.Contains("Issuer requires JwksUri", string.Join(" ",
            new TokenExchangeOptionsValidator().Validate("c", options).Failures!));
    }

    [Fact]
    public void RejectsJwksUriWithoutIssuer()
    {
        // M14 review observation 1: ValidIssuer=null would reject every token at
        // runtime; the mirror rule fails it at startup.
        var options = Valid();
        options.Issuer = null;

        Assert.Contains("Issuer is required with JwksUri", string.Join(" ",
            new TokenExchangeOptionsValidator().Validate("c", options).Failures!));
    }

    [Fact]
    public void RejectsMissingAudience()
    {
        var options = Valid();
        options.Audience = null;

        Assert.Contains("Audience is required", string.Join(" ",
            new TokenExchangeOptionsValidator().Validate("c", options).Failures!));
    }

    [Fact]
    public void RejectsMissingTokenEndpoint_WithoutAuthority()
    {
        var options = Valid();
        options.TokenEndpoint = null;

        Assert.Contains("TokenEndpoint is required", string.Join(" ",
            new TokenExchangeOptionsValidator().Validate("c", options).Failures!));
    }

    [Fact]
    public void RejectsMissingClientId()
    {
        var options = Valid();
        options.ClientId = null;

        Assert.Contains("ClientId is required", string.Join(" ",
            new TokenExchangeOptionsValidator().Validate("c", options).Failures!));
    }
}
