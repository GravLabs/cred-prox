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

    // RequireHttpsMetadata (docs/adr/0003): inbound-validation key material over plain
    // http is refused at startup by default; the refusal names the opt-out.

    [Fact]
    public void RejectsHttpAuthorityByDefault()
    {
        var options = Valid();
        options.Issuer = null;
        options.JwksUri = null;
        options.Authority = "http://idp.example";
        options.TokenEndpoint = null; // discovered

        Assert.Contains("RequireHttpsMetadata", string.Join(" ",
            new TokenExchangeOptionsValidator().Validate("c", options).Failures!));
    }

    [Fact]
    public void RejectsHttpAuthorityWithLeadingWhitespace()
    {
        // F2: the URI parser eats leading whitespace, so " http://…" reaches the wire as
        // http; the scheme test judges the trimmed value.
        var options = Valid();
        options.Issuer = null;
        options.JwksUri = null;
        options.Authority = "  http://idp.example";
        options.TokenEndpoint = null; // discovered

        Assert.Contains("RequireHttpsMetadata", string.Join(" ",
            new TokenExchangeOptionsValidator().Validate("c", options).Failures!));
    }

    [Fact]
    public void RejectsHttpJwksUriByDefault()
    {
        var options = Valid();
        options.JwksUri = "http://idp.example/jwks";

        Assert.Contains("RequireHttpsMetadata", string.Join(" ",
            new TokenExchangeOptionsValidator().Validate("c", options).Failures!));
    }

    [Fact]
    public void AcceptsHttpMetadataWhenOptedOut()
    {
        var jwks = Valid();
        jwks.JwksUri = "http://idp.example/jwks";
        jwks.RequireHttpsMetadata = false;
        Assert.True(new TokenExchangeOptionsValidator().Validate("c", jwks).Succeeded);

        var authority = Valid();
        authority.Issuer = null;
        authority.JwksUri = null;
        authority.Authority = "http://idp.example";
        authority.TokenEndpoint = null;
        authority.RequireHttpsMetadata = false;
        Assert.True(new TokenExchangeOptionsValidator().Validate("c", authority).Succeeded);
    }

    [Fact]
    public void RejectsHttpAuthorityRegardlessOfSchemeCase()
    {
        var options = Valid();
        options.Issuer = null;
        options.JwksUri = null;
        options.Authority = "HTTP://idp.example";
        options.TokenEndpoint = null;

        Assert.Contains("RequireHttpsMetadata", string.Join(" ",
            new TokenExchangeOptionsValidator().Validate("c", options).Failures!));
    }

    [Fact]
    public void AcceptsTemplateThatHidesTheScheme()
    {
        // The startup validator cannot resolve templates; the runtime fetch fails closed
        // on the expanded value, so an undecidable scheme must not refuse startup.
        var options = Valid();
        options.Issuer = null;
        options.JwksUri = null;
        options.Authority = "{proto}://idp.example";
        options.TokenEndpoint = null;

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

    // --- M31 mutation triage. The source-combination gates survived because a Contains
    // over the joined failures lets an EXTRA failure ride along — exactly what the
    // :217/:222 logical mutants add. The failure SET must be pinned. ---

    [Fact]
    public void AcceptsAuthorityConfig_EvenWithIssuerSet_IgnoringIt()
    {
        // The :217 mutant ('!hasAuthority || ...') demands JwksUri here; with Authority
        // the issuer is discovered, so an explicit Issuer is permitted and irrelevant.
        var options = Valid();
        options.Authority = "https://idp.example";
        options.JwksUri = null;
        options.TokenEndpoint = null; // discovered

        Assert.True(new TokenExchangeOptionsValidator().Validate("c", options).Succeeded);
    }

    [Fact]
    public void RejectsBothSources_ExactlyOneFailure()
    {
        // The :222 mutant ('hasJwks || ...') fires 'Issuer is required with JwksUri' on
        // top of the mutual-exclusion failure. The operator must be told to pick one —
        // and nothing else.
        var options = Valid();
        options.Authority = "https://idp.example";
        options.Issuer = null;

        var result = new TokenExchangeOptionsValidator().Validate("c", options);

        Assert.False(result.Succeeded);
        Assert.Single(result.Failures!);
        Assert.Contains("Authority and JwksUri are mutually exclusive; pick one validation source",
            result.FailureMessage!, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectsUndefinedModeValue_MessageCitesTheRemoval()
    {
        // M27 review N1: the binder accepts a NUMBER for the removed enum member, so
        // Mode: 1 binds silently; the guard's message is the operator's redirect, and
        // every fragment of it must survive (:201/:202 string survivors).
        var options = Valid();
        options.Mode = (TokenExchangeMode)1; // the removed Entra OBO value

        var result = new TokenExchangeOptionsValidator().Validate("c", options);

        Assert.False(result.Succeeded);
        Assert.Contains("Mode is not a defined TokenExchangeMode value: '1'",
            result.FailureMessage!, StringComparison.Ordinal);
        Assert.Contains("removed in M27", result.FailureMessage!, StringComparison.Ordinal);
        Assert.Contains("use Mode: Rfc8693 or omit the key", result.FailureMessage!, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectsEmptySubjectClaim()
    {
        // Empty SubjectClaim would exchange every token minted by the issuer (§3.6).
        var options = Valid();
        options.SubjectClaim = string.Empty;

        var result = new TokenExchangeOptionsValidator().Validate("c", options);

        Assert.False(result.Succeeded);
        Assert.Contains("SubjectClaim must not be empty", result.FailureMessage!, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectsEmptyTokenField()
    {
        var options = Valid();
        options.TokenField = string.Empty;

        var result = new TokenExchangeOptionsValidator().Validate("c", options);

        Assert.False(result.Succeeded);
        Assert.Contains("TokenField is required", result.FailureMessage!, StringComparison.Ordinal);
    }

    // Boundary pair for the skew/lifetime comparators (:251/:256 equality survivors):
    // zero must pass (operators legitimately disable skew), negative/zero lifetime must not.
    [Fact]
    public void AcceptsZeroClockSkew()
    {
        var options = Valid();
        options.ClockSkew = TimeSpan.Zero;

        Assert.True(new TokenExchangeOptionsValidator().Validate("c", options).Succeeded);
    }

    [Fact]
    public void RejectsNegativeClockSkew_NamingTheRule()
    {
        var options = Valid();
        options.ClockSkew = TimeSpan.FromSeconds(-1);

        var result = new TokenExchangeOptionsValidator().Validate("c", options);

        Assert.False(result.Succeeded);
        Assert.Contains("ClockSkew must not be negative", result.FailureMessage!, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectsZeroDefaultLifetime_NamingTheRule()
    {
        var options = Valid();
        options.DefaultLifetime = TimeSpan.Zero;

        var result = new TokenExchangeOptionsValidator().Validate("c", options);

        Assert.False(result.Succeeded);
        Assert.Contains("DefaultLifetime must be positive", result.FailureMessage!, StringComparison.Ordinal);
    }
}
