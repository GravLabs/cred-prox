using CredProx;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage for the built-in options validators that had no direct tests:
/// OAuthClientCredentials, StaticKey, JwtAssertion and Hmac. For each rule the operator
/// must get the exact fix-it message (string survivors / NoCoverage rows), the success
/// path must be asserted (the always-Fail gate mutants :30/:112 survived), and the
/// boundary comparators need both sides pinned.
/// </summary>
public sealed class CredentialOptionsValidatorsM31Tests
{
    // --- OAuthClientCredentialsOptionsValidator ---

    private static OAuthClientCredentialsOptions OAuthValid() => new()
    {
        TokenEndpoint = "https://idp.example/token",
        ClientId = "cid",
        ClientSecret = "secret:cid-secret",
    };

    [Fact]
    public void OAuth_AcceptsValidConfig()
    {
        // Kills the always-Fail gate mutant (:30 equality survivor): without a
        // success assertion a validator that fails every config looks identical.
        Assert.True(new OAuthClientCredentialsOptionsValidator().Validate("c", OAuthValid()).Succeeded);
    }

    [Fact]
    public void OAuth_RejectsMissingTokenEndpoint_MessageNamesTheKey()
    {
        var options = OAuthValid();
        options.TokenEndpoint = null;

        var result = new OAuthClientCredentialsOptionsValidator().Validate("c", options);

        Assert.False(result.Succeeded);
        Assert.Contains("TokenEndpoint is required", result.FailureMessage!, StringComparison.Ordinal);
    }

    [Fact]
    public void OAuth_RejectsNonHttpScheme_MessageNamesTheContract()
    {
        var options = OAuthValid();
        options.TokenEndpoint = "ftp://idp.example/token";

        var result = new OAuthClientCredentialsOptionsValidator().Validate("c", options);

        Assert.False(result.Succeeded);
        Assert.Contains("TokenEndpoint must be an absolute http(s) URL", result.FailureMessage!, StringComparison.Ordinal);
    }

    [Fact]
    public void OAuth_RejectsMissingClientId_MessageNamesTheKey()
    {
        var options = OAuthValid();
        options.ClientId = null;

        var result = new OAuthClientCredentialsOptionsValidator().Validate("c", options);

        Assert.False(result.Succeeded);
        Assert.Contains("ClientId is required", result.FailureMessage!, StringComparison.Ordinal);
    }

    // --- StaticKeyOptionsValidator ---

    [Fact]
    public void StaticKey_AcceptsValidConfig()
    {
        Assert.True(new StaticKeyOptionsValidator().Validate("c",
            new StaticKeyOptions { Secret = "plain", Name = "X-Api-Key" }).Succeeded);
    }

    [Fact]
    public void StaticKey_RejectsMissingSecret_MessageNamesTheKey()
    {
        var result = new StaticKeyOptionsValidator().Validate("c",
            new StaticKeyOptions { Name = "X-Api-Key" });

        Assert.False(result.Succeeded);
        Assert.Contains("Secret is required", result.FailureMessage!, StringComparison.Ordinal);
    }

    [Fact]
    public void StaticKey_RejectsMissingName_MessageNamesTheKey()
    {
        var result = new StaticKeyOptionsValidator().Validate("c",
            new StaticKeyOptions { Secret = "plain" });

        Assert.False(result.Succeeded);
        Assert.Contains("Name is required", result.FailureMessage!, StringComparison.Ordinal);
    }

    // --- JwtAssertionOptionsValidator ---

    private static JwtAssertionOptions JwtValid() => new()
    {
        SigningKey = "assertion-signing-key",
        Issuer = "app-id",
        Audience = "https://idp.example",
        TokenEndpoint = "https://idp.example/token",
    };

    [Fact]
    public void JwtAssertion_AcceptsValidConfig()
    {
        Assert.True(new JwtAssertionOptionsValidator().Validate("c", JwtValid()).Succeeded);
    }

    [Fact]
    public void JwtAssertion_RejectsNoSigningMaterial_MessageNamesBothKeys()
    {
        var options = JwtValid();
        options.SigningKey = null;

        var result = new JwtAssertionOptionsValidator().Validate("c", options);

        Assert.False(result.Succeeded);
        Assert.Contains("SigningKey or SigningCertificate is required",
            result.FailureMessage!, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Issuer")]
    [InlineData("Audience")]
    [InlineData("TokenEndpoint")]
    public void JwtAssertion_RejectsMissingClaimEssential_MessageNamesTheKey(string key)
    {
        var options = JwtValid();
        typeof(JwtAssertionOptions).GetProperty(key)!.SetValue(options, null);

        var result = new JwtAssertionOptionsValidator().Validate("c", options);

        Assert.False(result.Succeeded);
        Assert.Contains($"{key} is required", result.FailureMessage!, StringComparison.Ordinal);
    }

    [Fact]
    public void JwtAssertion_AcceptsZeroClockSkew_RejectsNegative_NamingTheRule()
    {
        var validator = new JwtAssertionOptionsValidator();

        var zero = JwtValid();
        zero.ClockSkew = TimeSpan.Zero; // the option default — must stay valid
        Assert.True(validator.Validate("c", zero).Succeeded);

        var negative = JwtValid();
        negative.ClockSkew = TimeSpan.FromSeconds(-1);
        var result = validator.Validate("c", negative);

        Assert.False(result.Succeeded);
        Assert.Contains("ClockSkew must not be negative", result.FailureMessage!, StringComparison.Ordinal);
    }

    [Fact]
    public void JwtAssertion_RejectsZeroDefaultLifetime_NamingTheRule()
    {
        // '<=' boundary (:167 equality survivor): zero is the mutant's pass, the
        // rule's fail — a cached credential that expires immediately is a config error.
        var options = JwtValid();
        options.DefaultLifetime = TimeSpan.Zero;

        var result = new JwtAssertionOptionsValidator().Validate("c", options);

        Assert.False(result.Succeeded);
        Assert.Contains("DefaultLifetime must be positive", result.FailureMessage!, StringComparison.Ordinal);
    }

    [Fact]
    public void JwtAssertion_RejectsEmptyTokenField_MessageNamesTheKey()
    {
        var options = JwtValid();
        options.TokenField = string.Empty;

        var result = new JwtAssertionOptionsValidator().Validate("c", options);

        Assert.False(result.Succeeded);
        Assert.Contains("TokenField is required", result.FailureMessage!, StringComparison.Ordinal);
    }

    // --- HmacOptionsValidator ---

    private static HmacOptions HmacValid() => new()
    {
        Secret = "hmac-secret",
        SignatureHeader = "X-Signature",
        Components = ["method", "path"],
    };

    [Fact]
    public void Hmac_AcceptsValidConfig()
    {
        Assert.True(new HmacOptionsValidator().Validate("c", HmacValid()).Succeeded);
    }

    [Fact]
    public void Hmac_RejectsEmptyComponents_MessageNamesTheRecipe()
    {
        var options = HmacValid();
        options.Components = [];

        var result = new HmacOptionsValidator().Validate("c", options);

        Assert.False(result.Succeeded);
        Assert.Contains("Components must list at least one canonical-string component",
            result.FailureMessage!, StringComparison.Ordinal);
    }

    [Fact]
    public void Hmac_RejectsUnrecognizedComponent_MessageNamesTokenAndVocabulary()
    {
        var options = HmacValid();
        options.Components = ["method", "bofyHash"];

        var result = new HmacOptionsValidator().Validate("c", options);

        Assert.False(result.Succeeded);
        Assert.Contains("Component 'bofyHash' is not recognized", result.FailureMessage!, StringComparison.Ordinal);
        Assert.Contains("method, path, query, timestamp, bodyHash or header:<Name>",
            result.FailureMessage!, StringComparison.Ordinal);
    }

    [Fact]
    public void Hmac_DuplicateBodyHash_WithoutBuffer_StillFailsOnce()
    {
        // :307 survivor: needsBody was accumulated with '|='; the '^=' mutant cancels
        // out on a repeated bodyHash component and signs a body that was never
        // buffered. Two bodyHash entries must fail exactly like one.
        var options = HmacValid();
        options.BufferBody = false;
        options.Components = ["bodyHash", "bodyHash"];

        var result = new HmacOptionsValidator().Validate("c", options);

        Assert.False(result.Succeeded);
        Assert.Single(result.Failures!);
        Assert.Contains("The bodyHash component requires BufferBody", result.FailureMessage!, StringComparison.Ordinal);
    }

    [Fact]
    public void Hmac_BodyHashWithBuffer_Accepted()
    {
        var options = HmacValid();
        options.BufferBody = true;
        options.Components = ["method", "bodyHash"];

        Assert.True(new HmacOptionsValidator().Validate("c", options).Succeeded);
    }
}
