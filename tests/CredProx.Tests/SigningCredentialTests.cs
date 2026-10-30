using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// Startup validation for the M9 signing credential types (§3.5: bad config fails at
/// startup, not at the first vendor call) and the <see cref="HmacProvider"/>'s key
/// resolution (signature-style: the key resolves but is never attached).
/// </summary>
public sealed class SigningCredentialTests
{
    // ---- JwtAssertionOptionsValidator ----

    private static JwtAssertionOptions ValidJwtOptions() => new()
    {
        SigningKey = "secret:key",
        Issuer = "app",
        Audience = "https://vendor.example",
        TokenEndpoint = "https://vendor.example/token",
    };

    [Fact]
    public void JwtValidator_AcceptsMinimalValidConfig()
    {
        Assert.True(new JwtAssertionOptionsValidator()
            .Validate("c", ValidJwtOptions()).Succeeded);
    }

    [Fact]
    public void JwtValidator_RejectsMissingSigningMaterial()
    {
        var options = ValidJwtOptions();
        options.SigningKey = null;

        Assert.Contains("SigningKey", Assert.Single(
            new JwtAssertionOptionsValidator().Validate("c", options).Failures!));
    }

    [Fact]
    public void JwtValidator_RejectsBothKeyAndCertificate()
    {
        var options = ValidJwtOptions();
        options.SigningCertificate = "secret:cert";

        Assert.Contains("mutually exclusive", Assert.Single(
            new JwtAssertionOptionsValidator().Validate("c", options).Failures!));
    }

    [Fact]
    public void JwtValidator_RejectsRelativeEndpointAndNonPositiveLifetime()
    {
        var options = ValidJwtOptions();
        options.TokenEndpoint = "/relative";
        options.Lifetime = TimeSpan.Zero;

        var failures = new JwtAssertionOptionsValidator().Validate("c", options).Failures!;
        Assert.Contains(failures, f => f.Contains("TokenEndpoint"));
        Assert.Contains(failures, f => f.Contains("Lifetime"));
    }

    // ---- HmacOptionsValidator ----

    private static HmacOptions ValidHmacOptions() => new()
    {
        Secret = "secret:key",
        SignatureHeader = "X-Signature",
        Components = ["method", "path"],
    };

    [Fact]
    public void HmacValidator_AcceptsMinimalValidConfig()
    {
        Assert.True(new HmacOptionsValidator().Validate("c", ValidHmacOptions()).Succeeded);
    }

    [Fact]
    public void HmacValidator_RejectsUnknownComponent()
    {
        var options = ValidHmacOptions();
        options.Components = ["method", "body"];

        Assert.Contains("body", Assert.Single(
            new HmacOptionsValidator().Validate("c", options).Failures!));
    }

    [Fact]
    public void HmacValidator_BodyHashRequiresBuffering()
    {
        var options = ValidHmacOptions();
        options.Components = ["method", "bodyHash"];

        Assert.Contains("BufferBody", Assert.Single(
            new HmacOptionsValidator().Validate("c", options).Failures!));
    }

    [Fact]
    public void HmacValidator_RejectsNonPositiveCapWhenBuffering()
    {
        var options = ValidHmacOptions();
        options.Components = ["method", "bodyHash"];
        options.BufferBody = true;
        options.MaxBodyBytes = 0;

        Assert.Contains("MaxBodyBytes", Assert.Single(
            new HmacOptionsValidator().Validate("c", options).Failures!));
    }

    [Fact]
    public void HmacValidator_RejectsMissingSecretOrSignatureHeader()
    {
        var options = ValidHmacOptions();
        options.Secret = null;
        options.SignatureHeader = null;

        var failures = new HmacOptionsValidator().Validate("c", options).Failures!;
        Assert.Contains(failures, f => f.Contains("Secret"));
        Assert.Contains(failures, f => f.Contains("SignatureHeader"));
    }

    // ---- HmacProvider ----

    [Fact]
    public async Task HmacProvider_ResolvesTheKey()
    {
        var secrets = TestSecrets.AccessorFor(
            new() { ["Secret"] = "secret:hmac-key" },
            new() { ["hmac-key"] = "shared-key-value" });

        var key = await new HmacProvider().GetCredentialAsync(
            new HmacOptions { Secret = "secret:hmac-key" },
            secrets,
            new CredentialRequestContext { CredentialName = "signer", Partition = null },
            default);

        Assert.Equal("shared-key-value", key);
    }

    [Fact]
    public async Task HmacProvider_MissingSecretFailsWithoutValueInMessage()
    {
        // Reference declared in the credential's config but absent from the store: the
        // accessor fails naming the reference — never a value (there is none to leak).
        var secrets = TestSecrets.AccessorFor(
            new() { ["Secret"] = "secret:absent" },
            new());

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => new HmacProvider()
            .GetCredentialAsync(
                new HmacOptions { Secret = "secret:absent" },
                secrets,
                new CredentialRequestContext { CredentialName = "signer", Partition = null },
                default)
            .AsTask());

        Assert.Contains("secret:absent", ex.Message);
    }

    [Fact]
    public void HmacOptions_DeclareNoAttachment()
    {
        // Signature-style credential: the attach step must place nothing on the request.
        Assert.False(typeof(IHasAttachment).IsAssignableFrom(typeof(HmacOptions)));
    }
}
