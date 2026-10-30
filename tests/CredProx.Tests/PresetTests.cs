using System.Text.Json;
using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// §5.2 "Presets" row, 0.4.0 shape: the library ships no built-in vendor presets — a
/// preset is a host-defined fragment (<c>CredProx:Presets</c> or a custom
/// <see cref="IPresetSource"/>). Each preset validates; a field-level override wins over
/// the preset; an unknown preset fails startup; a name that belonged to a removed
/// built-in fails startup pointing at its sample; and a preset cannot introduce a
/// <c>secret:</c> reference the host did not configure — the preset's references are
/// validated through the host's secret source exactly like the host's own.
/// </summary>
public sealed class PresetTests
{
    private static ServiceProvider BuildServices(IConfiguration configuration)
    {
        var services = new ServiceCollection();
        services.AddCredProxTokenCache();
        services.AddCredProxConfigurationSecrets(configuration);
        services.AddCredProxBuiltInCredentials();
        services.AddCredProxCredentials(configuration);
        return services.BuildServiceProvider();
    }

    private static IConfiguration Config(params (string Key, string? Value)[] entries)
    {
        var dictionary = entries.ToDictionary(e => "CredProx:" + e.Key, e => e.Value);
        return new ConfigurationBuilder().AddInMemoryCollection(dictionary).Build();
    }

    // A host-defined OAuth preset under CredProx:Presets — the shape a community preset
    // takes with no code. Mirrors what samples/Spotify now writes out in full.
    private static readonly (string Key, string? Value)[] AcmeOAuthPreset =
    [
        ("Presets:acme-oauth:Type", "OAuthClientCredentials"),
        ("Presets:acme-oauth:TokenEndpoint", "https://accounts.acme.example/api/token"),
        ("Presets:acme-oauth:ClientAuthentication", "BasicHeader"),
        ("Presets:acme-oauth:ClientSecret", "secret:acme-client-secret"),
    ];

    [Fact]
    public void Preset_SuppliesTypeAndFields_CredentialBindsCompletely()
    {
        // The whole point of a preset: the credential section is a name and a client id.
        var configuration = Config(
            [.. AcmeOAuthPreset,
                ("Credentials:acme:Preset", "acme-oauth"),
                ("Credentials:acme:ClientId", "my-dev-app")]);

        var binding = BuildServices(configuration)
            .GetRequiredService<CredentialRegistry>()
            .Get("acme");

        Assert.Equal("OAuthClientCredentials", binding.TypeName);
        var options = Assert.IsType<OAuthClientCredentialsOptions>(binding.Options);
        Assert.Equal("https://accounts.acme.example/api/token", options.TokenEndpoint);
        Assert.Equal(OAuthClientAuthentication.BasicHeader, options.ClientAuthentication);
        Assert.Equal("secret:acme-client-secret", options.ClientSecret);
        Assert.Equal("my-dev-app", options.ClientId);
    }

    [Fact]
    public void HostField_WinsOverThePresetField()
    {
        var configuration = Config(
            [.. AcmeOAuthPreset,
                ("Credentials:acme:Preset", "acme-oauth"),
                ("Credentials:acme:ClientId", "my-dev-app"),
                ("Credentials:acme:TokenEndpoint", "https://proxy.example/token"),
                ("Credentials:acme:Scope", "streaming")]);

        var binding = BuildServices(configuration)
            .GetRequiredService<CredentialRegistry>()
            .Get("acme");

        var options = Assert.IsType<OAuthClientCredentialsOptions>(binding.Options);
        Assert.Equal("https://proxy.example/token", options.TokenEndpoint); // override wins
        Assert.Equal("streaming", options.Scope); // preset-absent field fills in
        Assert.Equal("secret:acme-client-secret", options.ClientSecret); // preset stands
    }

    [Fact]
    public void UnknownPreset_FailsStartupNamingThePreset()
    {
        var configuration = Config(
            ("Credentials:x:Preset", "nonexistent-vendor"),
            ("Credentials:x:Type", "StaticKey"),
            ("Credentials:x:Secret", "secret:k"),
            ("Credentials:x:Name", "X-Key"),
            ("Secrets:k", "v"));

        var error = Assert.Throws<OptionsValidationException>(() =>
            BuildServices(configuration).GetRequiredService<CredentialRegistry>());

        Assert.Contains("unknown preset 'nonexistent-vendor'", error.Message);
        Assert.Contains("'x'", error.Message);
    }

    public static TheoryData<string, string> RemovedBuiltInPresets() => new()
    {
        // The six names 0.3 embedded; each must now fail startup pointing at the sample
        // whose explicit config replaces the preset.
        { "spotify", "samples/Spotify" },
        { "microsoft-graph", "samples/MicrosoftGraph" },
        { "github-app", "samples/GitHubApp" },
        { "keycloak", "samples/OAuthKeycloak" },
        { "adp", "samples/ADP" },
        { "cayuse", "samples/LoginExchange" },
    };

    [Theory]
    [MemberData(nameof(RemovedBuiltInPresets))]
    public void RemovedBuiltInPreset_FailsStartupPointingAtItsSample(string preset, string sample)
    {
        var configuration = Config(
            ("Credentials:x:Preset", preset),
            ("Credentials:x:Type", "StaticKey"),
            ("Credentials:x:Secret", "secret:k"),
            ("Credentials:x:Name", "X-Key"),
            ("Secrets:k", "v"));

        var error = Assert.Throws<OptionsValidationException>(() =>
            BuildServices(configuration).GetRequiredService<CredentialRegistry>());

        Assert.Contains($"'{preset}'", error.Message);
        Assert.Contains("removed in 0.4.0", error.Message);
        Assert.Contains(sample, error.Message);
        Assert.Contains("'x'", error.Message);
    }

    [Fact]
    public void RemovedBuiltInPresetName_HostRedefinesIt_UsesTheHostsFragment()
    {
        // The name is the host's to reuse: a CredProx:Presets entry resolves before the
        // removed-name pointer, so no startup error is produced.
        var configuration = Config(
            ("Presets:spotify:Type", "StaticKey"),
            ("Presets:spotify:Name", "X-Acme-Key"),
            ("Presets:spotify:Secret", "secret:k"),
            ("Credentials:c:Preset", "spotify"),
            ("Secrets:k", "v"));

        var binding = BuildServices(configuration)
            .GetRequiredService<CredentialRegistry>()
            .Get("c");

        Assert.Equal("StaticKey", binding.TypeName);
    }

    [Fact]
    public async Task PresetSecretReference_TheHostDidNotConfigure_FailsStartupValidation()
    {
        // The preset introduces secret:acme-client-secret. The host wrote no such secret,
        // so the same startup scan that checks host references must reject it.
        var configuration = Config(
            [.. AcmeOAuthPreset,
                ("Credentials:acme:Preset", "acme-oauth"),
                ("Credentials:acme:ClientId", "my-dev-app")]);

        var services = BuildServices(configuration);
        var composed = PresetConfiguration.Compose(
            configuration, services.GetServices<IPresetSource>(), []);

        var error = await Assert.ThrowsAsync<OptionsValidationException>(() =>
            services.GetRequiredService<SecretReferenceValidator>()
                .ValidateAsync(composed.GetSection("CredProx"), default).AsTask());

        Assert.Contains("secret:acme-client-secret", error.Message);
        Assert.Contains("does not resolve", error.Message);
    }

    [Fact]
    public async Task PresetSecretReference_TheHostConfigured_Resolves()
    {
        var configuration = Config(
            [.. AcmeOAuthPreset,
                ("Credentials:acme:Preset", "acme-oauth"),
                ("Credentials:acme:ClientId", "my-dev-app"),
                ("Secrets:acme-client-secret", "the-secret")]);

        var services = BuildServices(configuration);
        var composed = PresetConfiguration.Compose(
            configuration, services.GetServices<IPresetSource>(), []);

        // Must not throw: the preset's reference resolves through the host's source.
        await services.GetRequiredService<SecretReferenceValidator>()
            .ValidateAsync(composed.GetSection("CredProx"), default);
    }

    [Fact]
    public void ConfigurationPreset_IsReferencedByName_BindsNestedShapes()
    {
        // A community preset written under CredProx:Presets — including the array shape —
        // is a first-class preset with no code.
        var configuration = Config(
            ("Presets:signed-hmac:Type", "Hmac"),
            ("Presets:signed-hmac:Secret", "secret:hmac-key"),
            ("Presets:signed-hmac:SignatureHeader", "X-Signature"),
            ("Presets:signed-hmac:Components:0", "method"),
            ("Presets:signed-hmac:Components:1", "path"),
            ("Credentials:vendor:Preset", "signed-hmac"),
            ("Secrets:hmac-key", "v"));

        var binding = BuildServices(configuration)
            .GetRequiredService<CredentialRegistry>()
            .Get("vendor");

        Assert.Equal("Hmac", binding.TypeName);
        var options = Assert.IsType<HmacOptions>(binding.Options);
        Assert.Equal(["method", "path"], options.Components);
        Assert.Equal("X-Signature", options.SignatureHeader);
    }

    [Fact]
    public void ConfigurationPreset_UnknownName_ReturnsFalse()
    {
        var source = new ConfigurationPresetSource(Config(("Presets:known:Type", "StaticKey")));

        Assert.True(source.TryGetPreset("known", out var preset));
        Assert.Equal(JsonValueKind.Object, preset.ValueKind);
        Assert.False(source.TryGetPreset("missing", out _));
    }

    [Fact]
    public void LoginExchangePreset_NestedFormObject_Binds()
    {
        // The nested-object shape (a Form block inside the fragment) flattens exactly as
        // the JSON provider would — the login-exchange vendor shape as a host preset.
        var configuration = Config(
            ("Presets:acme-login:Type", "LoginExchange"),
            ("Presets:acme-login:Method", "POST"),
            ("Presets:acme-login:Response", "JsonPath"),
            ("Presets:acme-login:ResponseField", "sessionId"),
            ("Presets:acme-login:Lifetime", "01:00:00"),
            ("Presets:acme-login:Form:User", "{partition}-svc"),
            ("Presets:acme-login:Form:Password", "secret:acme-password"),
            ("Credentials:c:Preset", "acme-login"),
            ("Credentials:c:LoginEndpoint", "https://acme.example/{partition}/login"));

        var binding = BuildServices(configuration)
            .GetRequiredService<CredentialRegistry>()
            .Get("c");

        var options = Assert.IsType<LoginExchangeOptions>(binding.Options);
        Assert.Equal("POST", options.Method);
        Assert.Equal(LoginExchangeResponse.JsonPath, options.Response);
        Assert.Equal("sessionId", options.ResponseField);
        Assert.Equal(TimeSpan.FromHours(1), options.Lifetime);
        Assert.NotNull(options.Form);
        Assert.Equal("{partition}-svc", options.Form!.User);
        Assert.Equal("secret:acme-password", options.Form.Password);
    }

    private sealed class ArrayPresetSource : IPresetSource
    {
        public bool TryGetPreset(string name, out JsonElement preset)
        {
            if (name == "not-an-object")
            {
                preset = JsonDocument.Parse("""["Type","StaticKey"]""").RootElement.Clone();
                return true;
            }

            preset = default;
            return false;
        }
    }

    [Fact]
    public void PresetFragment_ThatIsNotAnObject_FailsStartup()
    {
        var configuration = Config(
            ("Credentials:c:Preset", "not-an-object"),
            ("Credentials:c:Type", "StaticKey"),
            ("Credentials:c:Secret", "secret:k"),
            ("Credentials:c:Name", "X"),
            ("Secrets:k", "v"));

        var services = new ServiceCollection();
        services.AddCredProxTokenCache();
        services.AddCredProxConfigurationSecrets(configuration);
        services.AddCredProxBuiltInCredentials();
        services.AddSingleton<IPresetSource, ArrayPresetSource>();
        services.AddCredProxCredentials(configuration);

        var error = Assert.Throws<OptionsValidationException>(() =>
            services.BuildServiceProvider().GetRequiredService<CredentialRegistry>());

        Assert.Contains("not a JSON object", error.Message);
    }

    private sealed class JwtAssertionPresetSource : IPresetSource
    {
        public bool TryGetPreset(string name, out JsonElement preset)
        {
            if (name == "jwt-exchange")
            {
                preset = JsonDocument.Parse("""
                {
                  "Type": "JwtAssertion",
                  "Algorithm": "RS256",
                  "SigningKey": "secret:jwt-key",
                  "Audience": "https://api.example",
                  "Lifetime": "00:09:00",
                  "Exchange": "BearerExchange",
                  "TokenField": "token",
                  "ExpiresAtField": "expires_at"
                }
                """).RootElement.Clone();
                return true;
            }

            preset = default;
            return false;
        }
    }

    [Fact]
    public void PresetNullMember_DoesNotShadowTheOptionsDefault()
    {
        // A preset member the fragment omits carries nothing: ExpiresInField keeps its
        // options default ("expires_in"), it is not nulled out by the fragment.
        var configuration = Config(
            ("Credentials:c:Preset", "jwt-exchange"),
            ("Credentials:c:Issuer", "1"),
            ("Credentials:c:TokenEndpoint", "https://api.example/app/installations/2/access_tokens"));

        var services = new ServiceCollection();
        services.AddCredProxTokenCache();
        services.AddCredProxConfigurationSecrets(configuration);
        services.AddCredProxBuiltInCredentials();
        services.AddSingleton<IPresetSource, JwtAssertionPresetSource>();
        services.AddCredProxCredentials(configuration);

        var binding = services.BuildServiceProvider()
            .GetRequiredService<CredentialRegistry>()
            .Get("c");

        var options = Assert.IsType<JwtAssertionOptions>(binding.Options);
        Assert.Equal("expires_in", options.ExpiresInField);
        Assert.Equal("expires_at", options.ExpiresAtField);
        Assert.Equal(JwtAssertionExchange.BearerExchange, options.Exchange);
        Assert.Equal("token", options.TokenField);
    }
}
