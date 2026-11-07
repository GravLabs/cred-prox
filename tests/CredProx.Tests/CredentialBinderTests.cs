using System.Net;
using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// §5.2 "Validation" and "Explicit registration" rows: every
/// <c>CredProx:Credentials</c> section binds at startup; a missing or unknown <c>Type</c>
/// and failing validators throw before traffic; the registry serves bound credentials with
/// their scoped accessors and attach steps.
/// </summary>
public sealed class CredentialBinderTests
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

    [Fact]
    public void UnknownCredentialType_FailsStartupNamingTheCredentialAndKnownTypes()
    {
        var configuration = Config(
            ("Credentials:weird:Type", "Magic"),
            ("Credentials:weird:Name", "X"));

        var error = Assert.Throws<OptionsValidationException>(() =>
            BuildServices(configuration).GetRequiredService<CredentialRegistry>());

        Assert.Contains("weird", error.Message);
        Assert.Contains("Magic", error.Message);
        Assert.Contains("OAuthClientCredentials", error.Message);
        Assert.Contains("StaticKey", error.Message);
    }

    [Fact]
    public void MissingType_FailsStartup()
    {
        var configuration = Config(("Credentials:ownerless:Name", "X"));

        var error = Assert.Throws<OptionsValidationException>(() =>
            BuildServices(configuration).GetRequiredService<CredentialRegistry>());

        Assert.Contains("ownerless", error.Message);
        Assert.Contains("no Type", error.Message);
    }

    [Fact]
    public void FailingValidator_FailsStartupWithoutLeakingValues()
    {
        var configuration = Config(
            ("Credentials:key:Type", "StaticKey"),
            ("Credentials:key:Secret", "secret:api-key"), // Name missing
            ("Secrets:api-key", "top-secret-value"));

        var error = Assert.Throws<OptionsValidationException>(() =>
            BuildServices(configuration).GetRequiredService<CredentialRegistry>());

        Assert.Contains("key", error.Message);
        Assert.Contains("Name is required", error.Message);
        Assert.DoesNotContain("top-secret-value", error.Message);
    }

    [Fact]
    public void AllProblems_AreCollectedIntoOneFailure()
    {
        var configuration = Config(
            ("Credentials:a:Type", "Magic"),
            ("Credentials:b:Type", "StaticKey")); // missing Secret and Name

        var error = Assert.Throws<OptionsValidationException>(() =>
            BuildServices(configuration).GetRequiredService<CredentialRegistry>());

        Assert.Contains("'a'", error.Message);
        Assert.Contains("'b'", error.Message);
    }

    [Fact]
    public async Task StaticKey_BindsResolvesAndAttaches()
    {
        var configuration = Config(
            ("Credentials:key:Type", "StaticKey"),
            ("Credentials:key:Secret", "secret:api-key"),
            ("Credentials:key:Name", "X-Api-Key"),
            ("Credentials:key:Prefix", "Key "),
            ("Secrets:api-key", "kv-1"));

        var registry = BuildServices(configuration).GetRequiredService<CredentialRegistry>();

        var binding = registry.Get("key");
        Assert.Equal("StaticKey", binding.TypeName);
        Assert.Equal("kv-1", await binding.GetCredential(new CredentialRequestContext { CredentialName = "key" }, default));

        var request = new HttpRequestMessage(HttpMethod.Get, "https://vendor.example/api");
        binding.Attach!(request, "kv-1");
        Assert.Equal("Key kv-1", Assert.Single(request.Headers.GetValues("X-Api-Key")));
    }

    [Fact]
    public async Task DynamicSecretName_ResolvesThroughTheSectionsShape()
    {
        // §3.2 acme through the binder: the section declares the shape, the request's
        // partition expands it, and the scoped accessor resolves the expanded name.
        var configuration = Config(
            ("Credentials:acme:Type", "LoginExchange"),
            ("Credentials:acme:LoginEndpoint", "http://vendor.example/{partition}/login"),
            ("Credentials:acme:Method", "GET"),
            ("Credentials:acme:Basic:User", "secret:acme-{partition}-user"),
            ("Credentials:acme:Basic:Password", "secret:acme-{partition}-pass"),
            ("Secrets:acme-uat-user", "uat-user"),
            ("Secrets:acme-uat-pass", "uat-pass"));

        var handler = new StubHttpHandler(HttpStatusCode.OK, "session-token");
        var services = new ServiceCollection();
        services.AddCredProxTokenCache();
        services.AddCredProxConfigurationSecrets(configuration);
        services.AddCredProxBuiltInCredentials();
        services.AddHttpClient(OAuthClientCredentialsProvider.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => handler);
        services.AddCredProxCredentials(configuration);

        var registry = services.BuildServiceProvider().GetRequiredService<CredentialRegistry>();
        var binding = registry.Get("acme");

        var token = await binding.GetCredential(
            new CredentialRequestContext { CredentialName = "acme", Partition = "uat" }, default);

        Assert.Equal("session-token", token);
        Assert.Equal("http://vendor.example/uat/login", handler.Requests[0].RequestUri!.ToString());
    }

    [Fact]
    public void Registry_UnknownName_FailsClearly()
    {
        var configuration = Config(
            ("Credentials:key:Type", "StaticKey"),
            ("Credentials:key:Secret", "literal"),
            ("Credentials:key:Name", "X"));

        var registry = BuildServices(configuration).GetRequiredService<CredentialRegistry>();

        Assert.Equal(["key"], registry.Names);
        Assert.False(registry.TryGet("nope", out var missing));
        Assert.Null(missing);

        var error = Assert.Throws<InvalidOperationException>(() => registry.Get("nope"));
        Assert.Contains("nope", error.Message);
        Assert.Contains("CredProx:Credentials", error.Message);
    }

    [Fact]
    public void Registry_LookupsAreCaseInsensitive()
    {
        var configuration = Config(
            ("Credentials:ApiKey:Type", "StaticKey"),
            ("Credentials:ApiKey:Secret", "literal"),
            ("Credentials:ApiKey:Name", "X"));

        var registry = BuildServices(configuration).GetRequiredService<CredentialRegistry>();

        Assert.True(registry.TryGet("apikey", out var binding));
        Assert.Equal("ApiKey", binding!.Name);
    }

    [Fact]
    public void OAuthValidator_RejectsMissingOrRelativeEndpoint()
    {
        foreach (var endpoint in new string?[] { null, "not-a-url", "ftp://vendor.example/token" })
        {
            var configuration = Config(
                ("Credentials:oauth:Type", "OAuthClientCredentials"),
                ("Credentials:oauth:TokenEndpoint", endpoint),
                ("Credentials:oauth:ClientId", "id"));

            var error = Assert.Throws<OptionsValidationException>(() =>
                BuildServices(configuration).GetRequiredService<CredentialRegistry>());
            Assert.Contains("TokenEndpoint", error.Message);
        }
    }

    [Fact]
    public void LoginExchangeValidator_RejectsBothCredentialStylesAndMissingResponseField()
    {
        var configuration = Config(
            ("Credentials:login:Type", "LoginExchange"),
            ("Credentials:login:LoginEndpoint", "https://vendor.example/login"),
            ("Credentials:login:Basic:User", "u"),
            ("Credentials:login:Form:User", "u"),
            ("Credentials:login:Response", "JsonPath")); // no ResponseField

        var error = Assert.Throws<OptionsValidationException>(() =>
            BuildServices(configuration).GetRequiredService<CredentialRegistry>());

        Assert.Contains("mutually exclusive", error.Message);
        Assert.Contains("ResponseField", error.Message);
    }

    [Fact]
    public async Task CustomCredentialType_RegistersExplicitlyAndBinds()
    {
        var configuration = Config(("Credentials:custom:Type", "TestType"), ("Credentials:custom:Value", "hello"));

        var services = new ServiceCollection();
        services.AddCredProxTokenCache();
        services.AddCredProxConfigurationSecrets(configuration);
        services.AddCredProxCredentialType<TestProvider, TestOptions>("TestType");
        services.AddCredProxCredentials(configuration);

        var registry = services.BuildServiceProvider().GetRequiredService<CredentialRegistry>();
        var binding = registry.Get("custom");

        Assert.Equal("hello", await binding.GetCredential(
            new CredentialRequestContext { CredentialName = "custom" }, default));
        Assert.Null(binding.Attach); // options declare no attachment
    }

    [Fact]
    public void ProviderWithUnregisteredDependencies_FailsAsOptionsValidation()
    {
        var configuration = Config(("Credentials:needy:Type", "Needy"));

        var services = new ServiceCollection();
        services.AddCredProxTokenCache();
        services.AddCredProxConfigurationSecrets(configuration);
        services.AddCredProxCredentialType<NeedyProvider, NeedyOptions>("Needy");
        services.AddCredProxCredentials(configuration);

        // F5: a registered type whose own dependencies are unregistered is still a
        // startup binding failure, reported like the others — not a bare DI exception.
        var error = Assert.Throws<OptionsValidationException>(() =>
            services.BuildServiceProvider().GetRequiredService<CredentialRegistry>());

        Assert.Contains("needy", error.Message);
        Assert.Contains("cannot be constructed", error.Message);
    }

    // M16 (§3.3): keys the options type does not declare are silently ignored by section.Bind,
    // so they must fail startup naming the credential and the key — the M14a rule extended
    // from Callers to Credentials, with the allowed set derived from the options type.

    [Fact]
    public void UnknownCredentialKey_FailsStartupNamingCredentialAndKey()
    {
        var configuration = Config(
            ("Credentials:key:Type", "StaticKey"),
            ("Credentials:key:Secret", "literal"),
            ("Credentials:key:Name", "X"),
            ("Credentials:key:Extra", "oops"));

        var error = Assert.Throws<OptionsValidationException>(() =>
            BuildServices(configuration).GetRequiredService<CredentialRegistry>());

        Assert.Contains("'key'", error.Message);
        Assert.Contains("unknown configuration key 'Extra'", error.Message);
        Assert.Contains("Known keys", error.Message);
    }

    [Fact]
    public void MisspelledOptionalField_FailsStartupPointingAtTheRealKey()
    {
        // The M16 motivating case: "Scopee" binds to nothing, so without rejection the
        // credential would run without the scope its author meant to set.
        var configuration = Config(
            ("Credentials:oauth:Type", "OAuthClientCredentials"),
            ("Credentials:oauth:TokenEndpoint", "https://vendor.example/token"),
            ("Credentials:oauth:ClientId", "id"),
            ("Credentials:oauth:Scopee", "read"));

        var error = Assert.Throws<OptionsValidationException>(() =>
            BuildServices(configuration).GetRequiredService<CredentialRegistry>());

        Assert.Contains("'oauth'", error.Message);
        Assert.Contains("unknown configuration key 'Scopee'", error.Message);
        Assert.Contains("Scope", error.Message); // the known-keys list names the real key
    }

    [Fact]
    public void NestedUnknownKey_FailsStartupNamingTheNestedPath()
    {
        var configuration = Config(
            ("Credentials:oauth:Type", "OAuthClientCredentials"),
            ("Credentials:oauth:TokenEndpoint", "https://vendor.example/token"),
            ("Credentials:oauth:ClientId", "id"),
            ("Credentials:oauth:Partition:From", "header:X-Env"),
            ("Credentials:oauth:Partition:Allowed:0", "uat"),
            ("Credentials:oauth:Partition:Frm", "header:X-Env")); // typo of From

        var error = Assert.Throws<OptionsValidationException>(() =>
            BuildServices(configuration).GetRequiredService<CredentialRegistry>());

        Assert.Contains("unknown configuration key 'Partition:Frm'", error.Message);
        Assert.Contains("From", error.Message);
    }

    [Fact]
    public void NestedBlockUnderScalarKey_FailsStartup()
    {
        // Review F1: a Partition-shaped block written under the scalar Scope — the binder
        // reads Scope's (absent) value and drops From/Allowed in silence. A scalar takes a
        // single value; children under one are always a config mistake.
        var configuration = Config(
            ("Credentials:oauth:Type", "OAuthClientCredentials"),
            ("Credentials:oauth:TokenEndpoint", "https://vendor.example/token"),
            ("Credentials:oauth:ClientId", "id"),
            ("Credentials:oauth:Scope:From", "header:X-Env"),
            ("Credentials:oauth:Scope:Allowed:0", "uat"));

        var error = Assert.Throws<OptionsValidationException>(() =>
            BuildServices(configuration).GetRequiredService<CredentialRegistry>());

        Assert.Contains("'oauth'", error.Message);
        Assert.Contains("nested block under 'Scope'", error.Message);
        Assert.Contains("Scope:From", error.Message);
    }

    [Fact]
    public void ScalarValueWithNestedChild_FailsStartup()
    {
        // Belt-and-braces (review F1 repro 2): the scalar carries a value AND a child —
        // the value would bind and the child would vanish silently.
        var configuration = Config(
            ("Credentials:oauth:Type", "OAuthClientCredentials"),
            ("Credentials:oauth:TokenEndpoint", "https://vendor.example/token"),
            ("Credentials:oauth:ClientId", "id"),
            ("Credentials:oauth:Scope", "read"),
            ("Credentials:oauth:Scope:Extra", "x"));

        var error = Assert.Throws<OptionsValidationException>(() =>
            BuildServices(configuration).GetRequiredService<CredentialRegistry>());

        Assert.Contains("nested block under 'Scope'", error.Message);
        Assert.Contains("Scope:Extra", error.Message);
    }

    [Fact]
    public void NestedBlockUnderPresetKey_FailsStartup()
    {
        // Review round-2 one-liner: Preset is consumed as a value; a block under it would
        // read as "no preset" and the nested keys would vanish silently.
        var configuration = Config(
            ("Credentials:c:Type", "StaticKey"),
            ("Credentials:c:Secret", "literal"),
            ("Credentials:c:Name", "X"),
            ("Credentials:c:Preset:Name", "acme-oauth"));

        var error = Assert.Throws<OptionsValidationException>(() =>
            BuildServices(configuration).GetRequiredService<CredentialRegistry>());

        Assert.Contains("nested block under 'Preset'", error.Message);
        Assert.Contains("Preset:Name", error.Message);
    }

    [Fact]
    public void GetOnlyComputedKey_FailsStartup()
    {
        // OAuth's Location is a get-only computed property (always Header/Authorization):
        // the binder ignores it too, so declaring it in config must not look accepted.
        var configuration = Config(
            ("Credentials:oauth:Type", "OAuthClientCredentials"),
            ("Credentials:oauth:TokenEndpoint", "https://vendor.example/token"),
            ("Credentials:oauth:ClientId", "id"),
            ("Credentials:oauth:Location", "Header"));

        var error = Assert.Throws<OptionsValidationException>(() =>
            BuildServices(configuration).GetRequiredService<CredentialRegistry>());

        Assert.Contains("unknown configuration key 'Location'", error.Message);
    }

    [Fact]
    public void FullValidCredentialConfig_BindsEveryKey()
    {
        // The false-positive guard: every declared key of a rich section — scalars, enum,
        // TimeSpan, the nested Partition block and its leaf array — is accepted.
        var configuration = Config(
            ("Credentials:oauth:Type", "OAuthClientCredentials"),
            ("Credentials:oauth:TokenEndpoint", "https://vendor.example/token"),
            ("Credentials:oauth:ClientAuthentication", "FormPost"),
            ("Credentials:oauth:ClientId", "id"),
            ("Credentials:oauth:ClientSecret", "secret"),
            ("Credentials:oauth:Scope", "read"),
            ("Credentials:oauth:Audience", "api"),
            ("Credentials:oauth:DefaultLifetime", "00:30:00"),
            ("Credentials:oauth:TokenTypeName", ""),
            ("Credentials:oauth:Partition:From", "header:X-Env"),
            ("Credentials:oauth:Partition:Allowed:0", "uat"),
            ("Credentials:oauth:Partition:Allowed:1", "app"));

        var binding = BuildServices(configuration)
            .GetRequiredService<CredentialRegistry>()
            .Get("oauth");

        var options = Assert.IsType<OAuthClientCredentialsOptions>(binding.Options);
        Assert.Equal(OAuthClientAuthentication.FormPost, options.ClientAuthentication);
        Assert.Equal(TimeSpan.FromMinutes(30), options.DefaultLifetime);
        Assert.Equal(["uat", "app"], options.Partition!.Allowed);
    }

    [Fact]
    public void LeafArrayIndices_AreNotValidatedAsKeys()
    {
        // Components is a List<string>: its children are indices, not keys the options
        // type declares — any index is accepted.
        var configuration = Config(
            ("Credentials:signer:Type", "Hmac"),
            ("Credentials:signer:Secret", "literal"),
            ("Credentials:signer:SignatureHeader", "X-Signature"),
            ("Credentials:signer:Components:0", "method"),
            ("Credentials:signer:Components:1", "path"));

        var binding = BuildServices(configuration)
            .GetRequiredService<CredentialRegistry>()
            .Get("signer");

        Assert.Equal(["method", "path"], Assert.IsType<HmacOptions>(binding.Options).Components);
    }

    [Fact]
    public void CredentialKeys_AreMatchedCaseInsensitively()
    {
        // Configuration keys are case-insensitive; the validation must not invent a
        // false positive on a differently-cased spelling of a real key.
        var configuration = Config(
            ("Credentials:key:type", "StaticKey"),
            ("Credentials:key:secret", "literal"),
            ("Credentials:key:name", "X"));

        var binding = BuildServices(configuration)
            .GetRequiredService<CredentialRegistry>()
            .Get("key");

        Assert.Equal("StaticKey", binding.TypeName);
    }

    [Fact]
    public void PresetSuppliedUnknownKey_FailsStartup()
    {
        // Validation runs on the effective (post-compose) section, so a typo inside a
        // host preset is caught exactly like one the host wrote itself.
        var configuration = Config(
            ("Presets:acme-oauth:Type", "OAuthClientCredentials"),
            ("Presets:acme-oauth:TokenEndpoint", "https://accounts.acme.example/api/token"),
            ("Presets:acme-oauth:Scopee", "streaming"),
            ("Credentials:acme:Preset", "acme-oauth"),
            ("Credentials:acme:ClientId", "my-dev-app"));

        var error = Assert.Throws<OptionsValidationException>(() =>
            BuildServices(configuration).GetRequiredService<CredentialRegistry>());

        Assert.Contains("'acme'", error.Message);
        Assert.Contains("unknown configuration key 'Scopee'", error.Message);
    }

    [Fact]
    public void PluginTypeUnknownKey_FailsStartupNamingThePluginOptionsKey()
    {
        // A plugin declares its keys by having them on its options type: TestOptions.Value
        // is accepted (covered by CustomCredentialType_RegistersExplicitlyAndBinds), a typo
        // beside it is rejected with the plugin's own key list.
        var configuration = Config(
            ("Credentials:custom:Type", "TestType"),
            ("Credentials:custom:Value", "hello"),
            ("Credentials:custom:Valuee", "typo"));

        var services = new ServiceCollection();
        services.AddCredProxTokenCache();
        services.AddCredProxConfigurationSecrets(configuration);
        services.AddCredProxCredentialType<TestProvider, TestOptions>("TestType");
        services.AddCredProxCredentials(configuration);

        var error = Assert.Throws<OptionsValidationException>(() =>
            services.BuildServiceProvider().GetRequiredService<CredentialRegistry>());

        Assert.Contains("'custom'", error.Message);
        Assert.Contains("unknown configuration key 'Valuee'", error.Message);
        Assert.Contains("Value", error.Message);
    }

    private sealed class NeedyOptions;

    private interface ISomeUnregisteredDependency;

    private sealed class NeedyProvider : ICredentialProvider<NeedyOptions>
    {
        public NeedyProvider(ISomeUnregisteredDependency dependency) => _ = dependency;

        public string Type => "Needy";

        public ValueTask<string> GetCredentialAsync(
            NeedyOptions options,
            ISecretAccessor secrets,
            CredentialRequestContext context,
            CancellationToken cancellationToken) => new(string.Empty);
    }

    private sealed class TestOptions
    {
        public string? Value { get; set; }
    }

    private sealed class TestProvider : ICredentialProvider<TestOptions>
    {
        public string Type => "TestType";

        public ValueTask<string> GetCredentialAsync(
            TestOptions options,
            ISecretAccessor secrets,
            CredentialRequestContext context,
            CancellationToken cancellationToken) => new(options.Value ?? string.Empty);
    }
}
