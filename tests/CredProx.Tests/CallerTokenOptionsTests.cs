using CredProx;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M39 outcome A (ADR-0004): the caller-token options surface and its registration. The
/// validation layer is the stock JWT bearer handler under a CredProx scheme name, configured
/// from <c>CredProx:CallerToken</c>; like CallerAuth (M14a) a typo here fails closed —
/// silently validating against the wrong issuer or audience is the worst shape of it.
/// </summary>
public sealed class CallerTokenOptionsTests
{
    private static IConfiguration Config(params KeyValuePair<string, string?>[] rows) =>
        new ConfigurationBuilder().AddInMemoryCollection(rows).Build();

    private static KeyValuePair<string, string?> Row(string key, string? value) =>
        new(key, value);

    private static IConfiguration ValidConfig() => Config(
        Row("CredProx:CallerToken:Authority", "https://login.microsoftonline.com/tenant-id/v2.0"),
        Row("CredProx:CallerToken:Audience", "api://credprox"));

    [Fact]
    public async Task TokenScheme_RegistersJwtBearerHandler_UnderTheCredProxSchemeName()
    {
        // Swap-point contract (ADR-0004): validation is the framework handler under a
        // CredProx scheme name. Replace the scheme, keep everything above it.
        var services = new ServiceCollection();
        services.AddCredProxCallerTokenAuthentication(ValidConfig());
        using var provider = services.BuildServiceProvider();

        var scheme = await provider
            .GetRequiredService<IAuthenticationSchemeProvider>()
            .GetSchemeAsync(CredProxAuth.CallerTokenScheme);

        Assert.NotNull(scheme);
        Assert.Equal(typeof(JwtBearerHandler), scheme.HandlerType);
    }

    [Fact]
    public void TokenScheme_CarriesAuthorityAndAudience_ToTheBearerOptions()
    {
        var services = new ServiceCollection();
        services.AddCredProxCallerTokenAuthentication(ValidConfig());
        using var provider = services.BuildServiceProvider();

        var bearer = provider
            .GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(CredProxAuth.CallerTokenScheme);

        Assert.Equal("https://login.microsoftonline.com/tenant-id/v2.0", bearer.Authority);
        Assert.Equal("api://credprox", bearer.Audience);
    }

    [Fact]
    public void MissingAuthority_FailsRegistration()
    {
        // A token scheme without an authority validates against nothing pinned — refuse.
        var services = new ServiceCollection();
        var config = Config(Row("CredProx:CallerToken:Audience", "api://credprox"));

        var ex = Assert.Throws<OptionsValidationException>(
            () => services.AddCredProxCallerTokenAuthentication(config));

        Assert.Contains(ex.Failures, f => f.Contains("Authority", StringComparison.Ordinal));
    }

    [Fact]
    public void MissingAudience_FailsRegistration()
    {
        var services = new ServiceCollection();
        var config = Config(Row(
            "CredProx:CallerToken:Authority",
            "https://login.microsoftonline.com/tenant-id/v2.0"));

        var ex = Assert.Throws<OptionsValidationException>(
            () => services.AddCredProxCallerTokenAuthentication(config));

        Assert.Contains(ex.Failures, f => f.Contains("Audience", StringComparison.Ordinal));
    }

    [Fact]
    public void UnknownKey_FailsRegistration_NamingTheKey()
    {
        // M14a shape: "Audiencee" must not silently keep the (refused) default — the whole
        // point of the fail-closed CallerAuth precedent applied to the new section.
        var services = new ServiceCollection();
        var config = Config(
            Row("CredProx:CallerToken:Authority", "https://login.microsoftonline.com/tenant-id/v2.0"),
            Row("CredProx:CallerToken:Audience", "api://credprox"),
            Row("CredProx:CallerToken:Audiencee", "api://typo"));

        var ex = Assert.Throws<OptionsValidationException>(
            () => services.AddCredProxCallerTokenAuthentication(config));

        // Full text: the unknown key named AND the known-key guidance — half a message
        // reads like a different mistake.
        Assert.Contains(
            ex.Failures,
            f => f.Contains("'Audiencee'", StringComparison.Ordinal)
                && f.Contains("Audience", StringComparison.Ordinal));
    }

    [Fact]
    public void MaxTokenAge_BareNumber_RefusesRegistration_NamingTheFormat()
    {
        // D-F3 (verdict D): a bare '15' binds as 15 DAYS (TimeSpan's default numeric
        // format is days) — the limit was silently ~1440x wider than the operator meant.
        var services = new ServiceCollection();
        var config = Config(
            Row("CredProx:CallerToken:Authority", "https://login.microsoftonline.com/tenant-id/v2.0"),
            Row("CredProx:CallerToken:Audience", "api://credprox"),
            Row("CredProx:CallerToken:MaxTokenAge", "15"));

        var ex = Assert.Throws<OptionsValidationException>(
            () => services.AddCredProxCallerTokenAuthentication(config));

        Assert.Contains(
            ex.Failures,
            f => f.Contains("MaxTokenAge", StringComparison.Ordinal)
                && f.Contains("00:15:00", StringComparison.Ordinal));
    }

    [Fact]
    public void MaxTokenAge_NonPositive_RefusesRegistration()
    {
        // A negative limit 401s every caller token forever behind a generic detail;
        // zero is the same lockout without the typo. Refused at registration like the
        // unknown-key/garbage family already is (D-F3).
        var services = new ServiceCollection();
        var config = Config(
            Row("CredProx:CallerToken:Authority", "https://login.microsoftonline.com/tenant-id/v2.0"),
            Row("CredProx:CallerToken:Audience", "api://credprox"),
            Row("CredProx:CallerToken:MaxTokenAge", "-00:15:00"));

        var ex = Assert.Throws<OptionsValidationException>(
            () => services.AddCredProxCallerTokenAuthentication(config));

        Assert.Contains(ex.Failures, f => f.Contains("MaxTokenAge", StringComparison.Ordinal));
    }

    [Fact]
    public void MaxTokenAge_Exactly24Hours_RefusesRegistration()
    {
        // The upper gate at its exact boundary: 24 h is refused, below stays legal.
        var services = new ServiceCollection();
        var config = Config(
            Row("CredProx:CallerToken:Authority", "https://login.microsoftonline.com/tenant-id/v2.0"),
            Row("CredProx:CallerToken:Audience", "api://credprox"),
            Row("CredProx:CallerToken:MaxTokenAge", "24:00:00"));

        var ex = Assert.Throws<OptionsValidationException>(
            () => services.AddCredProxCallerTokenAuthentication(config));

        Assert.Contains(ex.Failures, f => f.Contains("MaxTokenAge", StringComparison.Ordinal));
    }

    [Fact]
    public void MaxTokenAge_JustUnder24Hours_Registers()
    {
        // Control for the boundary: the largest legal value still binds.
        var services = new ServiceCollection();
        var config = Config(
            Row("CredProx:CallerToken:Authority", "https://login.microsoftonline.com/tenant-id/v2.0"),
            Row("CredProx:CallerToken:Audience", "api://credprox"),
            Row("CredProx:CallerToken:MaxTokenAge", "23:59:59"));

        services.AddCredProxCallerTokenAuthentication(config);
    }

    [Fact]
    public void DefaultClaimNames_AzpThenAppid_AndRolesThenScp()
    {
        // v2 tokens carry azp/roles; v1 tokens carry appid. The defaults are the Entra
        // shapes; the lists exist so another OIDC issuer can be met without code.
        var services = new ServiceCollection();
        services.AddCredProxCallerTokenAuthentication(ValidConfig());
        using var provider = services.BuildServiceProvider();

        var options = provider.GetRequiredService<CallerTokenOptions>();

        Assert.Equal(["azp", "appid"], options.ClientClaimNames);
        // Raw names only (M39 fold F3): the caller-token scheme sets MapInboundClaims =
        // false, so the stock handler never renames roles/scp to the long claim types and
        // the mapped URIs would match nothing on any real token.
        Assert.Equal(["roles", "scp"], options.ScopeClaimNames);
    }

    [Fact]
    public void MaxTokenAge_BindsFromConfig()
    {
        var services = new ServiceCollection();
        var config = Config(
            Row("CredProx:CallerToken:Authority", "https://login.microsoftonline.com/tenant-id/v2.0"),
            Row("CredProx:CallerToken:Audience", "api://credprox"),
            Row("CredProx:CallerToken:MaxTokenAge", "00:15:00"));
        services.AddCredProxCallerTokenAuthentication(config);
        using var provider = services.BuildServiceProvider();

        Assert.Equal(TimeSpan.FromMinutes(15), provider.GetRequiredService<CallerTokenOptions>().MaxTokenAge);
    }

    [Fact]
    public async Task CallerPolicy_ListsBothCallerSchemes_EitherAuthenticates()
    {
        // The single caller policy must name both schemes so a middleware-fronted host
        // authenticates a bearer token or a caller key alike. An unregistered scheme is
        // AuthenticateResult.NoResult, not a throw — so naming both is safe everywhere.
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = "sha256:" + new string('a', 64),
            ["CredProx:CallerToken:Authority"] = "https://login.microsoftonline.com/tenant-id/v2.0",
            ["CredProx:CallerToken:Audience"] = "api://credprox",
        }).Build();
        var services = new ServiceCollection();
        services.AddCredProxConfigurationSecrets(config);
        services.AddCredProxCallerAuthentication(config);
        services.AddCredProxCallerTokenAuthentication(config);
        using var provider = services.BuildServiceProvider();

        var policy = await provider
            .GetRequiredService<IAuthorizationPolicyProvider>()
            .GetPolicyAsync(CredProxAuth.CallerPolicy);

        Assert.NotNull(policy);
        Assert.Contains(CredProxAuth.CallerKeyScheme, policy.AuthenticationSchemes);
        Assert.Contains(CredProxAuth.CallerTokenScheme, policy.AuthenticationSchemes);
    }
}
