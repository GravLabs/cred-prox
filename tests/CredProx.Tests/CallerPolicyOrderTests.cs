using CredProx;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// Pins the ordering contract of <c>AddCredProxCallerPolicy</c>: a host-defined
/// <c>CredProxAuth.CallerPolicy</c> wins in EITHER order — CredProx skips registering
/// the policy when the name already carries one, and a host definition added afterwards
/// still overwrites. Host-first like ADR-0006, whatever the registration order.
/// </summary>
public sealed class CallerPolicyOrderTests
{
    private const string HostMarkerClaim = "credprox-test:host-marker";

    [Fact]
    public async Task HostPolicyDefinedBeforeCredProxCall_IsKept()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuthentication();
        services.AddAuthorization(options => options.AddPolicy(
            CredProxAuth.CallerPolicy,
            policy => policy.RequireClaim(HostMarkerClaim)));
        services.AddCredProxCallerPolicy();

        var policy = await ResolvePolicy(services);

        Assert.Contains(HostMarkerClaim, ClaimTypesOf(policy));
        Assert.DoesNotContain(CredProxAuth.CallerKeyScheme, policy.AuthenticationSchemes);
        Assert.DoesNotContain(CredProxAuth.CallerTokenScheme, policy.AuthenticationSchemes);
    }

    [Fact]
    public async Task NoHostPolicy_CredProxRegistersItsPolicy()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuthentication();
        services.AddCredProxCallerPolicy();

        var policy = await ResolvePolicy(services);

        Assert.Contains(CredProxAuth.CallerKeyScheme, policy.AuthenticationSchemes);
        Assert.Contains(CredProxAuth.CallerTokenScheme, policy.AuthenticationSchemes);
    }

    [Fact]
    public async Task HostPolicyDefinedAfterCredProxCall_Wins()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuthentication();
        services.AddCredProxCallerPolicy();
        services.AddAuthorization(options => options.AddPolicy(
            CredProxAuth.CallerPolicy,
            policy => policy.RequireClaim(HostMarkerClaim)));

        var policy = await ResolvePolicy(services);

        Assert.Contains(HostMarkerClaim, ClaimTypesOf(policy));
        Assert.DoesNotContain(CredProxAuth.CallerKeyScheme, policy.AuthenticationSchemes);
        Assert.DoesNotContain(CredProxAuth.CallerTokenScheme, policy.AuthenticationSchemes);
    }

    private static IEnumerable<string> ClaimTypesOf(AuthorizationPolicy policy) =>
        policy.Requirements.OfType<ClaimsAuthorizationRequirement>().Select(r => r.ClaimType);

    private static async Task<AuthorizationPolicy> ResolvePolicy(ServiceCollection services)
    {
        using var provider = services.BuildServiceProvider();
        var policy = await provider
            .GetRequiredService<IAuthorizationPolicyProvider>()
            .GetPolicyAsync(CredProxAuth.CallerPolicy);
        Assert.NotNull(policy);
        return policy;
    }
}
