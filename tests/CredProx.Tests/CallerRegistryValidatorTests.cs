using CredProx;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;
using Yarp.ReverseProxy.Configuration;

namespace CredProx.Tests;

/// <summary>
/// The token client-id rules travel with the CredProx.CallerTokens package but are
/// enforced where the caller registry lives: the core runs the package's rules at host
/// start AND on every live rebind, and a refused rebind keeps the previous registry
/// serving. These are the live-edit cells (A2/A5/A6 shapes) the package split restores.
/// The seam-generic cells register a test's own validator through the public extension
/// with no token package in sight: the guarantee belongs to the core, not to one
/// package's rules.
/// </summary>
/// <remarks>
/// The two startup cells witness TIMING: the same configuration was already refused
/// before the split, at the <c>AddCredProxCallerTokenAuthentication</c> call itself
/// (during <c>Build()</c>); now it is refused at host start instead. The rebind cells
/// carry the guarantee a registration-time check never had: the configuration can drift
/// into a refused shape after the host started, and the drift must not take effect.
/// </remarks>
public sealed class CallerRegistryValidatorTests
{
    private const string Key = "registry-validator-test-key-1";

    private static readonly RouteConfig PlainRoute = new()
    {
        RouteId = "plain",
        ClusterId = "acme",
        Match = new RouteMatch { Path = "/plain/{**catch-all}" },
        Metadata = new Dictionary<string, string> { [CredProxMetadata.Destination] = "acme" },
    };

    private static readonly ClusterConfig AcmeCluster = new()
    {
        ClusterId = "acme",
        Destinations = new Dictionary<string, DestinationConfig>
        {
            ["static"] = new() { Address = "http://upstream.example/" },
        },
    };

    private static string Hash(string value) =>
        "sha256:" + Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private static Dictionary<string, string?> BaseEntries() => new()
    {
        ["CredProx:CallerToken:Authority"] = "https://idp.example",
        ["CredProx:CallerToken:Audience"] = "credprox-api",
        ["CredProx:Callers:agent-1:Keys:0:KeyId"] = "k1",
        ["CredProx:Callers:agent-1:Keys:0:KeyHash"] = Hash(Key),
        ["CredProx:Destinations:acme:Template"] = "http://upstream.example/",
    };

    private static IHostBuilder ProxyHost(
        IConfiguration config,
        bool keyExt,
        bool tokenExt,
        List<string?>? logs = null,
        Action<IServiceCollection>? extra = null)
    {
        var builder = new HostBuilder()
            .ConfigureAppConfiguration(build => build.AddConfiguration(config))
            .ConfigureServices(services =>
            {
                services.AddCredProxTokenCache();
                services.AddCredProxConfigurationSecrets(config);
                services.AddCredProxBuiltInCredentials();
                services.AddCredProxCredentials(config);
                if (keyExt)
                {
                    services.AddCredProxCallerAuthentication(config);
                }

                if (tokenExt)
                {
                    services.AddCredProxCallerTokenAuthentication(config);
                }

                extra?.Invoke(services);

                services.AddRouting();
                services.AddReverseProxy().LoadFromMemory([PlainRoute], [AcmeCluster]).AddCredProx(config);
            })
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints => endpoints.MapReverseProxy());
                });
            });

        if (logs is not null)
        {
            builder.ConfigureLogging(logging => logging.AddProvider(new CapturingLoggerProvider(logs)));
        }

        return builder;
    }

    // ---------------------------------------------------------------- startup timing

    [Fact]
    public async Task PaddedTokenClientId_TokenPackageRegistered_RefusedAtHostStart()
    {
        // The padding rule runs at host start now, not inside the registration call:
        // Build() must stay clean and StartAsync must refuse, naming the padded entry.
        // (Before the split this exact config threw at Build() instead.)
        var entries = BaseEntries();
        entries["CredProx:Callers:agent-1:TokenClientIds:0"] = " client-abc ";
        var config = new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
        using var host = ProxyHost(config, keyExt: true, tokenExt: true).Build();

        var ex = await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync(default));
        Assert.Contains("leading or trailing whitespace", ex.Message);
    }

    [Fact]
    public async Task TwoOwnersForOneClientId_TokenPackageRegistered_RefusedAtHostStart()
    {
        // One Entra app (case-insensitive collision) claimed by two callers: the token
        // would authenticate as whichever registry position wins — refused, not guessed.
        var entries = BaseEntries();
        entries["CredProx:Callers:agent-1:TokenClientIds:0"] = "shared-client";
        entries["CredProx:Callers:agent-2:Keys:0:KeyId"] = "k2";
        entries["CredProx:Callers:agent-2:Keys:0:KeyHash"] = Hash(Key + "-2");
        entries["CredProx:Callers:agent-2:TokenClientIds:0"] = "SHARED-CLIENT";
        var config = new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
        using var host = ProxyHost(config, keyExt: true, tokenExt: true).Build();

        var ex = await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync(default));
        Assert.Contains("is listed by more than one caller ('agent-1' and 'agent-2')", ex.Message);
    }

    // ---------------------------------------------------------------- live rebind

    [Fact]
    public async Task LiveEdit_AddsSecondOwnerAndNewCaller_RebindRefused_PreviousRegistryKeepsServing()
    {
        // The differential witness (A6): one live edit that adds a brand-new caller AND
        // makes an existing client id two-owned. The whole rebind is refused — the new
        // caller never appears, the previous registry keeps serving — and the operator
        // sees the offending caller and client id, not only the generic rebind failure.
        var entries = BaseEntries();
        entries["CredProx:Callers:agent-1:TokenClientIds:0"] = "shared-client";
        var config = new ConfigurationBuilder()
            .Add(new ReloadableMemoryConfigurationSource(entries))
            .Build();
        var provider = (ReloadableMemoryConfigurationProvider)config.Providers
            .OfType<ReloadableMemoryConfigurationProvider>().Single();
        var logs = new List<string?>();
        using var host = ProxyHost(config, keyExt: true, tokenExt: true, logs).Build();
        await host.StartAsync(default);

        var registryProvider = host.Services.GetRequiredService<CallerRegistryProvider>();
        var before = registryProvider.Current;

        provider.Set("CredProx:Callers:agent-9:Keys:0:KeyId", "k9");
        provider.Set("CredProx:Callers:agent-9:Keys:0:KeyHash", Hash(Key + "-9"));
        provider.Set("CredProx:Callers:agent-9:TokenClientIds:0", "SHARED-CLIENT");
        provider.Reload();
        await Task.Delay(250);

        Assert.Same(before, registryProvider.Current);
        Assert.DoesNotContain("agent-9", registryProvider.Current.CallerIds);
        Assert.Contains(logs, line => line!.Contains("keeping the previous registry"));
        Assert.Contains(
            logs,
            line => line!.Contains("SHARED-CLIENT") && line!.Contains("listed by more than one caller"));
        await host.StopAsync();
    }

    [Fact]
    public async Task LiveEdit_SecondOwnerForListedClient_RebindRefused_MapperKeepsOriginalOwner()
    {
        // The A5 half: the edit that silently creates two owners for one client id must
        // be refused at the rebind, so the mapper's answer for that token cannot change
        // under the operator — the original owner keeps serving until the config is fixed.
        var entries = BaseEntries();
        entries["CredProx:Callers:agent-1:TokenClientIds:0"] = "shared-client";
        entries["CredProx:Callers:agent-2:Keys:0:KeyId"] = "k2";
        entries["CredProx:Callers:agent-2:Keys:0:KeyHash"] = Hash(Key + "-2");
        var config = new ConfigurationBuilder()
            .Add(new ReloadableMemoryConfigurationSource(entries))
            .Build();
        var provider = (ReloadableMemoryConfigurationProvider)config.Providers
            .OfType<ReloadableMemoryConfigurationProvider>().Single();
        using var host = ProxyHost(config, keyExt: true, tokenExt: true).Build();
        await host.StartAsync(default);

        var mapper = host.Services.GetRequiredService<ICallerTokenMapper>();
        var registryProvider = host.Services.GetRequiredService<CallerRegistryProvider>();
        var principal = new System.Security.Claims.ClaimsPrincipal(new System.Security.Claims.ClaimsIdentity(
            [new System.Security.Claims.Claim("azp", "shared-client"), new System.Security.Claims.Claim("roles", "plain-read")], "test"));

        var beforeMapping = mapper.MapToken(principal);
        Assert.Equal("agent-1", beforeMapping?.Identity.CallerId);
        var before = registryProvider.Current;

        provider.Set("CredProx:Callers:agent-2:TokenClientIds:0", "SHARED-CLIENT");
        provider.Reload();
        await Task.Delay(250);

        Assert.Same(before, registryProvider.Current);
        var afterMapping = mapper.MapToken(principal);
        Assert.Equal("agent-1", afterMapping?.Identity.CallerId);
        await host.StopAsync();
    }

    // ---------------------------------------------------------------- seam, generic

    private sealed class RefusesBadCaller : ICallerRegistryValidator
    {
        public IReadOnlyList<string> Validate(IReadOnlyList<CallerRegistryEntry> callers) =>
            [.. callers
                .Where(caller => caller.CallerId.Equals("agent-bad", StringComparison.Ordinal))
                .Select(caller => $"The caller '{caller.CallerId}' is refused by the test sentinel rule.")];
    }

    [Fact]
    public async Task CustomValidator_RefusedCallerId_BuildStaysCleanAndStartRefuses()
    {
        // The seam is the core's, not the token package's: a validator registered through
        // AddCredProxCallerRegistryValidator alone runs at host start. No token package
        // registered here — only the key extension.
        var entries = BaseEntries();
        entries["CredProx:Callers:agent-bad:Keys:0:KeyId"] = "kb";
        entries["CredProx:Callers:agent-bad:Keys:0:KeyHash"] = Hash(Key + "-bad");
        var config = new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
        using var host = ProxyHost(
            config, keyExt: true, tokenExt: false,
            extra: services => services.AddCredProxCallerRegistryValidator<RefusesBadCaller>()).Build();

        var ex = await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync(default));
        Assert.Contains("test sentinel rule", ex.Message);
    }

    [Fact]
    public async Task CustomValidator_LiveEdit_RebindRefused_OldRegistryStaysServing()
    {
        // The same seam on the live path: a validator a host contributed itself refuses a
        // mid-flight edit, the previous registry keeps serving, and the operator sees the
        // validator's own reason, not just the generic rebind failure.
        var config = new ConfigurationBuilder()
            .Add(new ReloadableMemoryConfigurationSource(BaseEntries()))
            .Build();
        var provider = (ReloadableMemoryConfigurationProvider)config.Providers
            .OfType<ReloadableMemoryConfigurationProvider>().Single();
        var logs = new List<string?>();
        using var host = ProxyHost(
            config, keyExt: true, tokenExt: false, logs,
            extra: services => services.AddCredProxCallerRegistryValidator<RefusesBadCaller>()).Build();
        await host.StartAsync(default);

        var registryProvider = host.Services.GetRequiredService<CallerRegistryProvider>();
        var before = registryProvider.Current;

        provider.Set("CredProx:Callers:agent-bad:Keys:0:KeyId", "kb");
        provider.Set("CredProx:Callers:agent-bad:Keys:0:KeyHash", Hash(Key + "-bad"));
        provider.Reload();
        await Task.Delay(250);

        Assert.Same(before, registryProvider.Current);
        Assert.DoesNotContain("agent-bad", registryProvider.Current.CallerIds);
        Assert.Contains(logs, line => line!.Contains("keeping the previous registry"));
        Assert.Contains(logs, line => line!.Contains("test sentinel rule"));
        await host.StopAsync();
    }

    // ---------------------------------------------------------------- ruled limit

    [Fact]
    public async Task TokenClientIds_WithoutTokenPackage_StartClean_AndClientCannotAuthenticate()
    {
        // The accepted limit of the split, stated here so the narrowing is tested, not
        // implied: the client-id rules live with the package that matches them. A host
        // that never registers CredProx.CallerTokens starts clean even with padded or
        // colliding TokenClientIds entries — they are inert, no client id can
        // authenticate (there is no token layer), and the key path is untouched.
        var entries = BaseEntries();
        entries["CredProx:Callers:agent-1:TokenClientIds:0"] = " client-abc ";
        var config = new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
        using var host = ProxyHost(config, keyExt: true, tokenExt: false).Build();
        await host.StartAsync(default);

        // The configured key still authenticates and the request reaches the forwarder
        // (BadGateway = it was admitted and failed at the nonexistent example upstream;
        // an unauthenticated caller would have stopped at 401 before forwarding).
        var keyed = new HttpRequestMessage(HttpMethod.Get, "http://proxy/plain/thing");
        keyed.Headers.Add("X-CredProx-Key", Key);
        var keyedResponse = await host.GetTestClient().SendAsync(keyed);
        Assert.NotEqual(System.Net.HttpStatusCode.Unauthorized, keyedResponse.StatusCode);

        // And no bearer path exists: the padded entry admits nobody because the whole
        // token layer is absent.
        var bearer = new HttpRequestMessage(HttpMethod.Get, "http://proxy/plain/thing");
        bearer.Headers.Add("Authorization", "Bearer not-a-real-token");
        var bearerResponse = await host.GetTestClient().SendAsync(bearer);
        Assert.Equal(System.Net.HttpStatusCode.Unauthorized, bearerResponse.StatusCode);

        await host.StopAsync();
    }
}
