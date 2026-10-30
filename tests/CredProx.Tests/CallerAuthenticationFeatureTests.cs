using System.Security.Cryptography;
using System.Text;
using CredProx;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The <see cref="Stage.AuthenticateCaller"/> feature (§3.5 rule 3, §4 Phase B): once
/// caller authentication is registered every proxied route requires an authenticated
/// caller unless the route opts out; a rejected request aborts with the §3.4 401 problem
/// document before any later stage runs, and the key value never appears in the response.
/// </summary>
public sealed class CallerAuthenticationFeatureTests
{
    private const string Key = "feature-test-key";

    [Fact]
    public async Task ValidKey_Succeeds_PublishesIdentityAndUser()
    {
        var context = Context(key: Key);

        await Feature(context).ApplyAsync(context, default);

        var state = context.Features.Get<CredProxRequestState>()!;
        Assert.False(state.IsAborted);
        Assert.Equal(new CallerIdentity("app-a", "k1"), context.Features.Get<CallerIdentity>());
        Assert.True(context.User.Identity!.IsAuthenticated);
    }

    [Fact]
    public async Task MissingKey_401Problem()
    {
        var context = Context(key: null);

        await Feature(context).ApplyAsync(context, default);

        AssertRejected(context);
    }

    [Fact]
    public async Task UnknownKey_401Problem_KeyValueNotLeaked()
    {
        var context = Context(key: "wrong-value-entirely");

        await Feature(context).ApplyAsync(context, default);

        AssertRejected(context);
        Assert.DoesNotContain("wrong-value-entirely", M4Contexts.ResponseBody(context));
    }

    [Fact]
    public async Task AnonymousRoute_SkipsAuthentication()
    {
        var context = Context(
            key: null,
            routeMetadata: new Dictionary<string, string>
            {
                [CredProxMetadata.Caller] = CallerAuthenticationFeature.AnonymousValue,
            });

        await Feature(context).ApplyAsync(context, default);

        var state = context.Features.Get<CredProxRequestState>()!;
        Assert.False(state.IsAborted);
        Assert.Null(context.Features.Get<CallerIdentity>());
    }

    [Fact]
    public async Task RouteMetadataOtherValue_StillRequiresCaller()
    {
        var context = Context(
            key: null,
            routeMetadata: new Dictionary<string, string> { [CredProxMetadata.Caller] = "anything-else" });

        await Feature(context).ApplyAsync(context, default);

        AssertRejected(context);
    }

    private static bool Aborted(DefaultHttpContext context) =>
        context.Features.Get<CredProxRequestState>()!.IsAborted;

    private static void AssertRejected(DefaultHttpContext context)
    {
        Assert.True(Aborted(context));
        Assert.Equal(401, context.Response.StatusCode);
        var body = M4Contexts.ResponseBody(context);
        Assert.Contains("application/problem+json", context.Response.ContentType);
        Assert.Contains("credprox.caller_unauthenticated", body);
    }

    private static CallerAuthenticationFeature Feature(DefaultHttpContext context) => new();

    private static DefaultHttpContext Context(
        string? key, Dictionary<string, string>? routeMetadata = null)
    {
        var context = M4Contexts.Create(out var proxyRequest, routeMetadata: routeMetadata);
        if (key is not null)
        {
            context.Request.Headers["X-CredProx-Key"] = key;
        }

        var entries = new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] =
                "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Key))).ToLowerInvariant(),
        };
        var config = new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
        var secretSource = new ConfigurationSecretSource(config);
        var registryProvider = new CallerRegistryProvider(
            new CallerBinder(config, new SecretAccessorFactory(secretSource)),
            secretSource,
            NullLogger<CallerRegistryProvider>.Instance);

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        services.AddSingleton<ICallerStore>(new ConfigCallerStore(registryProvider, TimeProvider.System));
        services.AddAuthentication()
            .AddScheme<CallerKeyOptions, CallerKeyAuthenticationHandler>(
                CredProxAuth.CallerKeyScheme, _ => { });
        context.RequestServices = services.BuildServiceProvider();
        return context;
    }
}
