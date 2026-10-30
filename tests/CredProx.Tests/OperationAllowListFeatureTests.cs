using System.Security.Cryptography;
using System.Text;
using CredProx;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Model;

namespace CredProx.Tests;

/// <summary>
/// The <see cref="Stage.AuthorizeOperation"/> feature (§4 Phase B, §5.2 "Operation
/// allow-lists"): declared callers are admitted only by route/method/path match, hostile
/// path shapes are refused before any pattern is consulted, and undeclared callers and
/// anonymous requests pass through untouched.
/// </summary>
public sealed class OperationAllowListFeatureTests
{
    private sealed record Rule(string? Route = null, string[]? Methods = null, string[]? Paths = null);

    [Fact]
    public async Task CallerWithoutOperations_IsUnrestricted()
    {
        var (feature, context) = Setup(
            operations: null,
            identity: new CallerIdentity("app-a", "k1"),
            path: "/anything/at/all");

        await feature.ApplyAsync(context, default);

        Assert.False(Aborted(context));
    }

    [Fact]
    public async Task NoCallerIdentity_IsLeftToAuthenticationStage()
    {
        // Anonymous routes and hosts without caller auth: the feature must not invent a 403.
        var (feature, context) = Setup(
            operations: [new Rule("reports", ["GET"], ["/reports/*"])],
            identity: null,
            path: "/secret");

        await feature.ApplyAsync(context, default);

        Assert.False(Aborted(context));
    }

    [Fact]
    public async Task MatchingRouteMethodPath_IsAdmitted()
    {
        var (feature, context) = Setup(
            operations: [new Rule("reports", ["GET"], ["/reports/*"])],
            identity: new CallerIdentity("app-a", "k1"),
            path: "/reports/q1",
            routeId: "reports");

        await feature.ApplyAsync(context, default);

        Assert.False(Aborted(context));
    }

    [Fact]
    public async Task WrongMethod_403()
    {
        var (feature, context) = Setup(
            operations: [new Rule("reports", ["GET"], ["/reports/*"])],
            identity: new CallerIdentity("app-a", "k1"),
            path: "/reports/q1",
            routeId: "reports",
            method: "POST");

        await feature.ApplyAsync(context, default);

        AssertRejected(context);
    }

    [Fact]
    public async Task WrongPath_403()
    {
        var (feature, context) = Setup(
            operations: [new Rule("reports", ["GET"], ["/reports/*"])],
            identity: new CallerIdentity("app-a", "k1"),
            path: "/admin/users",
            routeId: "reports");

        await feature.ApplyAsync(context, default);

        AssertRejected(context);
    }

    [Fact]
    public async Task WrongRoute_403()
    {
        var (feature, context) = Setup(
            operations: [new Rule("reports", ["GET"], ["/reports/*"])],
            identity: new CallerIdentity("app-a", "k1"),
            path: "/reports/q1",
            routeId: "other");

        await feature.ApplyAsync(context, default);

        AssertRejected(context);
    }

    [Fact]
    public async Task RoutelessRule_AppliesToAnyRoute()
    {
        var (feature, context) = Setup(
            operations: [new Rule(null, ["GET"], ["/reports/*"])],
            identity: new CallerIdentity("app-a", "k1"),
            path: "/reports/q1",
            routeId: "whatever");

        await feature.ApplyAsync(context, default);

        Assert.False(Aborted(context));
    }

    [Theory]
    [InlineData("/a/../admin")]
    [InlineData("/a/./admin")]
    [InlineData("/../admin")]
    public async Task TraversalPath_403_EvenWhenItWouldMatch(string path)
    {
        // A rule that would match the *resolved* shape must still refuse the traversal
        // shape: /a/../admin must not sneak into /**.
        var (feature, context) = Setup(
            operations: [new Rule(null, ["GET"], ["/**"])],
            identity: new CallerIdentity("app-a", "k1"),
            path: path);

        await feature.ApplyAsync(context, default);

        AssertRejected(context);
    }

    [Fact]
    public async Task CaseTrick_DoesNotMatch()
    {
        var (feature, context) = Setup(
            operations: [new Rule(null, ["GET"], ["/Reports"])],
            identity: new CallerIdentity("app-a", "k1"),
            path: "/reports");

        await feature.ApplyAsync(context, default);

        AssertRejected(context);
    }

    [Fact]
    public async Task CallerRevokedBetweenStages_FailsClosed()
    {
        // Authenticated identity whose caller is gone from the live registry (rebind race
        // net): the request is refused, not served under a stale identity.
        var context = Context("/reports", new CallerIdentity("app-a", "k1"));
        var emptyProvider = Registry([("app-gone", null)]);

        await new OperationAllowListFeature(emptyProvider).ApplyAsync(context, default);

        AssertRejected(context);
    }

    private static bool Aborted(DefaultHttpContext context) =>
        context.Features.Get<CredProxRequestState>()!.IsAborted;

    private static void AssertRejected(DefaultHttpContext context)
    {
        Assert.True(Aborted(context));
        Assert.Equal(403, context.Response.StatusCode);
        var body = M4Contexts.ResponseBody(context);
        Assert.Contains("credprox.operation_not_allowed", body);
    }

    private static (OperationAllowListFeature Feature, DefaultHttpContext Context) Setup(
        Rule[]? operations,
        CallerIdentity? identity,
        string path,
        string? routeId = null,
        string method = "GET")
    {
        // The caller always exists; operations: null means it declares no allow-list.
        (string Caller, Rule[]? Operations)[] callers = [("app-a", operations)];

        var provider = Registry(callers);
        var feature = new OperationAllowListFeature(provider);
        var context = Context(path, identity, routeId, method);
        return (feature, context);
    }

    private static DefaultHttpContext Context(
        string path, CallerIdentity? identity, string? routeId = null, string method = "GET")
    {
        var context = M4Contexts.Create(out _);

        if (routeId is not null)
        {
            context.Features.Set<IReverseProxyFeature>(new RouteIdFeature(routeId));
        }

        context.Request.Method = method;
        context.Request.Path = path;
        if (identity is not null)
        {
            context.Features.Set(identity);
        }

        return context;
    }

    private static CallerRegistryProvider Registry(
        (string Caller, Rule[]? Operations)[] callers)
    {
        var entries = new Dictionary<string, string?>();
        foreach (var (caller, operations) in callers)
        {
            entries[$"CredProx:Callers:{caller}:Keys:0:KeyId"] = "k1";
            entries[$"CredProx:Callers:{caller}:Keys:0:KeyHash"] =
                "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("unused"))).ToLowerInvariant();

            if (operations is not null)
            {
                for (var i = 0; i < operations.Length; i++)
                {
                    var rule = operations[i];
                    if (rule.Route is not null)
                    {
                        entries[$"CredProx:Callers:{caller}:Operations:{i}:Route"] = rule.Route;
                    }

                    for (var m = 0; m < (rule.Methods?.Length ?? 0); m++)
                    {
                        entries[$"CredProx:Callers:{caller}:Operations:{i}:Methods:{m}"] = rule.Methods![m];
                    }

                    for (var p = 0; p < (rule.Paths?.Length ?? 0); p++)
                    {
                        entries[$"CredProx:Callers:{caller}:Operations:{i}:Paths:{p}"] = rule.Paths![p];
                    }
                }
            }
        }

        var config = new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
        return new CallerRegistryProvider(
            new CallerBinder(config, new SecretAccessorFactory(new ConfigurationSecretSource(config))),
            new ConfigurationSecretSource(config),
            NullLogger<CallerRegistryProvider>.Instance);
    }

    private sealed class RouteIdFeature(string routeId) : IReverseProxyFeature
    {
        public RouteModel Route { get; } = new(
            new RouteConfig { RouteId = routeId }, cluster: null, HttpTransformer.Default);

        public ClusterModel Cluster { get; } = new(
            new ClusterConfig { ClusterId = "c" },
            new HttpMessageInvoker(new SocketsHttpHandler()));

        public IReadOnlyList<DestinationState> AllDestinations { get; } = [];

        public IReadOnlyList<DestinationState> AvailableDestinations { get; set; } = [];

        public DestinationState? ProxiedDestination { get; set; }
    }
}
