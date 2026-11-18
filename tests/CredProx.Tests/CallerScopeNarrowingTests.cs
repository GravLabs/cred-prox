using System.Security.Cryptography;
using System.Text;
using CredProx;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Model;

namespace CredProx.Tests;

/// <summary>
/// M39 outcome C (ADR-0004 "Scope only narrows") as ruled in fold 2: operation rules
/// carry a <c>Name</c> equal to an app-role / scope value, and on the caller-token
/// path — the one that sets the per-request scope-set feature — only NAMED rules
/// whose name the token carries admit the request. An unnamed rule admits no token,
/// a caller without operations gets 403, and a role that names no rule grants
/// nothing. The feature is never set on the caller-key path, so keyed requests are
/// byte-for-byte unaffected. The intersection lives in the allow-list stage; nothing
/// else downstream changes.
/// </summary>
public sealed class CallerScopeNarrowingTests
{
    private sealed record Rule(string? Route = null, string[]? Methods = null, string[]? Paths = null, string? Name = null);

    // ---- binder: the Name key ----

    [Fact]
    public void OperationName_BindsToTheRule()
    {
        var provider = Registry([("app-a", [new Rule("reports", ["GET"], ["/reports/*"], "reports-read")])]);

        Assert.True(provider.Current.TryGet("app-a", out var caller));
        var rule = Assert.Single(caller!.Operations);
        Assert.Equal("reports-read", rule.Name);
    }

    [Fact]
    public void OperationWithoutName_BindsAsNull()
    {
        var provider = Registry([("app-a", [new Rule("reports", null, null)])]);

        var rule = Assert.Single(provider.Current.Get("app-a").Operations);
        Assert.Null(rule.Name);
    }

    [Fact]
    public void OperationWithEmptyName_FailsClosed()
    {
        // An empty name would match no role and read as a typo for one — the same
        // fail-closed family as an empty Route.
        var entries = Entries([("app-a", [new Rule("reports", null, null, "")])]);
        var ex = Assert.Throws<OptionsValidationException>(() => Binder(entries).Bind());

        var failure = Assert.Single(ex.Failures);
        Assert.Contains("declares an operation with an empty Name", failure, StringComparison.Ordinal);
    }

    [Fact]
    public void UnknownOperationKey_KnownListNamesTheTypoFreeName()
    {
        // "Nmae" must fail closed and the guidance must list the real key, or the
        // operator fixes the wrong thing.
        var entries = Entries([("app-a", [new Rule("reports", null, null, "reports-read")])], nameKeyTypo: true);
        var ex = Assert.Throws<OptionsValidationException>(() => Binder(entries).Bind());

        var failure = Assert.Single(ex.Failures);
        // The known-keys tail is ordinal-sorted (AddUnknownKeyError), not declaration order.
        Assert.Contains("Known keys at that level: Methods, Name, Paths, Route.", failure, StringComparison.Ordinal);
    }

    // ---- allow-list stage: the intersection ----

    [Fact]
    public async Task NamedRule_ScopeHoldsItsName_Admitted()
    {
        var (feature, context) = Setup(
            [new Rule("reports", ["GET"], ["/reports/*"], "reports-read")],
            path: "/reports/q1",
            routeId: "reports",
            scopes: Scopes("reports-read"));

        await feature.ApplyAsync(context, default);

        Assert.False(Aborted(context));
    }

    [Fact]
    public async Task NamedRule_ScopeLacksItsName_Rejected()
    {
        // The whole point of ADR-0004: a valid token for the right app with the wrong
        // role does not get the named operation. 403 exactly like today's denial.
        var (feature, context) = Setup(
            [new Rule("reports", ["GET"], ["/reports/*"], "reports-read")],
            path: "/reports/q1",
            routeId: "reports",
            scopes: Scopes("other-role"));

        await feature.ApplyAsync(context, default);

        AssertRejected(context);
    }

    [Fact]
    public async Task UnnamedRule_ScopePresent_Rejected()
    {
        // M39 fold 2 (architect ruling 00:33Z): on the token path a request is
        // allowed only by a NAMED rule whose name the token carries. An unnamed
        // rule admits no token; the caller-key path is byte-for-byte unaffected
        // (NamedRule_NoScopeFeature_Unaffected pins that side).
        var (feature, context) = Setup(
            [new Rule("reports", ["GET"], ["/reports/*"])],
            path: "/reports/q1",
            routeId: "reports",
            scopes: Scopes());

        await feature.ApplyAsync(context, default);

        AssertRejected(context);
    }

    [Fact]
    public async Task AllRulesNamed_EmptyScope_Rejected()
    {
        // A token carrying no roles/scp gets nothing from the named set.
        var (feature, context) = Setup(
            [new Rule("reports", ["GET"], ["/reports/*"], "reports-read")],
            path: "/reports/q1",
            routeId: "reports",
            scopes: Scopes());

        await feature.ApplyAsync(context, default);

        AssertRejected(context);
    }

    [Fact]
    public async Task NamedRule_NoScopeFeature_Unaffected()
    {
        // The caller-key path sets no feature: named rules are plain rules there.
        var (feature, context) = Setup(
            [new Rule("reports", ["GET"], ["/reports/*"], "reports-read")],
            path: "/reports/q1",
            routeId: "reports",
            scopes: null);

        await feature.ApplyAsync(context, default);

        Assert.False(Aborted(context));
    }

    [Fact]
    public async Task CallerWithoutOperations_ScopePresent_Rejected()
    {
        // Ruling fold-in (00:33Z): a scoped token against a caller with no
        // Operations gets 403 — the caller declares no named rule the token could
        // match, and on the token path only a named match admits.
        var (feature, context) = Setup(
            null,
            path: "/anything",
            routeId: "whatever",
            scopes: Scopes("anything"));

        await feature.ApplyAsync(context, default);

        AssertRejected(context);
    }

    [Fact]
    public async Task CallerWithoutOperations_EmptyScope_Rejected()
    {
        // Role-less token against a caller with no operations: the scope feature
        // is present (an empty set is still present) on the token path, and no
        // named rule exists to admit anything.
        var (feature, context) = Setup(
            null,
            path: "/anything",
            routeId: "whatever",
            scopes: Scopes());

        await feature.ApplyAsync(context, default);

        AssertRejected(context);
    }

    [Fact]
    public async Task UnnamedRule_ScopesPresent_MatchingRouteStillRejected()
    {
        // "Unnamed rules never admit a token": carrying some role changes nothing
        // for a rule that has no name to match — the never-admit direction holds
        // for scoped and role-less tokens alike.
        var (feature, context) = Setup(
            [new Rule("reports", ["GET"], ["/reports/*"])],
            path: "/reports/q1",
            routeId: "reports",
            scopes: Scopes("anything"));

        await feature.ApplyAsync(context, default);

        AssertRejected(context);
    }

    [Fact]
    public async Task ScopeNamingNoRule_AddsNothing()
    {
        // The never-union direction: a role with no matching rule cannot admit an
        // operation the caller's own rules deny.
        var (feature, context) = Setup(
            [new Rule("other", null, null)],
            path: "/reports/q1",
            routeId: "reports",
            scopes: Scopes("super-scope"));

        await feature.ApplyAsync(context, default);

        AssertRejected(context);
    }

    [Fact]
    public async Task ScopeNameOrdinalMatch_RoleCaseMismatch_Rejected()
    {
        // Role values are compared with the strictest reading, like methods and
        // paths: the set is ordinal, so "Reports-Read" is not "reports-read".
        var (feature, context) = Setup(
            [new Rule("reports", null, null, "reports-read")],
            path: "/reports/q1",
            routeId: "reports",
            scopes: Scopes("Reports-Read"));

        await feature.ApplyAsync(context, default);

        AssertRejected(context);
    }

    // ---- identity: the client id rides with the caller identity ----

    [Fact]
    public void CallerIdentity_WithoutClientId_IsNull()
    {
        Assert.Null(new CallerIdentity("app-a", "k1").ClientId);
    }

    [Fact]
    public void CallerIdentity_FromPrincipal_ReadsTheClientIdClaim()
    {
        var principal = new System.Security.Claims.ClaimsPrincipal(
            new System.Security.Claims.ClaimsIdentity(
                [
                    new System.Security.Claims.Claim(CallerIdentity.CallerClaimType, "app-a"),
                    new System.Security.Claims.Claim(CallerIdentity.KeyIdClaimType, "token:abc"),
                    new System.Security.Claims.Claim(CallerIdentity.ClientIdClaimType, "client-sec-a"),
                ],
                authenticationType: "test"));

        var identity = CallerIdentity.FromPrincipal(principal);

        Assert.Equal("app-a", identity!.CallerId);
        Assert.Equal("token:abc", identity.KeyId);
        Assert.Equal("client-sec-a", identity.ClientId);
    }

    // ---- audit: caller id + client id + token id, never the token ----

    [Fact]
    public async Task TokenRequest_AuditRecordsIds_NeverTheToken()
    {
        const string rawToken = "eyJhbGciOi-RAW-JWT-MUST-NEVER-BE-RECORDED";
        var sink = new CapturingSink();
        var recorder = new CredProxAuditRecorder(
            [sink],
            new CredProxAuditOptions(),
            TimeProvider.System,
            NullLogger<CredProxAuditRecorder>.Instance,
            new CredProxCoreOptions(),
            null);

        var context = new DefaultHttpContext();
        context.Features.Set<IHttpResponseFeature>(new CapturingResponseFeature());
        context.Response.Body = new MemoryStream();
        context.Request.Headers.Authorization = "Bearer " + rawToken;
        context.Features.Set(new CallerIdentity("agent-4", "token:tok-1", "client-sec-d"));
        context.Features.Set(new CallerRequestScopes(new HashSet<string>(StringComparer.Ordinal) { "plain-read" }));

        recorder.Begin(context);
        await context.Response.WriteAsync("ok");
        await context.Response.CompleteAsync();
        var feature = (CapturingResponseFeature)context.Features.Get<IHttpResponseFeature>()!;
        foreach (var callback in feature.OnCompletedCallbacks)
        {
            await callback();
        }

        var (_, fields) = Assert.Single(sink.Records);
        Assert.Equal("agent-4", fields["caller"]);
        Assert.Equal("token:tok-1", fields["keyId"]);
        Assert.Equal("client-sec-d", fields["client"]);
        Assert.DoesNotContain(
            rawToken, string.Join("|", fields.Values.Select(v => v?.ToString())), StringComparison.Ordinal);
    }

    // ---- helpers (mirroring OperationAllowListFeatureTests) ----

    private sealed class CapturingSink : IAuditSink
    {
        public List<(string Event, IReadOnlyDictionary<string, object?> Fields)> Records { get; } = [];

        public ValueTask WriteAsync(
            string eventName,
            IReadOnlyDictionary<string, object?> fields,
            CancellationToken cancellationToken)
        {
            Records.Add((eventName, fields));
            return ValueTask.CompletedTask;
        }
    }

    private sealed class CapturingResponseFeature : IHttpResponseFeature
    {
        public List<Func<Task>> OnCompletedCallbacks { get; } = [];

        public int StatusCode { get; set; } = 200;

        public string? ReasonPhrase { get; set; }

        public IHeaderDictionary Headers { get; set; } = new HeaderDictionary();

        public Stream Body { get; set; } = Stream.Null;

        public bool HasStarted => false;

        public void OnStarting(Func<Task> callback)
        {
        }

        public void OnStarting(Func<object, Task> callback, object state)
        {
        }

        public void OnCompleted(Func<Task> callback) => OnCompletedCallbacks.Add(callback);

        public void OnCompleted(Func<object, Task> callback, object state) =>
            OnCompletedCallbacks.Add(() => callback(state));
    }

    private static CallerRequestScopes Scopes(params string[] values) =>
        new(new HashSet<string>(values, StringComparer.Ordinal));

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
        string path,
        string? routeId,
        CallerRequestScopes? scopes)
    {
        var provider = Registry([("app-a", operations)]);
        var feature = new OperationAllowListFeature(provider);
        var context = M4Contexts.Create(out _);

        if (routeId is not null)
        {
            context.Features.Set<IReverseProxyFeature>(new RouteIdFeature(routeId));
        }

        context.Request.Method = "GET";
        context.Request.Path = path;
        context.Features.Set(new CallerIdentity("app-a", "token:abc", "client-sec-a"));
        if (scopes is not null)
        {
            context.Features.Set(scopes);
        }

        return (feature, context);
    }

    private static CallerRegistryProvider Registry(
        (string Caller, Rule[]? Operations)[] callers)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(Entries(callers)).Build();
        return new CallerRegistryProvider(
            new CallerBinder(config, new SecretAccessorFactory(new ConfigurationSecretSource(config)), []),
            new ConfigurationSecretSource(config),
            NullLogger<CallerRegistryProvider>.Instance);
    }

    private static CallerBinder Binder(Dictionary<string, string?> entries)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
        return new CallerBinder(config, new SecretAccessorFactory(new ConfigurationSecretSource(config)), []);
    }

    private static Dictionary<string, string?> Entries(
        (string Caller, Rule[]? Operations)[] callers, bool nameKeyTypo = false)
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

                    if (rule.Name is not null)
                    {
                        entries[nameKeyTypo
                            ? $"CredProx:Callers:{caller}:Operations:{i}:Nmae"
                            : $"CredProx:Callers:{caller}:Operations:{i}:Name"] = rule.Name;
                    }
                }
            }
        }

        return entries;
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
