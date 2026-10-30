using System.Security.Cryptography;
using System.Text;
using CredProx;
using CredProx.Abstractions;
using FsCheck;
using FsCheck.Xunit;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace CredProx.SecurityTests;

/// <summary>
/// §5.2 "Operation allow-lists" and "Caller API keys" as properties: for every generated
/// path — traversal variants, encodings, case tricks, hostile unicode — a declared caller
/// is admitted only by an exact ordinal pattern match on a safe path, every rejection
/// answers the same constant 403 document (nothing value-specific rides it out), and a
/// presented key value never appears in the 401 problem document.
/// </summary>
public sealed class CallerAllowListProperties
{
    private const string Key = "property-test-key-value";

    private static OperationAllowListFeature Feature(string[] patterns) =>
        new(Registry(patterns));

    private static readonly string RejectedBody = Reject("/zzzz-sentinel-zzzz").GetAwaiter().GetResult();

    private static async Task<string> Reject(string path)
    {
        var context = Context(path);
        await Feature(["/allowed/*"]).ApplyAsync(context, default);
        return SecurityContexts.ResponseBody(context);
    }

    [Property(MaxTest = 500)]
    public async Task AllowList_IsTheOnlyGate(NonNull<string> generated)
    {
        // A DefaultHttpContext publishes one path view — the host's decoded path; the
        // raw/decoded split is covered by the PathPatterns theories and the wire-level
        // integration tests. The property here: admission happens exactly when the path
        // is safe and matches the pattern, and every rejection answers the same constant
        // 403 document.
        var path = "/" + generated.Get.TrimStart('/');
        var context = Context(path);

        await Feature(["/allowed/*"]).ApplyAsync(context, default);

        var state = context.Features.Get<CredProxRequestState>()!;
        if (state is { IsAborted: false })
        {
            // Whatever is admitted is a safe decoded path that matches the pattern.
            Assert.True(PathPatterns.IsSafePath(path, path));
            Assert.True(PathPatterns.Matches(path, "/allowed/*"));
            return;
        }

        Assert.Equal(403, context.Response.StatusCode);
        Assert.Equal(RejectedBody, SecurityContexts.ResponseBody(context));
    }

    [Property(MaxTest = 500)]
    public async Task TraversalAndEncodingVariants_NeverMatch(NonNull<string> prefix, NonNull<string> suffix)
    {
        // Splice a dot segment or an encoded separator into a path that otherwise matches
        // the rule exactly: the result must never be admitted.
        foreach (var smuggle in new[] { "/../", "/./", "/%2e/", "/%2E%2E/", "/%2f/", "/%5c/" })
        {
            var path = $"/allowed/{prefix.Get}{smuggle}{suffix.Get}";
            var context = Context(path);

            await Feature(["/allowed/**"]).ApplyAsync(context, default);

            Assert.True(
                context.Features.Get<CredProxRequestState>()!.IsAborted,
                $"smuggled '{smuggle}' was admitted: {path}");
            Assert.Equal(RejectedBody, SecurityContexts.ResponseBody(context));
        }
    }

    [Property(MaxTest = 500)]
    public async Task CaseTricks_NeverMatch(NonNull<string> segment)
    {
        // Ordinal matching admits only the exact case; a case-folded or case-inverted
        // spelling of the literal segment must never be admitted.
        foreach (var spelling in new[] { "ALLOWED", "Allowed", "alLoWeD" })
        {
            var path = $"/{spelling}/{segment.Get}";
            var context = Context(path);
            await Feature(["/allowed/*"]).ApplyAsync(context, default);

            Assert.True(
                context.Features.Get<CredProxRequestState>()!.IsAborted,
                $"case trick '{spelling}' was admitted");
        }
    }

    [Fact]
    public async Task HostilePaths_FromThePlanList_AreRejected()
    {
        foreach (var path in new[]
        {
            "/allowed/../admin",
            "/allowed/%2e%2e/admin",
            "/allowed%2Fadmin",
            "/allowed/%252e%252e/admin",
            "/allowed/..%2fadmin",
            "/allowed/./../admin",
            "/allowed/\\admin",
            "/ALLOWED/q1",
            // F2 regressions: a '%' adjacent to a real escape must not hide it. (The
            // host decodes the path before the feature's raw view — the harness mirrors
            // Kestrel here — so these are the shapes that stay dangerous after one
            // decode. The raw-scan-only shapes, e.g. a bare %%25 that decodes to a
            // literal %% segment, are pinned at scan level in PathPatternsTests instead;
            // admitting their decoded literals is correct.)
            "/allowed/%/%2f/",
            "/allowed/%%2fadmin",
            "/allowed/%%2e%2e/admin",
            "/allowed/%252fadmin", // double-encoded separator: still %2f after one decode
            // Empty-segment decision: collapsed by matching, so refused, never matched.
            "/allowed//admin",
            "/allowed/q1?q=1#f", // query/fragment never reach the path; this one matches
        })
        {
            var context = Context(path);
            await Feature(["/allowed/*"]).ApplyAsync(context, default);

            var state = context.Features.Get<CredProxRequestState>()!;
            if (path == "/allowed/q1?q=1#f")
            {
                // A literal path string with ?/# is still an ordinal segment match here;
                // the point of the row is that it is treated as data, not structure.
                continue;
            }

            Assert.True(state.IsAborted, $"expected rejection for {path}");
            Assert.Equal(403, context.Response.StatusCode);
            Assert.Equal(RejectedBody, SecurityContexts.ResponseBody(context));
        }
    }

    private static readonly string Document401 = Problem401("sentinel-key-value").GetAwaiter().GetResult();

    [Property(MaxTest = 200)]
    public async Task PresentedKeyValue_NeverAppearsInThe401Document(NonNull<string> presented)
    {
        // The honest form of "the value never appears": run the real authentication stage
        // with the generated value presented as the key and require the 401 document to
        // be byte-identical to the one produced for a fixed sentinel. A value-specific
        // leak would make the documents differ. (A generated value equal to the
        // configured key authenticates and writes no document — outside the rejection
        // domain.)
        if (presented.Get == Key)
        {
            return;
        }

        var document = await Problem401(presented.Get);
        Assert.Equal(Document401, document);
        Assert.Contains("credprox.caller_unauthenticated", document);
    }

    private static async Task<string> Problem401(string presentedKey)
    {
        var context = SecurityContexts.Create(out _, destinationName: null);
        context.Request.Headers["X-CredProx-Key"] = presentedKey;

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
            .AddScheme<CallerKeyOptions, CallerKeyAuthenticationHandler>(CredProxAuth.CallerKeyScheme, _ => { });
        context.RequestServices = services.BuildServiceProvider();

        await new CallerAuthenticationFeature().ApplyAsync(context, default);
        return SecurityContexts.ResponseBody(context);
    }

    private static DefaultHttpContext Context(string path)
    {
        var context = SecurityContexts.Create(out _, destinationName: null);
        context.Request.Path = path;
        context.Features.Set(new CallerIdentity("app-a", "k1"));
        return context;
    }

    private static CallerRegistryProvider Registry(string[] pathPatterns)
    {
        var entries = new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] =
                "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Key))).ToLowerInvariant(),
        };
        for (var i = 0; i < pathPatterns.Length; i++)
        {
            entries[$"CredProx:Callers:app-a:Operations:0:Paths:{i}"] = pathPatterns[i];
        }

        var config = new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
        return new CallerRegistryProvider(
            new CallerBinder(config, new SecretAccessorFactory(new ConfigurationSecretSource(config))),
            new ConfigurationSecretSource(config),
            NullLogger<CallerRegistryProvider>.Instance);
    }
}
