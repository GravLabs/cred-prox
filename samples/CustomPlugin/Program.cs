using System.Reflection;
using System.Text.Json;
using CredProx;
using Xunit;

// E10 (plan §6): writing a plugin. The credential type is the sample's own code
// (VendorSessionProvider.cs, ~50 lines), registered explicitly below — no discovery,
// no magic. --selftest runs the CredProx.Testing conformance suite the plugin ships
// (VendorSessionConformanceTests.cs); --smoke drives the full proxy path against
// in-process vendor stubs. Both need nothing: no Docker, no vendor account.
if (args.Contains("--selftest"))
{
    return await ConformanceSelfTest.RunAsync();
}

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCredProxTokenCache();
builder.Services.AddCredProxConfigurationSecrets(builder.Configuration);

// A plugin-only host supplies what its provider takes from DI — here the standard
// HttpClient machinery (hosts that also call AddCredProxBuiltInCredentials get it already).
builder.Services.AddHttpClient();

// The explicit registration a custom credential type needs: type name, provider, options.
// Everything else — binder, validation, secret scoping, cache, attach, refresh-on-401 —
// is the core treating the plugin exactly like a built-in.
builder.Services.AddCredProxCredentialType<VendorSessionProvider, VendorSessionOptions>("VendorSession");
builder.Services.AddCredProxCredentials(builder.Configuration);
builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx(builder.Configuration);

const string SmokeAppId = "smoke-app";
const string SmokeSecret = "smoke-vendor-secret";
var smoke = args.Contains("--smoke");
var loginCalls = 0;
if (smoke)
{
    builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
    {
        ["CredProx:Credentials:vendor-session:AppId"] = SmokeAppId,
        ["CredProx:Secrets:vendor-secret"] = SmokeSecret,
        ["CredProx:Credentials:vendor-session:LoginEndpoint"] = "http://localhost:5090/vendor/login",
        ["CredProx:Destinations:vendor:Template"] = "http://localhost:5090",
        ["ReverseProxy:Clusters:vendor:Destinations:vendor:Address"] = "http://localhost:5090/",
    });
}

builder.WebHost.UseUrls("http://localhost:5090");

var app = builder.Build();

if (smoke)
{
    // The vendor's login endpoint stand-in: checks the posted credentials and hands out
    // numbered session ids, so the smoke can prove the cache collapsed both calls.
    app.MapPost("/vendor/login", async (HttpContext context) =>
    {
        using var body = await JsonDocument.ParseAsync(
            context.Request.Body, cancellationToken: context.RequestAborted);
        var accepted =
            body.RootElement.GetProperty("appId").GetString() == SmokeAppId
            && body.RootElement.GetProperty("secret").GetString() == SmokeSecret;

        if (!accepted)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsync("""{"error":"invalid_credentials"}""");
            return;
        }

        var number = Interlocked.Increment(ref loginCalls);
        await context.Response.WriteAsync(
            $$"""{"access_token":"vsess_stub_{{number}}","expires_in":3600}""");
    });

    // The vendor API stand-in: reports the session header it received.
    app.Map("/echo", (HttpContext context) =>
        context.Response.WriteAsync(context.Request.Headers["X-Session-Id"].ToString()));
}

app.MapReverseProxy();

if (smoke)
{
    app.Start();
    using var client = new HttpClient();

    var first = await client.GetAsync("http://localhost:5090/vendor/echo");
    var firstBody = await first.Content.ReadAsStringAsync();
    var second = await client.GetAsync("http://localhost:5090/vendor/echo");
    var secondBody = await second.Content.ReadAsStringAsync();

    var ok = first.IsSuccessStatusCode
        && second.IsSuccessStatusCode
        && firstBody == "vsess_stub_1"
        && secondBody == firstBody
        && loginCalls == 1;
    Console.WriteLine(ok
        ? "SMOKE OK: the vendor saw X-Session-Id from the plugin-minted session; two proxied calls, one login."
        : $"SMOKE FAILED: first={(int)first.StatusCode} '{firstBody}' second={(int)second.StatusCode} '{secondBody}' loginCalls={loginCalls}");
    return ok ? 0 : 1;
}

app.Run();
return 0;

// Runs every [Fact] the conformance suite declares — the same facts `dotnet test` runs
// in a plugin's own test project, driven directly so the example needs no test runner.
internal static class ConformanceSelfTest
{
    public static async Task<int> RunAsync()
    {
        var suite = typeof(VendorSessionConformanceTests);
        var facts = suite
            .GetMethods(BindingFlags.Public | BindingFlags.Instance)
            .Where(method => method.GetCustomAttribute<FactAttribute>() is not null)
            .OrderBy(method => method.Name, StringComparer.Ordinal)
            .ToArray();

        Console.WriteLine($"CredProx.Testing conformance for VendorSession: {facts.Length} facts.");
        var failed = 0;
        foreach (var fact in facts)
        {
            // xunit's own contract: a fresh suite instance per fact.
            var instance = Activator.CreateInstance(suite)!;
            try
            {
                await (Task)fact.Invoke(instance, null)!;
                Console.WriteLine($"  PASS  {fact.Name}");
            }
            catch (Exception ex)
            {
                failed++;
                var root = ex is TargetInvocationException wrapper ? wrapper.InnerException ?? ex : ex;
                Console.WriteLine($"  FAIL  {fact.Name}: {root.Message.Split('\n')[0]}");
            }

            (instance as IDisposable)?.Dispose();
        }

        Console.WriteLine(failed == 0
            ? "CONFORMANCE OK: the plugin passes the suite the built-ins pass."
            : $"CONFORMANCE FAILED: {failed} of {facts.Length} facts failed.");
        return failed == 0 ? 0 : 1;
    }
}
