using System.Security.Cryptography;
using System.Text;
using CredProx;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// Operator-facing log lines on the caller-authentication path (M31 mutation triage):
/// the failed-auth warning, the success debug line, and the rebind-success information
/// line are behaviour an operator greps for — the tests pin their existence, level and
/// content, and that a failure line never carries the key value.
/// </summary>
public sealed class CallerAuthObservabilityTests
{
    private const string Key = "observability-test-key";

    private static string Hash(string value) =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    [Fact]
    public async Task FailedKey_LogsWarning_NeverTheKeyValue()
    {
        var logs = new CapturingLoggerFactory();
        var context = Context("wrong-value-entirely", logs);

        await new CallerAuthenticationFeature().ApplyAsync(context, default);

        Assert.Contains(
            logs.Entries,
            e => e.Level == LogLevel.Warning && e.Message.Contains("failed authentication", StringComparison.Ordinal));
        Assert.DoesNotContain(logs.Entries, e => e.Message.Contains("wrong-value-entirely", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ValidKey_LogsDebug_NamingCallerAndKey()
    {
        var logs = new CapturingLoggerFactory();
        var context = Context(Key, logs);

        await new CallerAuthenticationFeature().ApplyAsync(context, default);

        Assert.Contains(
            logs.Entries,
            e => e.Level == LogLevel.Debug
                && e.Message == "Caller 'app-a' authenticated with key 'k1'.");
    }

    [Fact]
    public void RebindSuccess_LogsInformation()
    {
        var logs = new CapturingLoggerFactory();
        var entries = new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("unused"),
        };
        var config = new ConfigurationBuilder()
            .Add(new ReloadableMemoryConfigurationSource(entries))
            .Build();
        var secretSource = new ConfigurationSecretSource(config);
        var provider = new CallerRegistryProvider(
            new CallerBinder(config, new SecretAccessorFactory(secretSource)),
            secretSource,
            logs.CreateLogger<CallerRegistryProvider>());
        var reloadable = (ReloadableMemoryConfigurationProvider)config.Providers
            .OfType<ReloadableMemoryConfigurationProvider>().Single();

        reloadable.Set("CredProx:Callers:app-b:Keys:0:KeyId", "k2");
        reloadable.Set("CredProx:Callers:app-b:Keys:0:KeyHash", Hash("other"));
        reloadable.Reload();

        Assert.Contains(
            logs.Entries,
            e => e.Level == LogLevel.Information
                && e.Message.Contains("callers rebound", StringComparison.Ordinal));
    }

    private static DefaultHttpContext Context(string? key, CapturingLoggerFactory logs)
    {
        var context = M4Contexts.Create(out _);
        if (key is not null)
        {
            context.Request.Headers["X-CredProx-Key"] = key;
        }

        var entries = new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash(Key),
        };
        var config = new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
        var secretSource = new ConfigurationSecretSource(config);
        var registryProvider = new CallerRegistryProvider(
            new CallerBinder(config, new SecretAccessorFactory(secretSource)),
            secretSource,
            logs.CreateLogger<CallerRegistryProvider>());

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<ILoggerFactory>(logs);
        services.AddOptions();
        services.AddSingleton<ICallerStore>(new ConfigCallerStore(registryProvider, TimeProvider.System));
        services.AddAuthentication()
            .AddScheme<CallerKeyOptions, CallerKeyAuthenticationHandler>(
                CredProxAuth.CallerKeyScheme, _ => { });
        context.RequestServices = services.BuildServiceProvider();
        return context;
    }
}
