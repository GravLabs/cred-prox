using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M50 fold LOW-4: the metering reload walk follows the M45 F-5 house pattern — a bad
/// reload never throws on the reload thread, logs the failure kind only, and the
/// last-known-good options (bound once, never rebound) stay in force. The walk is armed
/// by the guard the metering response feature resolves, and the startup validator's
/// response-feature enumeration is what puts it live at host start.
/// </summary>
public sealed class CredProxMeteringReloadGuardTests
{
    private sealed class CollectingLogger : ILogger<CredProxMeteringReloadGuard>
    {
        public List<string> Messages { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) => Messages.Add(formatter(state, exception));
    }

    private static IConfigurationRoot BuildReloadable(
        IDictionary<string, string?> data,
        out ReloadableMemoryConfigurationProvider provider)
    {
        var configuration = new ConfigurationBuilder()
            .Add(new ReloadableMemoryConfigurationSource(data))
            .Build();
        provider = configuration.Providers.OfType<ReloadableMemoryConfigurationProvider>().Single();
        return configuration;
    }

    private static IDictionary<string, string?> MeteringData() =>
        new Dictionary<string, string?> { ["CredProx:Metering:MaxUsageParseBytes"] = "1048576" };

    [Fact]
    public void BadReload_DoesNotThrowAndLogsTheKeepPreviousLine()
    {
        var configuration = BuildReloadable(MeteringData(), out var provider);
        var logger = new CollectingLogger();
        _ = new CredProxMeteringReloadGuard(configuration, logger); // the ctor arms the walk

        provider.Set("CredProx:Metering:NotARealKey", "1");
        var error = Record.Exception(() => provider.Reload());

        Assert.Null(error); // pre-fold this escaped the raise (wrapped in AggregateException)
        var line = Assert.Single(logger.Messages, m => m.Contains("keeping the previous configuration"));
        Assert.Contains("rejected a configuration reload (", line);
    }

    [Fact]
    public void BadReload_KeepsThePreviouslyBoundOptionsInForce()
    {
        var configuration = BuildReloadable(MeteringData(), out var provider);
        var services = new ServiceCollection();
        services.AddCredProxMetering(configuration);
        using var container = services.BuildServiceProvider();

        var options = container.GetRequiredService<CredProxMeteringOptions>();
        Assert.Equal(1048576L, options.MaxUsageParseBytes);

        provider.Set("CredProx:Metering:NotARealKey", "1");
        var error = Record.Exception(() => provider.Reload());

        Assert.Null(error); // pre-fold (raw registration-time callback) the reload threw here
        Assert.Equal(1048576L, options.MaxUsageParseBytes); // options are never rebound
    }

    [Fact]
    public void ResponseFeatureEnumeration_ArmsTheReloadWalk()
    {
        // The R2 startup gate enumerates IResponseFeature before the app serves; that
        // construction resolves the guard and arms the walk. After it, a bad reload is
        // logged and kept — never thrown.
        var configuration = BuildReloadable(MeteringData(), out var provider);
        var services = new ServiceCollection();
        services.AddCredProxMetering(configuration);
        using var container = services.BuildServiceProvider();

        var features = container.GetServices<IResponseFeature>().ToList();
        var meteringFeature = Assert.Single(features.OfType<CredProxMeteringResponseFeature>());
        Assert.NotNull(meteringFeature.ReloadGuard); // walk is live once the feature is built

        provider.Set("CredProx:Metering:NotARealKey", "1");
        var error = Record.Exception(() => provider.Reload());
        Assert.Null(error);
    }

    [Fact]
    public void CleanReload_AfterArming_PassesTheWalkWithNoLogLine()
    {
        // Fold LOW-3 remainder: the same walk that rejects a bad key must let a valid
        // reload through quietly — no exception, no log line — and the reloaded value
        // is what configuration reads answer from then on (the options instance itself
        // stays bound, witnessed by the cell above).
        var configuration = BuildReloadable(MeteringData(), out var provider);
        var logger = new CollectingLogger();
        _ = new CredProxMeteringReloadGuard(configuration, logger);

        provider.Set("CredProx:Metering:MaxUsageParseBytes", "2097152");
        var error = Record.Exception(() => provider.Reload());

        Assert.Null(error);
        Assert.Empty(logger.Messages);
        Assert.Equal("2097152", configuration["CredProx:Metering:MaxUsageParseBytes"]);
    }
}
