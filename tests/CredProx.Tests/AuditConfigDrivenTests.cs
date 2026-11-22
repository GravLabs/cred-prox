using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M49 (ADR-0007): the audit log is a core feature driven by configuration — a host that
/// writes a <c>CredProx:Audit</c> section gets the built-in sink from the core entry with
/// no setup call, and a section the entry never saw is still validated. The absence of the
/// section stays absence of audit: the entry registers no sink when there is nothing to
/// honor.
/// </summary>
public sealed class AuditConfigDrivenTests
{
    private static IConfiguration Config(params (string Key, string? Value)[] entries) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(entries.Select(e => new KeyValuePair<string, string?>("CredProx:" + e.Key, e.Value)))
            .Build();

    private static ServiceProvider BuildEntry(IConfiguration configuration)
    {
        var services = new ServiceCollection();
        services.AddCredProx(configuration);
        return services.BuildServiceProvider();
    }

    [Fact]
    public void ConfiguredAuditSection_RegistersTheBuiltInSinkThroughTheEntry()
    {
        var configuration = Config(("Audit:Enabled", "true"));
        using var provider = BuildEntry(configuration);

        var sinks = provider.GetServices<IAuditSink>().ToList();
        Assert.Contains(sinks, s => s is LoggerAuditSink);
    }

    [Fact]
    public void AbsentAuditSection_RegistersNoSink()
    {
        var configuration = Config();
        using var provider = BuildEntry(configuration);

        Assert.Empty(provider.GetServices<IAuditSink>());
    }

    [Fact]
    public void ConfiguredAuditSection_BindsItsOptionsThroughTheEntry()
    {
        var configuration = Config(("Audit:Enabled", "false"));
        using var provider = BuildEntry(configuration);

        var options = provider.GetRequiredService<CredProxAuditOptions>();
        Assert.False(options.Enabled);
    }

    [Fact]
    public void UnknownKeyUnderAuditSection_RefusesAtTheEntry()
    {
        // The entry validates what it binds: a typo under CredProx:Audit used to be
        // reachable only through the setup call; with no call to make, the entry owns it.
        var configuration = Config(("Audit:Enabled", "true"), ("Audit:Bogus", "1"));

        var services = new ServiceCollection();
        var error = Assert.Throws<OptionsValidationException>(() => services.AddCredProx(configuration));
        Assert.Contains("Bogus", error.Message);
    }

    [Fact]
    public void EntryPlusExplicitCall_RegistersTheSinkOnce()
    {
        // A 0.14-shape host still calling AddCredProxAudit explicitly lands on the same
        // TryAddEnumerable — exactly one built-in sink.
        var configuration = Config(("Audit:Enabled", "true"));
        var services = new ServiceCollection();
        services.AddCredProx(configuration);
        services.AddCredProxAudit(configuration);

        var sinks = services
            .Where(d => d.ServiceType == typeof(IAuditSink))
            .ToList();
        Assert.Single(sinks);
    }
}
