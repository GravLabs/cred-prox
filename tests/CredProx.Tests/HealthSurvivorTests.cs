using System.Diagnostics.Metrics;
using System.Net;
using System.Text;
using CredProx;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage of the health folder: probe identities, the options guard
/// boundaries (interval strictly positive, warning window zero-allowed), the snapshot and
/// service constructor guards, the ASP.NET Core health check's description and data
/// contract, and the token probe's partition-named failures, gauge statuses and warning
/// line.
/// </summary>
public sealed class HealthSurvivorTests
{
    private sealed class Handler(Func<CancellationToken, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(respond(cancellationToken));
    }

    private static CredentialRegistryProvider TokenRegistry(
        string credential,
        bool partitioned,
        Handler handler)
    {
        var entries = new Dictionary<string, string?>
        {
            [$"CredProx:Credentials:{credential}:Type"] = "OAuthClientCredentials",
            [$"CredProx:Credentials:{credential}:TokenEndpoint"] = "http://token.example/oauth/token",
            [$"CredProx:Credentials:{credential}:ClientId"] = "client",
            [$"CredProx:Credentials:{credential}:ClientSecret"] = $"secret:{credential}-secret",
            [$"CredProx:Secrets:{credential}-secret"] = "s3cr3t-value",
        };
        if (partitioned)
        {
            entries[$"CredProx:Credentials:{credential}:Partition:From"] = "caller:";
            entries[$"CredProx:Credentials:{credential}:Partition:Allowed:0"] = "app-a";
            entries[$"CredProx:Credentials:{credential}:Partition:Allowed:1"] = "app-b";
        }

        var config = new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
        var services = new ServiceCollection();
        services.AddCredProxTokenCache(o => o.NegativeCacheTtl = TimeSpan.Zero);
        services.AddCredProxConfigurationSecrets(config);
        services.AddCredProxBuiltInCredentials();
        services.AddCredProxCredentials(config);
        services.AddCredProxCallerAuthentication(config);
        services.AddHttpClient(CredProxHttpClientNames.TokenClient)
            .ConfigurePrimaryHttpMessageHandler(() => handler);
        return services.BuildServiceProvider().GetRequiredService<CredentialRegistryProvider>();
    }

    private static HttpResponseMessage TokenJson() =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(
                """{"access_token":"t","expires_in":3600}""",
                Encoding.UTF8,
                "application/json"),
        };

    private static HttpResponseMessage Failure() =>
        new(HttpStatusCode.InternalServerError) { Content = new StringContent("nope") };

    private static (List<(string Item, string Kind, double Status)> Gauges, MeterListener Listener) WatchHealthGauge()
    {
        var gauges = new List<(string, string, double)>();
        var listener = new MeterListener
        {
            InstrumentPublished = (instrument, l) =>
            {
                if (instrument.Name == "credprox.health.status")
                {
                    l.EnableMeasurementEvents(instrument);
                }
            },
        };
        listener.SetMeasurementEventCallback<double>((_, value, tags, _) =>
        {
            string item = string.Empty;
            string kind = string.Empty;
            foreach (var tag in tags)
            {
                if (tag.Key == "credprox.item")
                {
                    item = (string)tag.Value!;
                }
                else if (tag.Key == "credprox.kind")
                {
                    kind = (string)tag.Value!;
                }
            }

            gauges.Add((item, kind, value));
        });
        listener.Start();
        return (gauges, listener);
    }

    [Fact]
    public void Probes_PinTheirNames()
    {
        Assert.Equal("credprox.tokens", new TokenObtainableProbe(null!, null!).Name);
        Assert.Equal(
            "credprox.certificates",
            new CertificateExpiryProbe(null!, null!, null!).Name);
    }

    [Fact]
    public void Options_GuardBoundaries()
    {
        var options = new CredProxHealthOptions();

        // Interval must be strictly positive; zero is not a busy loop.
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => options.ProbeInterval = TimeSpan.Zero);
        Assert.Contains("The health probe interval must be positive.", ex.Message, StringComparison.Ordinal);

        // The warning window allows zero (warn immediately) but not negative.
        options.CertWarningDays = 0;
        Assert.Equal(0, options.CertWarningDays);
        var neg = Assert.Throws<ArgumentOutOfRangeException>(() => options.CertWarningDays = -1);
        Assert.Contains("The certificate warning window cannot be negative.", neg.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Snapshot_NullRound_Throws()
    {
        var guardError = Assert.Throws<ArgumentNullException>(
            () => new CredentialHealthSnapshot().Update(null!));
        Assert.Equal("results", guardError.ParamName); // the spread expression would name another
    }

    [Fact]
    public void ProbeService_GuardsItsConstructor()
    {
        var snapshot = new CredentialHealthSnapshot();
        var options = new CredProxHealthOptions();
        var logger = NullLogger<CredentialHealthProbeService>.Instance;

        Assert.Throws<ArgumentNullException>(
            () => new CredentialHealthProbeService(null!, snapshot, options, TimeProvider.System, logger));
        Assert.Throws<ArgumentNullException>(
            () => new CredentialHealthProbeService([], null!, options, TimeProvider.System, logger));
        Assert.Throws<ArgumentNullException>(
            () => new CredentialHealthProbeService([], snapshot, null!, TimeProvider.System, logger));
        Assert.Throws<ArgumentNullException>(
            () => new CredentialHealthProbeService([], snapshot, options, null!, logger));
        Assert.Throws<ArgumentNullException>(
            () => new CredentialHealthProbeService([], snapshot, options, TimeProvider.System, null!));
    }

    [Fact]
    public async Task HealthCheck_HealthyProbe_RunsCleanWithNoDescription()
    {
        // "No probes have run yet" is reserved for the empty snapshot — a clean round must
        // not masquerade as a never-run state.
        var snapshot = new CredentialHealthSnapshot();
        snapshot.Update([new HealthProbeResult("probe-a", 0, null, DateTimeOffset.UtcNow)]);

        var result = await new CredProxHealthCheck(snapshot).CheckHealthAsync(new HealthCheckContext());

        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Null(result.Description);
    }

    [Fact]
    public async Task HealthCheck_FailingProbes_JoinNameAndDescriptionAndCarryData()
    {
        var snapshot = new CredentialHealthSnapshot();
        snapshot.Update(
        [
            new HealthProbeResult("probe-a", 1, "certificate near expiry", DateTimeOffset.UtcNow),
            new HealthProbeResult("probe-b", 2, "tokens unavailable", DateTimeOffset.UtcNow),
        ]);

        var result = await new CredProxHealthCheck(snapshot).CheckHealthAsync(new HealthCheckContext());

        Assert.Equal(HealthStatus.Unhealthy, result.Status); // worst severity decides
        Assert.Equal("probe-a: certificate near expiry; probe-b: tokens unavailable", result.Description);
        Assert.Equal("tokens unavailable", Assert.Contains("probe-b", result.Data));
    }

    [Fact]
    public async Task TokenProbe_PartitionedFailure_NamesEveryPartitionAndGaugesUnhealthy()
    {
        var logs = new List<string?>();
        var probe = new TokenObtainableProbe(
            TokenRegistry("surv-part", partitioned: true, new Handler(_ => Failure())),
            new LoggerFactory([new CapturingLoggerProvider(logs)]).CreateLogger<TokenObtainableProbe>());
        var (gauges, listener) = WatchHealthGauge();
        using (listener)
        {
            var result = await probe.CheckAsync(default);

            listener.RecordObservableInstruments();

            Assert.NotNull(result);
            Assert.Contains("'surv-part' (partition 'app-a')", result.Description!, StringComparison.Ordinal);
            Assert.Contains("'surv-part' (partition 'app-b')", result.Description!, StringComparison.Ordinal);
            Assert.Equal(
                ("surv-part", "credential", 2d),
                Assert.Single(gauges, g => g.Item == "surv-part"));
            Assert.Contains(
                "The CredProx token health probe found 2 credential(s) that could not be obtained.",
                logs);
        }
    }

    [Fact]
    public async Task TokenProbe_FlatFailure_NamesNoPartition_ThenRecoveryGaugesHealthy()
    {
        var fail = true;
        var probe = new TokenObtainableProbe(
            TokenRegistry("surv-flat", partitioned: false, new Handler(_ => fail ? Failure() : TokenJson())),
            NullLogger<TokenObtainableProbe>.Instance);
        var (gauges, listener) = WatchHealthGauge();
        using (listener)
        {
            var result = await probe.CheckAsync(default);

            Assert.NotNull(result);
            Assert.Contains(
                "credential 'surv-flat' could not be obtained:",
                result.Description!,
                StringComparison.Ordinal);
            Assert.DoesNotContain("(partition", result.Description!, StringComparison.Ordinal);
            listener.RecordObservableInstruments();
            Assert.Equal(2d, Assert.Single(gauges, g => g.Item == "surv-flat").Status);

            fail = false;
            Assert.Null(await probe.CheckAsync(default));
            listener.RecordObservableInstruments();
            // Each Record pass re-renders the gauge into the list: the newest reading wins.
            Assert.Equal(0d, gauges.Last(g => g.Item == "surv-flat").Status);
        }
    }

    [Fact]
    public async Task TokenProbe_CancellationRethrows_NotReportedAsFailure()
    {
        // A cancelled round is shutdown, not an unhealthy credential.
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var probe = new TokenObtainableProbe(
            TokenRegistry("surv-cancel", partitioned: false, new Handler(_ => throw new TaskCanceledException("fetch cancelled"))),
            NullLogger<TokenObtainableProbe>.Instance);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => probe.CheckAsync(cts.Token).AsTask());
    }

    // ---- M31 batch-2 survivors ----

    [Fact]
    public void ProbeServiceCtor_NullSnapshot_ThrowsArgumentNullNamingSnapshot()
    {
        var error = Assert.Throws<ArgumentNullException>(() => new CredentialHealthProbeService(
            [],
            null!,
            new CredProxHealthOptions(),
            TimeProvider.System,
            NullLogger<CredentialHealthProbeService>.Instance));

        Assert.Equal("snapshot", error.ParamName);
    }

    [Fact]
    public void ProbeServiceCtor_NullProbes_ThrowsArgumentNullNamingProbes()
    {
        // The [.. probes] spread just below is an absorber that names its own
        // parameter ("source"): only the paramName distinguishes the guard's throw.
        var error = Assert.Throws<ArgumentNullException>(() => new CredentialHealthProbeService(
            null!,
            new CredentialHealthSnapshot(),
            new CredProxHealthOptions(),
            TimeProvider.System,
            NullLogger<CredentialHealthProbeService>.Instance));

        Assert.Equal("probes", error.ParamName);
    }

    [Fact]
    public async Task TokenProbe_TwoFailures_JoinTheReportWithSemicolonSpace()
    {
        // The health report is one operator-readable line; the "; " separator keeps the
        // failures apart. An empty join fuses two diagnosis lines into one unreadable one.
        var probe = new TokenObtainableProbe(
            TokenRegistry("surv-join", partitioned: true, new Handler(_ => Failure())),
            NullLogger<TokenObtainableProbe>.Instance);

        var result = await probe.CheckAsync(default);

        Assert.NotNull(result);
        Assert.Contains("; credential 'surv-join' (partition 'app-b')", result.Description!, StringComparison.Ordinal);
    }
}
