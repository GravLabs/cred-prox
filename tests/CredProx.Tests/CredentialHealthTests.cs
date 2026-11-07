using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The M7 credential health story (§4 "Credential health", §5.2 "Credential health"):
/// an expiring certificate is <c>Degraded</c> N days before expiry and <c>Unhealthy</c>
/// once expired; a failed token probe is <c>Unhealthy</c> and recovers on the next
/// successful round; probes go through the token cache, so a valid cached token costs no
/// vendor call. Plus the probe loop (interval rounds, transition-only logging, a throwing
/// probe never kills the loop), the ASP.NET Core health check aggregation, and the health
/// gauges on the <c>CredProx</c> meter.
/// </summary>
public sealed class CredentialHealthTests
{
    private sealed class FakeProbe(string name, Func<CredProxHealthResult?> check) : ICredentialHealthProbe
    {
        private int _rounds;

        public string Name => name;

        public int Rounds => Volatile.Read(ref _rounds);

        public ValueTask<CredProxHealthResult?> CheckAsync(CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _rounds);
            return ValueTask.FromResult(check());
        }
    }

    private static X509Certificate2 CreateCertWithExpiry(string commonName, DateTimeOffset notAfter)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={commonName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(notAfter - TimeSpan.FromDays(365), notAfter);
    }

    // ---- TokenObtainableProbe ---------------------------------------------------------

    private static CredentialRegistryProvider TokenProbeRegistry(
        Dictionary<string, string?> entries,
        StubHttpHandler tokenHandler,
        Action<TokenCacheOptions>? configureCache = null)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
        var services = new ServiceCollection();
        services.AddCredProxTokenCache(configureCache);
        services.AddCredProxConfigurationSecrets(config);
        services.AddCredProxBuiltInCredentials();
        services.AddCredProxCredentials(config);
        services.AddCredProxCallerAuthentication(config); // registers the caller: partition scheme
        services.AddHttpClient(CredProxHttpClientNames.TokenClient)
            .ConfigurePrimaryHttpMessageHandler(() => tokenHandler);
        return services.BuildServiceProvider().GetRequiredService<CredentialRegistryProvider>();
    }

    private static Dictionary<string, string?> OAuthEntries(string credential, bool partitioned = false)
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

        return entries;
    }

    private static HttpResponseMessage TokenJson(string token) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(
                "{\"access_token\":\"" + token + "\",\"expires_in\":3600}",
                Encoding.UTF8,
                "application/json"),
        };

    [Fact]
    public async Task TokenProbe_FailedFetch_IsUnhealthy_NamingTheCredential()
    {
        var handler = new StubHttpHandler((_, _) =>
            new HttpResponseMessage(HttpStatusCode.InternalServerError) { Content = new StringContent("nope") });
        var probe = new TokenObtainableProbe(
            TokenProbeRegistry(OAuthEntries("health-contoso-fail"), handler), NullLogger<TokenObtainableProbe>.Instance);

        var result = await probe.CheckAsync(default);

        Assert.NotNull(result);
        Assert.Equal(CredProxHealthSeverity.Unhealthy, result!.Severity);
        Assert.Contains("health-contoso-fail", result.Description, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TokenProbe_FailureThenSuccess_Recovers()
    {
        var fail = true;
        var handler = new StubHttpHandler((_, _) => fail
            ? new HttpResponseMessage(HttpStatusCode.InternalServerError) { Content = new StringContent("nope") }
            : TokenJson("recovered-token"));
        // The cache's negative-cache TTL would otherwise replay the first failure; the
        // probe interval is far longer than any realistic TTL, so the test zeroes it to
        // stand in for "the next round happens after the negative cache expired".
        var probe = new TokenObtainableProbe(
            TokenProbeRegistry(
                OAuthEntries("health-contoso-recover"), handler,
                configureCache: o => o.NegativeCacheTtl = TimeSpan.Zero),
            NullLogger<TokenObtainableProbe>.Instance);

        Assert.NotNull(await probe.CheckAsync(default));

        fail = false;
        Assert.Null(await probe.CheckAsync(default));
    }

    [Fact]
    public async Task TokenProbe_RespectsTokenCache_NoExtraVendorCalls()
    {
        // §5.2: "probes respect the token cache — no extra token calls when a valid
        // token is cached". The probe resolves through GetCredential, which is the same
        // cache-backed path the attach stage uses.
        var handler = new StubHttpHandler((_, _) => TokenJson("cached-token"));
        var probe = new TokenObtainableProbe(
            TokenProbeRegistry(OAuthEntries("health-contoso-cache"), handler), NullLogger<TokenObtainableProbe>.Instance);

        Assert.Null(await probe.CheckAsync(default));
        Assert.Null(await probe.CheckAsync(default));
        Assert.Null(await probe.CheckAsync(default));

        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task TokenProbe_PartitionedCredential_ProbesEachAllowedPartitionOnce()
    {
        var handler = new StubHttpHandler((_, _) => TokenJson("partitioned-token"));
        var probe = new TokenObtainableProbe(
            TokenProbeRegistry(OAuthEntries("health-contoso-partitioned", partitioned: true), handler),
            NullLogger<TokenObtainableProbe>.Instance);

        Assert.Null(await probe.CheckAsync(default));
        Assert.Equal(2, handler.Requests.Count); // one per Allowed value, none invented

        Assert.Null(await probe.CheckAsync(default));
        Assert.Equal(2, handler.Requests.Count); // second round served from the cache
    }

    // ---- CertificateExpiryProbe -------------------------------------------------------

    private static ConnectionRegistryProvider ConnectionsWithCert(string connection, DateTimeOffset notAfter)
    {
        using var cert = CreateCertWithExpiry(connection, notAfter);
        var entries = new Dictionary<string, string?>
        {
            [$"CredProx:Connections:{connection}:ClientCertificate"] = $"secret:{connection}-pfx",
            [$"CredProx:Secrets:{connection}-pfx"] = TestCertificates.PfxBase64(cert),
        };

        var config = new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
        return new ConnectionRegistryProvider(
            new ConnectionBinder(
                config,
                new SecretAccessorFactory(new ConfigurationSecretSource(config)),
                NullLoggerFactory.Instance),
            new ConfigurationSecretSource(config),
            NullLogger<ConnectionRegistryProvider>.Instance);
    }

    [Fact]
    public async Task CertProbe_ExpiringWithinWindow_IsDegraded()
    {
        // §5.2: "an expiring certificate yields Degraded N days before expiry".
        var probe = new CertificateExpiryProbe(
            ConnectionsWithCert("health-cert-soon", DateTimeOffset.UtcNow.AddDays(5)),
            new CredProxHealthOptions { CertWarningDays = 30 },
            TimeProvider.System);

        var result = await probe.CheckAsync(default);

        Assert.NotNull(result);
        Assert.Equal(CredProxHealthSeverity.Degraded, result!.Severity);
        Assert.Contains("health-cert-soon", result.Description, StringComparison.Ordinal);
        Assert.Contains("within 30 days", result.Description, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CertProbe_Expired_IsUnhealthy()
    {
        var probe = new CertificateExpiryProbe(
            ConnectionsWithCert("health-cert-expired", DateTimeOffset.UtcNow.AddDays(-1)),
            new CredProxHealthOptions { CertWarningDays = 30 },
            TimeProvider.System);

        var result = await probe.CheckAsync(default);

        Assert.NotNull(result);
        Assert.Equal(CredProxHealthSeverity.Unhealthy, result!.Severity);
        Assert.Contains("expired", result.Description, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CertProbe_BeyondWindow_IsHealthy()
    {
        var probe = new CertificateExpiryProbe(
            ConnectionsWithCert("health-cert-fresh", DateTimeOffset.UtcNow.AddDays(365)),
            new CredProxHealthOptions { CertWarningDays = 30 },
            TimeProvider.System);

        Assert.Null(await probe.CheckAsync(default));
    }

    [Fact]
    public async Task CertProbe_RecordsDaysToExpiryGauge()
    {
        var measurements = new ConcurrentQueue<(string Instrument, double Value, Dictionary<string, object?> Tags)>();
        using var listener = ListenToCredProxMeter(measurements);

        var probe = new CertificateExpiryProbe(
            ConnectionsWithCert("health-cert-gauge", DateTimeOffset.UtcNow.AddDays(5)),
            new CredProxHealthOptions { CertWarningDays = 30 },
            TimeProvider.System);
        await probe.CheckAsync(default);
        listener.RecordObservableInstruments();

        Assert.Contains(
            measurements,
            m => m.Instrument == "credprox.certificate.days_to_expiry"
                && m.Value is > 4 and < 6
                && Equals(m.Tags["credprox.connection"], "health-cert-gauge"));
    }

    private static MeterListener ListenToCredProxMeter(
        ConcurrentQueue<(string Instrument, double Value, Dictionary<string, object?> Tags)> measurements)
    {
        // The health instruments are static observable gauges on the shared meter; other
        // parallel tests feed the same dictionaries, so assertions filter by unique names.
        var listener = new MeterListener
        {
            InstrumentPublished = (instrument, l) =>
            {
                if (instrument.Meter == CredProxDiagnostics.Meter)
                {
                    l.EnableMeasurementEvents(instrument);
                }
            },
        };
        listener.SetMeasurementEventCallback<double>((instrument, measurement, tags, _) =>
            measurements.Enqueue((instrument.Name, measurement, tags.ToArray().ToDictionary(t => t.Key, t => t.Value))));
        listener.Start();
        return listener;
    }

    // ---- The probe loop ---------------------------------------------------------------

    private static async Task WaitForAsync(Func<bool> condition, string what)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(10);
        while (DateTime.UtcNow < deadline)
        {
            if (condition())
            {
                return;
            }

            await Task.Delay(10);
        }

        throw new TimeoutException($"{what} never happened.");
    }

    [Fact]
    public async Task ProbeLoop_RoundsOnInterval_LogsTransitionsOnly()
    {
        var time = new FakeTimeProvider();
        CredProxHealthResult? current = new(
            CredProxHealthSeverity.Degraded, "certificate expires soon");
        var probe = new FakeProbe("loop-probe", () => current);
        var snapshot = new CredentialHealthSnapshot();
        var logs = new List<string?>();
        using var factory = LoggerFactory.Create(b => b.AddProvider(new CapturingLoggerProvider(logs)));
        var service = new CredentialHealthProbeService(
            [probe], snapshot, new CredProxHealthOptions { ProbeInterval = TimeSpan.FromMinutes(5) },
            time, factory.CreateLogger<CredentialHealthProbeService>());

        using var cts = new CancellationTokenSource();
        try
        {
            await service.StartAsync(cts.Token);

            // First round runs at startup, without waiting for the interval. The snapshot
            // is published last in a round, so waiting on it observes a completed round.
            await WaitForAsync(() => snapshot.Results.Length >= 1, "first round");
            var firstCheckedAt = snapshot.Results[0].CheckedAt;
            Assert.Equal(1, Assert.Single(snapshot.Results).Severity);
            Assert.Contains(logs, l => l?.Contains("is Degraded", StringComparison.Ordinal) == true);

            // A second round with the same severity logs nothing new. The fake clock
            // stamps CheckedAt, so a changed stamp means the round completed.
            time.Advance(TimeSpan.FromMinutes(5));
            await WaitForAsync(
                () => snapshot.Results.Length >= 1 && snapshot.Results[0].CheckedAt != firstCheckedAt,
                "second round");
            Assert.Single(logs, l => l?.Contains("Degraded", StringComparison.Ordinal) == true);

            // Recovery logs once, at Information.
            current = null;
            time.Advance(TimeSpan.FromMinutes(5));
            await WaitForAsync(() => snapshot.Results.Length >= 1 && snapshot.Results[0].Severity == 0, "recovery");
            Assert.Contains(logs, l => l?.Contains("recovered", StringComparison.Ordinal) == true);
            Assert.Single(logs, l => l?.Contains("Degraded", StringComparison.Ordinal) == true);
        }
        finally
        {
            cts.Cancel();
            await service.StopAsync(default);
        }
    }

    [Fact]
    public async Task ProbeLoop_ThrowingProbe_IsUnhealthyRound_LoopSurvives()
    {
        var time = new FakeTimeProvider();
        var boom = true;
        var probe = new FakeProbe("throwing-probe", () =>
        {
            if (boom)
            {
                throw new InvalidOperationException("probe exploded");
            }

            return null;
        });
        var snapshot = new CredentialHealthSnapshot();
        var logs = new List<string?>();
        using var factory = LoggerFactory.Create(b => b.AddProvider(new CapturingLoggerProvider(logs)));
        var service = new CredentialHealthProbeService(
            [probe], snapshot, new CredProxHealthOptions { ProbeInterval = TimeSpan.FromMinutes(5) },
            time, factory.CreateLogger<CredentialHealthProbeService>());

        using var cts = new CancellationTokenSource();
        try
        {
            await service.StartAsync(cts.Token);
            await WaitForAsync(() => snapshot.Results.Length >= 1, "first round");

            var result = Assert.Single(snapshot.Results);
            Assert.Equal(2, result.Severity);
            Assert.Contains("the probe threw", result.Description, StringComparison.Ordinal);
            Assert.Contains(logs, l => l?.Contains("is Unhealthy", StringComparison.Ordinal) == true);

            // The loop is alive: the next round runs and recovers.
            boom = false;
            time.Advance(TimeSpan.FromMinutes(5));
            await WaitForAsync(() => snapshot.Results.Length >= 1 && snapshot.Results[0].Severity == 0, "recovery");
        }
        finally
        {
            cts.Cancel();
            await service.StopAsync(default);
        }
    }

    [Fact]
    public async Task ProbeLoop_Disabled_RunsNoRounds()
    {
        var probe = new FakeProbe("disabled-probe", () => null);
        var snapshot = new CredentialHealthSnapshot();
        using var factory = LoggerFactory.Create(b => { });
        var service = new CredentialHealthProbeService(
            [probe], snapshot, new CredProxHealthOptions { Enabled = false },
            new FakeTimeProvider(), factory.CreateLogger<CredentialHealthProbeService>());

        await service.StartAsync(default);
        await Task.Delay(50);
        Assert.Equal(0, probe.Rounds);
        Assert.Empty(snapshot.Results);
        await service.StopAsync(default);
    }

    [Fact]
    public async Task ProbeLoop_RecordsProbeStatusGauge()
    {
        var measurements = new ConcurrentQueue<(string Instrument, double Value, Dictionary<string, object?> Tags)>();
        using var listener = ListenToCredProxMeter(measurements);

        var time = new FakeTimeProvider();
        var probe = new FakeProbe("gauge-probe", () => new CredProxHealthResult(
            CredProxHealthSeverity.Unhealthy, "down"));
        var snapshot = new CredentialHealthSnapshot();
        using var factory = LoggerFactory.Create(b => { });
        var service = new CredentialHealthProbeService(
            [probe], snapshot, new CredProxHealthOptions { ProbeInterval = TimeSpan.FromMinutes(5) },
            time, factory.CreateLogger<CredentialHealthProbeService>());

        using var cts = new CancellationTokenSource();
        try
        {
            await service.StartAsync(cts.Token);
            // The snapshot is published after the gauge is recorded, so a published
            // round guarantees the gauge holds this round's value.
            await WaitForAsync(() => snapshot.Results.Length >= 1, "first round");
        }
        finally
        {
            cts.Cancel();
            await service.StopAsync(default);
        }

        listener.RecordObservableInstruments();
        Assert.Contains(
            measurements,
            m => m.Instrument == "credprox.health.status"
                && m.Value == 2
                && Equals(m.Tags["credprox.item"], "gauge-probe")
                && Equals(m.Tags["credprox.kind"], "probe"));
    }

    // ---- The ASP.NET Core health check ------------------------------------------------

    [Fact]
    public async Task HealthCheck_NoRoundsYet_IsHealthy()
    {
        var check = new CredProxHealthCheck(new CredentialHealthSnapshot());

        var result = await check.CheckHealthAsync(new HealthCheckContext());

        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Contains("No CredProx health probes have run yet", result.Description, StringComparison.Ordinal);
    }

    [Fact]
    public async Task HealthCheck_DegradedOnly_IsDegraded()
    {
        var snapshot = new CredentialHealthSnapshot();
        snapshot.Update([new HealthProbeResult("p", 1, "expiring", DateTimeOffset.UtcNow)]);

        var result = await new CredProxHealthCheck(snapshot).CheckHealthAsync(new HealthCheckContext());

        Assert.Equal(HealthStatus.Degraded, result.Status);
        Assert.Equal("expiring", result.Data["p"]);
    }

    [Fact]
    public async Task HealthCheck_AnyUnhealthy_IsUnhealthy_WithAllFailureData()
    {
        var snapshot = new CredentialHealthSnapshot();
        snapshot.Update(
        [
            new HealthProbeResult("ok", 0, null, DateTimeOffset.UtcNow),
            new HealthProbeResult("degraded", 1, "soon", DateTimeOffset.UtcNow),
            new HealthProbeResult("broken", 2, "down", DateTimeOffset.UtcNow),
        ]);

        var result = await new CredProxHealthCheck(snapshot).CheckHealthAsync(new HealthCheckContext());

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.Equal("down", result.Data["broken"]);
        Assert.Equal("soon", result.Data["degraded"]);
        Assert.False(result.Data.ContainsKey("ok"));
    }

    // ---- Registration -----------------------------------------------------------------

    [Fact]
    public async Task AddCredProxHealthProbes_RegistersBuiltInsLoopAndCheck()
    {
        var config = TestConfig.Root(
            ("CredProx:Health:ProbeInterval", "00:01:00"),
            ("CredProx:Health:CertWarningDays", "7"));
        var services = new ServiceCollection();
        services.AddCredProxHealthProbes(config);

        Assert.Contains(services, d => d.ServiceType == typeof(ICredentialHealthProbe)
            && d.ImplementationType == typeof(TokenObtainableProbe));
        Assert.Contains(services, d => d.ServiceType == typeof(ICredentialHealthProbe)
            && d.ImplementationType == typeof(CertificateExpiryProbe));
        Assert.Contains(services, d => d.ServiceType == typeof(IHostedService)
            && d.ImplementationType == typeof(CredentialHealthProbeService));
        Assert.Contains(services, d => d.ServiceType == typeof(CredentialHealthSnapshot));

        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<CredProxHealthOptions>();
        Assert.Equal(TimeSpan.FromMinutes(1), options.ProbeInterval);
        Assert.Equal(7, options.CertWarningDays);

        // The registered "credprox" ASP.NET Core health check resolves and runs against
        // the (still empty) snapshot.
        var report = await provider.GetRequiredService<HealthCheckService>().CheckHealthAsync();
        Assert.Equal(HealthStatus.Healthy, report.Status);
        Assert.Contains(
            "No CredProx health probes have run yet",
            report.Entries["credprox"].Description,
            StringComparison.Ordinal);
    }
}
