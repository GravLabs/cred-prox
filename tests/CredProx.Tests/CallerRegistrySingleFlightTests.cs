using System.Security.Cryptography;
using System.Text;
using CredProx;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Xunit;
using Yarp.ReverseProxy.Configuration;

namespace CredProx.Tests;

/// <summary>
/// The caller-registry provider's single-flight contract: one observed change performs
/// exactly one bind ATTEMPT. In the default host the provider watches the built-in
/// configuration source's own token — which every reload of that root raises — so one
/// reload arrives as exactly one trigger. In a host whose source is not configuration
/// over the watched root, both watches stay registered, and what makes them
/// single-flight is that a trigger whose inputs (the raw <c>CredProx:Callers</c> values
/// and the secret-source change token captured at the last attempt) match the last
/// attempt's inputs is the same event arriving through the second watch, and is dropped
/// with one debug line naming nothing but the drop. Pinned here, in order: one refused
/// reload writes ONE error line and one accepted reload performs ONE bind in the
/// default host; the dropped-trigger line carries no configuration value (pinned on a
/// host that keeps both watches, where a drop can happen); a secret-source signal during
/// a bind is never swallowed (the token is captured before the bind — pinned with a value
/// moving and, separately, with nothing but the token moving so that half alone saves the
/// recovery); a transient secret
/// failure recovers on the next signal with the configuration unchanged; and a rotated
/// secret rebinds although no configuration value moved.
/// </summary>
public sealed class CallerRegistrySingleFlightTests
{
    private const string KeyA = "single-flight-key-a";
    private const string RefusedPhrase = "keeping the previous registry";
    private const string RebindPhrase = "callers rebound after a configuration change";
    private const string DropPhrase = "rebind trigger dropped";

    private static readonly RouteConfig PlainRoute = new()
    {
        RouteId = "plain",
        ClusterId = "acme",
        Match = new RouteMatch { Path = "/plain/{**catch-all}" },
        Metadata = new Dictionary<string, string> { [CredProxMetadata.Destination] = "acme" },
    };

    private static readonly ClusterConfig AcmeCluster = new()
    {
        ClusterId = "acme",
        Destinations = new Dictionary<string, DestinationConfig>
        {
            ["static"] = new() { Address = "http://upstream.example/" },
        },
    };

    private static string Hash(string value) =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private sealed class Capture(List<string> sink) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            lock (sink)
            {
                // A logged exception rides along in the capture so a failed cell names
                // the cause, not just the line count.
                sink.Add(exception is null
                    ? formatter(state, exception)
                    : formatter(state, exception) + $" [{exception.GetType().Name}: {exception.Message}]");
            }
        }
    }

    private sealed class CaptureProvider(List<string> sink) : ILoggerProvider
    {
        public ILogger CreateLogger(string categoryName) => new Capture(sink);
        public void Dispose()
        {
        }
    }

    /// <summary>A secret source with mutable values, a failing set, and a real token the
    /// test can fire — the signal half of the provider's inputs, driven directly.</summary>
    private sealed class SignalableSecretSource : ISecretSource
    {
        private readonly Dictionary<string, string?> _values;
        private readonly HashSet<string> _failing;
        private readonly List<string> _reads = [];
        private CancellationTokenSource _cts = new();

        public SignalableSecretSource(Dictionary<string, string?> values, HashSet<string> failing)
        {
            _values = values;
            _failing = failing;
        }

        public string Scheme => "signalable";

        public IReadOnlyList<string> Reads
        {
            get { lock (_reads) { return [.. _reads]; } }
        }

        public void Rotate(string name, string? value)
        {
            lock (_values)
            {
                _values[name] = value;
            }
        }

        public void Signal() => Interlocked.Exchange(ref _cts, new CancellationTokenSource()).Cancel();

        public IChangeToken GetChangeToken() => new CancellationChangeToken(Volatile.Read(ref _cts).Token);

        public ValueTask<string?> GetSecretAsync(string name, CancellationToken cancellationToken)
        {
            lock (_reads)
            {
                _reads.Add(name);
            }

            if (_failing.Contains(name))
            {
                throw new InvalidOperationException($"the vault entry '{name}' is not reachable");
            }

            lock (_values)
            {
                return new ValueTask<string?>(_values.TryGetValue(name, out var value) ? value : null);
            }
        }
    }

    /// <summary>A contributor that holds one bind open — inside the bind, before the key
    /// table is built — until the test releases it, so the test can fire a secret-source
    /// signal mid-bind. Registered before the keys package, so it runs first in Commit.</summary>
    private sealed class GateContributor : ICallerRegistryContributor
    {
        private readonly SemaphoreSlim _entered = new(0);
        private readonly SemaphoreSlim _release = new(0);
        private int _attempts;
        private int _armed;
        private int _blocked;

        public int Attempts => Volatile.Read(ref _attempts);

        public void Arm() => Volatile.Write(ref _armed, 1);

        public void EnterAndWait()
        {
            Assert.True(_entered.Wait(TimeSpan.FromSeconds(5)), "the gated bind never reached the contributor");
        }

        public void Release() => _release.Release();

        public object Contribute(CallerRegistry registry)
        {
            Interlocked.Increment(ref _attempts);
            if (Interlocked.CompareExchange(ref _armed, 0, 1) == 1 && Interlocked.Increment(ref _blocked) == 1)
            {
                _entered.Release();
                Assert.True(_release.Wait(TimeSpan.FromSeconds(5)), "the test never released the gated bind");
            }

            return new object();
        }
    }

    private static (IHost Host, List<string> Logs, ReloadableMemoryConfigurationProvider Provider) BuildHost(
        IDictionary<string, string?> entries,
        ISecretSource? secretSource = null,
        ICallerRegistryContributor? gate = null,
        bool twoWatch = false)
    {
        var config = new ConfigurationBuilder()
            .Add(new ReloadableMemoryConfigurationSource(entries))
            .Build();
        // Two-watch host shape: the pipeline watches a DIFFERENT IConfiguration
        // instance than the one the secret source watches — the source gets the root,
        // the pipeline a wrapped copy. The roots share the underlying providers, so one
        // Reload reaches both, but the instance comparison fails and both watches stay
        // registered: one reload arrives as two triggers. The source's root is built
        // first, so its reload callback on the shared provider runs first and the
        // reload reaches the source callback before the pipeline's root callback.
        var pipelineConfig = twoWatch
            ? new ConfigurationBuilder().AddConfiguration(config).Build()
            : config;
        var provider = (ReloadableMemoryConfigurationProvider)config.Providers
            .OfType<ReloadableMemoryConfigurationProvider>().Single();
        var logs = new List<string>();
        var host = new HostBuilder()
            .ConfigureAppConfiguration(build => build.AddConfiguration(config))
            .ConfigureLogging(logging =>
            {
                // The dropped-trigger line is debug: without lowering the host's default
                // minimum level it never reaches the capture and "no drop line" would
                // mean "invisible", not "not emitted".
                logging.SetMinimumLevel(LogLevel.Debug);
                logging.AddProvider(new CaptureProvider(logs));
            })
            .ConfigureServices(services =>
            {
                // The default host shape: the secret source is the configuration itself,
                // so its token is driven by the very reload token the provider also
                // watches — one event, two triggers.
                services.AddCredProxConfigurationSecrets(config);
                if (secretSource is not null)
                {
                    services.AddSingleton(secretSource);
                }

                if (gate is not null)
                {
                    // Registered BEFORE the keys package: the provider enumerates
                    // contributors in registration order, so the gate runs first.
                    services.AddSingleton<ICallerRegistryContributor>(gate);
                }

                services.AddCredProxTokenCache();
                services.AddCredProxBuiltInCredentials();
                services.AddCredProxCredentials(config);
                services.AddCredProxCallerAuthentication(pipelineConfig);
                services.AddRouting();
                services.AddReverseProxy().LoadFromMemory([PlainRoute], [AcmeCluster]).AddCredProx(config);
            })
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints => endpoints.MapReverseProxy());
                });
            })
            .Build();
        return (host, logs, provider);
    }

    private static Dictionary<string, string?> BaseEntries() => new()
    {
        ["CredProx:Destinations:acme:Template"] = "http://upstream.example/",
        ["CredProx:Callers:acme:Keys:0:KeyId"] = "k1",
        ["CredProx:Callers:acme:Keys:0:KeyHash"] = Hash(KeyA),
    };

    private static async Task WaitForLog(List<string> logs, string phrase)
    {
        for (var i = 0; i < 30 && !logs.Any(l => l.Contains(phrase)); i++)
        {
            await Task.Delay(100);
        }

        Assert.Contains(logs, l => l.Contains(phrase, StringComparison.Ordinal));
    }

    [Fact]
    public async Task OneRefusedReload_DefaultHost_WritesExactlyOneErrorLine()
    {
        // PA: one user-visible reload whose edit is REFUSED. The default host's watch is
        // the built-in source's own token, which every reload of its root raises exactly
        // once — so the refusal is ONE line, and the previous generation keeps serving.
        var (host, logs, provider) = BuildHost(BaseEntries());
        await host.StartAsync(default);
        var store = host.Services.GetRequiredService<ICallerStore>();
        Assert.NotNull(await store.ResolveKeyAsync(KeyA, default));
        provider.Set("CredProx:Callers:bold:Keys:0:KeyId", "k2");
        provider.Set("CredProx:Callers:bold:Keys:0:KeyHash", "secret:not-in-this-vault");
        provider.Reload();
        await WaitForLog(logs, RefusedPhrase);
        await Task.Delay(300); // a second refusal line, if triggers were not coalesced, lands here
        var stillServes = await store.ResolveKeyAsync(KeyA, default) is not null;
        await host.StopAsync();
        Assert.True(stillServes, "the refused reload must leave the previous generation serving");
        Assert.Equal(1, logs.Count(l => l.Contains(RefusedPhrase)));
    }

    [Fact]
    public async Task OneAcceptedReload_DefaultHost_PerformsExactlyOneBind()
    {
        // PB: one user-visible reload whose edit is ACCEPTED performs ONE bind — one
        // rebind line, one resolution pass. The default host delivers one trigger per
        // reload, so there is no second trigger to coalesce: no drop line either, which is
        // the visible signature of the single watch.
        var (host, logs, provider) = BuildHost(BaseEntries());
        await host.StartAsync(default);
        var store = host.Services.GetRequiredService<ICallerStore>();
        Assert.NotNull(await store.ResolveKeyAsync(KeyA, default));
        provider.Set("CredProx:Callers:acme:Keys:0:KeyHash", Hash(KeyA + "-rotated"));
        provider.Reload();
        await WaitForLog(logs, RebindPhrase);
        await Task.Delay(300);
        var rotatedServes = await store.ResolveKeyAsync(KeyA + "-rotated", default) is not null;
        var oldStops = await store.ResolveKeyAsync(KeyA, default) is null;
        await host.StopAsync();
        Assert.True(rotatedServes && oldStops, "the accepted edit must take effect exactly once");
        Assert.Equal(1, logs.Count(l => l.Contains(RebindPhrase)));
        Assert.Equal(0, logs.Count(l => l.Contains(DropPhrase)));
    }

    [Fact]
    public async Task DroppedTrigger_DebugLine_NamesNoSentinelNoReference()
    {
        // The dropped trigger must be observable (debug line) without becoming a
        // confirmation oracle: the line may not carry configuration values. Pinned on the
        // host that keeps BOTH watches — a third-party source over its own store, so the
        // provider watches the configuration root too — where a reload that touches
        // nothing the registry reads arrives as a trigger the attempt record already
        // covers, and is the drop's honest home. A distinctive sentinel hash and a live
        // secret reference sit in the very section the stamp hashes over, and the line
        // contains neither — nor any caller id.
        const string sentinel = "sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        var entries = BaseEntries();
        entries["CredProx:Callers:bold:Keys:0:KeyId"] = "kb";
        entries["CredProx:Callers:bold:Keys:0:KeyHash"] = sentinel;
        entries["CredProx:Callers:acme:Keys:1:KeyId"] = "ks";
        entries["CredProx:Callers:acme:Keys:1:KeyHash"] = "secret:vault-ks";
        entries["CredProx:Secrets:vault-ks"] = Hash(KeyA + "-s");
        // The third-party source answers the declared reference and never signals: the
        // configuration watch is the only signal, and its no-op trigger is the drop.
        var source = new SignalableSecretSource(
            new Dictionary<string, string?> { ["vault-ks"] = Hash(KeyA + "-s") },
            new HashSet<string>(StringComparer.Ordinal));
        var (host, logs, provider) = BuildHost(entries, source);
        await host.StartAsync(default);
        provider.Reload(); // a reload that changes nothing the registry reads
        for (var i = 0; i < 30 && !logs.Any(l => l.Contains(DropPhrase)); i++)
        {
            await Task.Delay(100);
        }

        Assert.True(
            logs.Any(l => l.Contains(DropPhrase)),
            $"a no-op reload must leave exactly one dropped trigger logged; logs={string.Join(" // ", logs)}");
        await Task.Delay(300);
        await host.StopAsync();
        var dropLines = logs.Where(l => l.Contains(DropPhrase)).ToList();
        Assert.Single(dropLines);
        var line = dropLines[0];
        Assert.DoesNotContain(sentinel, line, StringComparison.Ordinal);
        Assert.DoesNotContain("0123456789abcdef", line, StringComparison.Ordinal);
        Assert.DoesNotContain("vault-ks", line, StringComparison.Ordinal);
        Assert.DoesNotContain("secret:", line, StringComparison.Ordinal);
        Assert.DoesNotContain("acme", line, StringComparison.Ordinal);
        Assert.DoesNotContain("bold", line, StringComparison.Ordinal);
    }

    [Fact]
    public async Task OneAcceptedReload_TwoWatchHost_PerformsExactlyOneBindAndOneDrop()
    {
        // The two-watch invariant, asserted as EQUALITY: one accepted reload binds ONCE
        // and its second trigger is dropped — one rebind line plus one drop line — and
        // the edit serves exactly once. An at-least-one assertion would let the failure
        // mode pass: this host registers the source's root on the shared providers first,
        // so the reload reaches the source callback first; if the root callback ever bound
        // before the source callback, the source trigger following it would legitimately
        // re-attempt through HasChanged — two binds — and this cell must be red for that
        // order, exactly as it must be red if the drop condition could never fire.
        var (host, logs, provider) = BuildHost(BaseEntries(), twoWatch: true);
        await host.StartAsync(default);
        var store = host.Services.GetRequiredService<ICallerStore>();
        Assert.NotNull(await store.ResolveKeyAsync(KeyA, default));
        provider.Set("CredProx:Callers:acme:Keys:0:KeyHash", Hash(KeyA + "-rot"));
        provider.Reload();
        await WaitForLog(logs, RebindPhrase);
        await Task.Delay(300);
        var rotatedServes = await store.ResolveKeyAsync(KeyA + "-rot", default) is not null;
        var oldStops = await store.ResolveKeyAsync(KeyA, default) is null;
        await host.StopAsync();
        Assert.True(rotatedServes && oldStops, "the accepted edit must take effect exactly once");
        Assert.Equal(1, logs.Count(l => l.Contains(RebindPhrase)));
        Assert.Equal(1, logs.Count(l => l.Contains(DropPhrase)));
    }

    [Fact]
    public async Task TransientSecretFailure_RecoversOnNextSignal_ConfigurationUnchanged()
    {
        // Architect pin: the stamp must not lock out recovery. The configuration never
        // moves — a signal while the vault is down is refused (stamp recorded, one error
        // line), and the very next signal with the vault back recovers through the token
        // half of the gate.
        var values = new Dictionary<string, string?> { ["vault-k2"] = Hash(KeyA + "-2") };
        var failing = new HashSet<string>(StringComparer.Ordinal);
        var source = new SignalableSecretSource(values, failing);
        var entries = BaseEntries();
        entries["CredProx:Callers:bold:Keys:0:KeyId"] = "k2";
        entries["CredProx:Callers:bold:Keys:0:KeyHash"] = "secret:vault-k2";
        var (host, logs, _) = BuildHost(entries, source);
        await host.StartAsync(default);
        var store = host.Services.GetRequiredService<ICallerStore>();
        Assert.NotNull(await store.ResolveKeyAsync(KeyA + "-2", default));
        failing.Add("vault-k2");
        source.Signal(); // a source signal with no configuration change — attempted, refused
        await WaitForLog(logs, RefusedPhrase);
        failing.Remove("vault-k2");
        source.Signal(); // the recovery signal — same configuration, live vault
        await WaitForLog(logs, RebindPhrase);
        var recovered = await store.ResolveKeyAsync(KeyA + "-2", default) is not null;
        await host.StopAsync();
        Assert.True(recovered, "after the vault recovers, the next signal must rebind even though no configuration value moved");
        Assert.Equal(1, logs.Count(l => l.Contains(RefusedPhrase)));
        Assert.Equal(1, logs.Count(l => l.Contains(RebindPhrase)));
    }

    [Fact]
    public async Task RotatedSecret_TokenFiresValuesUnchanged_RebindServesTheNewKey()
    {
        // Architect pin: a rotated secret is invisible to configuration but fires the
        // source's token — the OR half a values-only stamp would drop.
        var values = new Dictionary<string, string?> { ["vault-k2"] = Hash(KeyA + "-2") };
        var source = new SignalableSecretSource(values, new HashSet<string>(StringComparer.Ordinal));
        var entries = BaseEntries();
        entries["CredProx:Callers:bold:Keys:0:KeyId"] = "k2";
        entries["CredProx:Callers:bold:Keys:0:KeyHash"] = "secret:vault-k2";
        var (host, logs, _) = BuildHost(entries, source);
        await host.StartAsync(default);
        var store = host.Services.GetRequiredService<ICallerStore>();
        Assert.NotNull(await store.ResolveKeyAsync(KeyA + "-2", default));
        source.Rotate("vault-k2", Hash(KeyA + "-rotated"));
        source.Signal();
        await WaitForLog(logs, RebindPhrase);
        var rotatedServes = await store.ResolveKeyAsync(KeyA + "-rotated", default) is not null;
        var oldStops = await store.ResolveKeyAsync(KeyA + "-2", default) is null;
        await host.StopAsync();
        Assert.True(rotatedServes, "a rotated secret must reach the table via the token half of the gate");
        Assert.True(oldStops, "the previous secret's key must stop serving after the rotation rebind");
        // One resolution per pass over the entries: startup validation, the initial
        // bind, and the rotation rebind each read vault-k2 exactly once.
        Assert.Equal(["vault-k2", "vault-k2", "vault-k2"], source.Reads);
    }

    [Fact]
    public async Task TokenFiredMidBind_RecoveryRebind_ServesTheValueMutatedAfterTheFire()
    {
        // The token-capture race: a signal that lands DURING a bind must not be
        // swallowed by the attempt record. A gated contributor holds the bind open; the
        // test fires the source token, then mutates a SECOND configuration value (an
        // operation and a key hash) before releasing. Exactly two attempts follow start,
        // and the second one reflects the post-fire value — a retry reusing the blocked
        // bind's snapshot, or a swallowed signal, would serve the pre-fire state.
        var source = new SignalableSecretSource(new Dictionary<string, string?>(), new HashSet<string>(StringComparer.Ordinal));
        var gate = new GateContributor();
        var (host, logs, provider) = BuildHost(BaseEntries(), source, gate);
        await host.StartAsync(default);
        var store = host.Services.GetRequiredService<ICallerStore>();
        var registryProvider = host.Services.GetRequiredService<CallerRegistryProvider>();
        Assert.NotNull(await store.ResolveKeyAsync(KeyA, default));
        gate.Arm();
        provider.Set("CredProx:Callers:acme:Keys:0:KeyHash", Hash(KeyA + "-b"));
        // Change callbacks run INLINE on the thread that reloads or cancels: a synchronous
        // Reload() or Signal() here would run the trigger's bind on the test thread and
        // block the release that is supposed to come from this thread. Drive both events
        // off-thread; the bind runs inside the reload task.
        var reloadTask = Task.Run(provider.Reload); // attempt 2 begins and blocks inside the gated contributor
        gate.EnterAndWait();
        var signalTask = Task.Run(source.Signal); // mid-bind signal
        provider.Set("CredProx:Callers:acme:Keys:0:KeyHash", Hash(KeyA + "-c")); // after the fire…
        provider.Set("CredProx:Callers:acme:Operations:0:Paths:0", "/late"); // …and before the release
        gate.Release();
        await reloadTask;
        await signalTask;
        await WaitForLog(logs, RebindPhrase);
        for (var i = 0; i < 30 && registryProvider.Current.Get("acme").Operations.Count == 0; i++)
        {
            await Task.Delay(100);
        }

        await Task.Delay(300); // any further attempt would land here
        var lateServes = await store.ResolveKeyAsync(KeyA + "-c", default) is not null;
        var bServes = await store.ResolveKeyAsync(KeyA + "-b", default) is not null;
        var lateOperation = registryProvider.Current.Get("acme").Operations
            .Any(rule => rule.PathPatterns.Any(p => p.Contains("/late", StringComparison.Ordinal)));
        await host.StopAsync();
        Assert.Equal(3, gate.Attempts); // initial bind + EXACTLY two reload-driven attempts
        Assert.True(
            logs.Count(l => l.Contains(RebindPhrase)) == 2,
            $"both reload-driven attempts must rebind; logs={string.Join(" // ", logs)}");
        Assert.True(lateOperation, "the recovery rebind must reflect the value mutated after the signal fired");
        Assert.True(lateServes, "the key hash mutated after the fire must be what the live table serves");
        Assert.False(bServes, "the blocked bind's pre-fire hash must not survive the recovery rebind");
    }

    [Fact]
    public async Task TokenFiredMidBind_ValuesUnchanged_RecoveryRebindRunsOnTheTokenHalf()
    {
        // The token half alone, no stamp half: like the cell above, a signal lands mid-bind,
        // but NOTHING else moves — the blocked bind's stamp is still the current stamp.
        // Only the token captured BEFORE the bind (ctor: "Capture BEFORE the bind, never
        // after") tells the second watch that this event is newer than the attempt it just
        // served. Capture that token after the bind instead and the second trigger drops:
        // the mid-bind signal is swallowed and one rebind stays served with the fired
        // signal outstanding — this cell must go red for exactly that flip.
        var source = new SignalableSecretSource(new Dictionary<string, string?>(), new HashSet<string>(StringComparer.Ordinal));
        var gate = new GateContributor();
        var (host, logs, provider) = BuildHost(BaseEntries(), source, gate);
        await host.StartAsync(default);
        var store = host.Services.GetRequiredService<ICallerStore>();
        Assert.NotNull(await store.ResolveKeyAsync(KeyA, default));
        gate.Arm();
        provider.Set("CredProx:Callers:acme:Keys:0:KeyHash", Hash(KeyA + "-b"));
        // Same off-thread driving as the cell above: the reload callback binds inline on
        // the reloading thread, so the release has to come from this one.
        var reloadTask = Task.Run(provider.Reload); // attempt 2 begins and blocks inside the gated contributor
        gate.EnterAndWait();
        var signalTask = Task.Run(source.Signal); // mid-bind signal — the ONLY change from here on
        gate.Release();
        await reloadTask;
        await signalTask;
        await WaitForLog(logs, RebindPhrase); // the blocked bind completes
        for (var i = 0; i < 30 && gate.Attempts < 3; i++)
        {
            await Task.Delay(100);
        }

        await Task.Delay(300); // any further attempt would land here
        var bServes = await store.ResolveKeyAsync(KeyA + "-b", default) is not null;
        await host.StopAsync();
        Assert.Equal(3, gate.Attempts); // initial bind + the reload bind + the token-driven recovery
        Assert.Equal(2, logs.Count(l => l.Contains(RebindPhrase)));
        Assert.Equal(0, logs.Count(l => l.Contains(DropPhrase)));
        Assert.True(bServes, "the recovery rebind must keep the configuration serving unchanged across the swallowed-signal flip");
    }
}
