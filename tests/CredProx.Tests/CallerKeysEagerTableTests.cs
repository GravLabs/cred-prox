using System.Security.Cryptography;
using System.Text;
using CredProx;
using CredProx.Abstractions;
using CredProx.CallerKeys;
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
/// The contract between the caller-key table and the caller registry: the key table is
/// built eagerly — at host start and at every accepted configuration rebind — as the
/// same accepted unit the registry is. Consequences pinned here:
///   - an edit whose key material cannot be resolved (a <c>secret:</c> reference that
///     went unresolvable) REFUSES the rebind as a whole: the previous registry AND the
///     previous table keep serving, and the refusal is logged once, naming caller and
///     key, through the same path a shape-refused edit takes;
///   - the same unresolvable reference at host start refuses the start;
///   - the request path never calls a secret source: every secret read belongs to a
///     build (start or rebind), and a source that fails afterwards leaves the built
///     table and registry serving until a rebind is attempted.
/// </summary>
public sealed class CallerKeysEagerTableTests
{
    private const string KeyA = "eager-table-key-a";

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

    private sealed class Capture : ILogger
    {
        private readonly List<string> _sink;

        public Capture(List<string> sink) => _sink = sink;

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
            lock (_sink)
            {
                _sink.Add(formatter(state, exception) + " || " + exception?.Message);
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

    /// <summary>A secret source that counts every read, answers from a fixed set, and
    /// fails on demand for designated names.</summary>
    private sealed class CountingSecretSource(
        Dictionary<string, string?> values,
        HashSet<string> failing) : ISecretSource
    {
        private readonly List<string> _reads = [];

        public string Scheme => "counting";

        public IChangeToken GetChangeToken() => NeverToken.Instance;

        public IReadOnlyList<string> Reads
        {
            get { lock (_reads) { return [.. _reads]; } }
        }

        public ValueTask<string?> GetSecretAsync(string name, CancellationToken cancellationToken)
        {
            lock (_reads)
            {
                _reads.Add(name);
            }

            if (failing.Contains(name))
            {
                // The canary inside the source's own message: it may never surface in
                // user-visible failure text (TableBuild_SourceFailure_* pins that).
                throw new InvalidOperationException($"the vault entry '{name}' is not reachable (FAKE-SOURCE-SECRET-c1e4)");
            }

            return values.TryGetValue(name, out var value)
                ? ValueTask.FromResult(value)
                : ValueTask.FromResult<string?>(null);
        }
    }

    private sealed class NeverToken : IChangeToken, IDisposable
    {
        public static readonly NeverToken Instance = new();

        public void Dispose()
        {
        }

        public bool ActiveChangeCallbacks => false;

        public bool HasChanged => false;

        public IDisposable RegisterChangeCallback(Action<object?> callback, object? state) => this;
    }

    private static (IHost Host, List<string> Logs, ReloadableMemoryConfigurationProvider Provider) BuildHost(
        IDictionary<string, string?> entries,
        ISecretSource? secretSource = null)
    {
        var config = new ConfigurationBuilder()
            .Add(new ReloadableMemoryConfigurationSource(entries))
            .Build();
        var provider = (ReloadableMemoryConfigurationProvider)config.Providers
            .OfType<ReloadableMemoryConfigurationProvider>().Single();
        var logs = new List<string>();

        var host = new HostBuilder()
            .ConfigureAppConfiguration(build => build.AddConfiguration(config))
            .ConfigureLogging(logging => logging.AddProvider(new CaptureProvider(logs)))
            .ConfigureServices(services =>
            {
                services.AddCredProxConfigurationSecrets(config);
                if (secretSource is not null)
                {
                    // Last registration wins for GetRequiredService<ISecretSource>.
                    services.AddSingleton(secretSource);
                }

                services.AddCredProxTokenCache();
                services.AddCredProxBuiltInCredentials();
                services.AddCredProxCredentials(config);
                services.AddCredProxCallerAuthentication(config);
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
        ["CredProx:Callers:bold:Keys:0:KeyId"] = "k2",
        ["CredProx:Callers:bold:Keys:0:KeyHash"] = Hash(KeyA + "-2"),
    };

    // A waited-for line is a PINNED line: a cell that waits and then passes without
    // ever having seen the phrase proves nothing. Fail loudly with the captured log.
    private static async Task WaitForLog(List<string> logs, string phrase)
    {
        for (var i = 0; i < 30 && !logs.Any(l => l.Contains(phrase)); i++)
        {
            await Task.Delay(100);
        }

        Assert.Contains(logs, l => l.Contains(phrase, StringComparison.Ordinal));
    }

    [Fact]
    public async Task UnresolvableSecretOnRebind_RefusesTheRebind_KeepsRegistryAndBothKeys()
    {
        var failing = new HashSet<string>(StringComparer.Ordinal);
        var source = new CountingSecretSource(
            new Dictionary<string, string?> { ["rotated"] = Hash(KeyA + "-2") },
            failing);
        var entries = BaseEntries();

        var (host, logs, provider) = BuildHost(entries, source);
        await host.StartAsync(default);

        var registryProvider = host.Services.GetRequiredService<CallerRegistryProvider>();
        var store = host.Services.GetRequiredService<ICallerStore>();
        var before = registryProvider.Current;
        Assert.NotNull(await store.ResolveKeyAsync(KeyA, default));
        Assert.NotNull(await store.ResolveKeyAsync(KeyA + "-2", default));

        // An accepted-shape edit whose secret cannot be resolved: bold's inline hash
        // becomes a secret: reference, and the source refuses that name from now on.
        failing.Add("rotated");
        provider.Set("CredProx:Callers:bold:Keys:0:KeyHash", "secret:rotated");
        provider.Reload();
        await WaitForLog(logs, "keeping the previous registry");

        var sameInstance = ReferenceEquals(before, registryProvider.Current);
        var acmeStillWorks = await store.ResolveKeyAsync(KeyA, default) is not null;
        var boldStillWorks = await store.ResolveKeyAsync(KeyA + "-2", default) is not null;
        var refusalLines = logs.Count(l => l.Contains("keeping the previous registry"));
        var namesCallerAndKey = logs.Any(l => l.Contains("bold") && l.Contains("k2"));
        await host.StopAsync();

        Assert.True(
            sameInstance,
            $"an unresolvable secret must refuse the rebind, not swap the registry; logs={string.Join(" // ", logs)}");
        Assert.True(acmeStillWorks, "an unrelated caller's key must keep working through the refused rebind");
        Assert.True(boldStillWorks, "the refused caller's previous key must keep working — the previous table stays in service");
        Assert.Equal(1, refusalLines); // one refusal path: the same single line a shape refusal writes
        Assert.True(
            namesCallerAndKey,
            $"the refusal log must name caller and key id; logs={string.Join(" // ", logs)}");
    }

    [Fact]
    public async Task UnresolvableSecretAtStartup_RefusesTheHostStart()
    {
        var failing = new HashSet<string>(StringComparer.Ordinal) { "rotated" };
        var source = new CountingSecretSource(new Dictionary<string, string?>(), failing);
        var entries = BaseEntries();
        entries["CredProx:Callers:bold:Keys:0:KeyHash"] = "secret:rotated";

        var (host, _, _) = BuildHost(entries, source);
        string? refusal = null;
        try
        {
            await host.StartAsync(default);
        }
        catch (Exception ex)
        {
            refusal = ex.GetType().Name + ": " + ex.Message;
        }
        finally
        {
            host.Dispose();
        }

        Assert.NotNull(refusal);
        Assert.Contains("bold", refusal, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RequestPath_WhenTheTableIsBuilt_MakesNoSecretCalls()
    {
        var source = new CountingSecretSource(
            new Dictionary<string, string?> { ["vault-k2"] = Hash(KeyA + "-2") },
            new HashSet<string>(StringComparer.Ordinal));
        var entries = BaseEntries();
        entries["CredProx:Callers:bold:Keys:0:KeyHash"] = "secret:vault-k2";

        var (host, _, _) = BuildHost(entries, source);
        await host.StartAsync(default);

        var store = host.Services.GetRequiredService<ICallerStore>();
        var readsAfterStart = source.Reads.Count;
        Assert.NotNull(await store.ResolveKeyAsync(KeyA, default));
        Assert.NotNull(await store.ResolveKeyAsync(KeyA + "-2", default));
        Assert.NotNull(await store.ResolveKeyAsync(KeyA, default));
        var readsAfterRequests = source.Reads.Count;
        await host.StopAsync();

        Assert.True(
            readsAfterStart == readsAfterRequests,
            $"the built table must serve every request without touching a secret source; reads after start={readsAfterStart}, after requests={readsAfterRequests}");
    }

    [Fact]
    public async Task SourceDeadAfterAcceptedStart_RebindAttemptIsRefused_AndTheBuiltTableServes()
    {
        var failing = new HashSet<string>(StringComparer.Ordinal);
        var source = new CountingSecretSource(
            new Dictionary<string, string?> { ["vault-k2"] = Hash(KeyA + "-2") },
            failing);
        var entries = BaseEntries();
        entries["CredProx:Callers:bold:Keys:0:KeyHash"] = "secret:vault-k2";

        var (host, logs, provider) = BuildHost(entries, source);
        await host.StartAsync(default);

        var registryProvider = host.Services.GetRequiredService<CallerRegistryProvider>();
        var store = host.Services.GetRequiredService<ICallerStore>();
        var before = registryProvider.Current;
        Assert.NotNull(await store.ResolveKeyAsync(KeyA + "-2", default));

        // The source dies for an already-built key. An edit that does not touch bold at
        // all must still be refused (the build runs over the whole entry list), and while
        // no rebind completes the built table keeps every key serving.
        failing.Add("vault-k2");
        provider.Set("CredProx:Callers:acme:Keys:1:KeyId", "k3");
        provider.Set("CredProx:Callers:acme:Keys:1:KeyHash", Hash(KeyA + "-3"));
        provider.Reload();
        await WaitForLog(logs, "keeping the previous registry");

        var sameInstance = ReferenceEquals(before, registryProvider.Current);
        var acmeOldStillWorks = await store.ResolveKeyAsync(KeyA, default) is not null;
        var boldStillWorks = await store.ResolveKeyAsync(KeyA + "-2", default) is not null;
        var newKeyNotLive = await store.ResolveKeyAsync(KeyA + "-3", default) is null;
        await host.StopAsync();

        Assert.True(
            sameInstance,
            $"a rebind whose build fails must not swap the registry; logs={string.Join(" // ", logs)}");
        Assert.True(acmeOldStillWorks, "the previous table must keep serving untouched keys");
        Assert.True(boldStillWorks, "a dead secret source must not pull a built key out of service");
        Assert.True(newKeyNotLive, "the refused edit's new key must not be live");
        // The refusal really happened and happened exactly ONCE: the refused reload's two
        // watch triggers produced one bind attempt, one error line, and one resolution
        // pass — which died at bold's dead secret; the untouched inline keys consumed
        // nothing. (Before the coalesce this cell passed even when the line never
        // arrived: WaitForLog was silent.)
        Assert.Equal(1, logs.Count(l => l.Contains("keeping the previous registry")));
        // Startup validation resolves every declared secret reference once, the initial
        // bind resolves each again, and the refused rebind's single pass reads vault-k2
        // a third time before it throws: three reads, one per pass, no fourth.
        Assert.Equal(["vault-k2", "vault-k2", "vault-k2"], source.Reads);
    }

    [Fact]
    public async Task AcceptedRebind_BuildsOnceOverTheEntryList_RequestsAddNothing()
    {
        var source = new CountingSecretSource(
            new Dictionary<string, string?>
            {
                ["vault-k2"] = Hash(KeyA + "-2"),
                ["vault-k3"] = Hash(KeyA + "-3"),
            },
            new HashSet<string>(StringComparer.Ordinal));
        var entries = BaseEntries();
        entries["CredProx:Callers:bold:Keys:0:KeyHash"] = "secret:vault-k2";

        var (host, logs, provider) = BuildHost(entries, source);
        await host.StartAsync(default);

        var store = host.Services.GetRequiredService<ICallerStore>();

        // An accepted-shape rebind: bold gains a second key over another secret.
        provider.Set("CredProx:Callers:bold:Keys:1:KeyId", "k3");
        provider.Set("CredProx:Callers:bold:Keys:1:KeyHash", "secret:vault-k3");
        provider.Reload();
        await WaitForLog(logs, "callers rebound after a configuration change");
        await Task.Delay(300); // a doubled bind, if the coalesce were missing, lands here
        var newKeyServes = await store.ResolveKeyAsync(KeyA + "-3", default) is not null;

        // Every secret read must belong to a build (start or bind), never to a lookup:
        // after the rebind settles, resolving keys repeatedly may add NO read at all.
        var readsBeforeLookups = source.Reads.Count;
        Assert.NotNull(await store.ResolveKeyAsync(KeyA + "-2", default));
        Assert.NotNull(await store.ResolveKeyAsync(KeyA + "-2", default));
        var readsAfterLookups = source.Reads.Count;
        await host.StopAsync();

        Assert.True(
            readsBeforeLookups == readsAfterLookups,
            $"lookups must not resolve secrets once the table is built; beforeLookups={readsBeforeLookups}, afterLookups={readsAfterLookups}, logs={string.Join(" // ", logs)}");
        Assert.True(newKeyServes, "the added key must serve from the accepted rebind");
        Assert.Equal(1, logs.Count(l => l.Contains("callers rebound after a configuration change")));
        // Startup validation reads each declared secret once, then one accepted reload =
        // one build = each contributed secret resolved once per pass: validation
        // [vault-k2], initial bind [vault-k2], accepted rebind [vault-k2, vault-k3] —
        // one full pass over the entry list per pass, not two.
        Assert.Equal(["vault-k2", "vault-k2", "vault-k2", "vault-k3"], source.Reads);
    }
    [Fact]
    public async Task NeverSignallingSource_KeyOnlyAddition_NewKeyAuthenticates()
    {
        // The positive control: a secret source that NEVER signals must still see an
        // accepted key-only edit take effect — the configuration watch alone drives the
        // rebind, and the NEW key authenticates. An effect, not an absence of complaints.
        var source = new CountingSecretSource(new Dictionary<string, string?>(), new HashSet<string>(StringComparer.Ordinal));
        var (host, logs, provider) = BuildHost(BaseEntries(), source);
        await host.StartAsync(default);
        var store = host.Services.GetRequiredService<ICallerStore>();
        Assert.NotNull(await store.ResolveKeyAsync(KeyA, default));
        provider.Set("CredProx:Callers:acme:Keys:1:KeyId", "k-live");
        provider.Set("CredProx:Callers:acme:Keys:1:KeyHash", Hash(KeyA + "-live"));
        provider.Reload();
        await WaitForLog(logs, "callers rebound after a configuration change");
        await Task.Delay(300);
        var newKeyServes = await store.ResolveKeyAsync(KeyA + "-live", default) is not null;
        var firstServes = await store.ResolveKeyAsync(KeyA, default) is not null;
        await host.StopAsync();
        Assert.True(newKeyServes, "under a never-signalling secret source the configuration watch alone must commit the new key");
        Assert.True(firstServes, "the untouched key must keep serving");
        Assert.Equal(1, logs.Count(l => l.Contains("callers rebound after a configuration change")));
        // A never-signalling source offers no second trigger for one event: nothing to drop.
        Assert.DoesNotContain(logs, l => l.Contains("rebind trigger dropped"));
    }
    [Fact]
    public void TableBuild_SourceFailure_NamesTheExceptionType_KeepsTheCauseNotItsMessage()
    {
        var entries = new Dictionary<string, string?>
        {
            ["CredProx:Callers:acme:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:acme:Keys:0:KeyHash"] = "secret:vault-down",
        };
        var config = new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
        // The source's own message carries a value-shaped canary; it may live in the
        // CAUSE chain but never in the message this bind surfaces.
        var source = new CountingSecretSource(new Dictionary<string, string?>(), ["vault-down"]);
        var accessorFactory = new SecretAccessorFactory(source);
        var registry = new CallerBinder(config, accessorFactory, []).Bind();
        var contributor = new CallerKeyTableContributor(config, accessorFactory);
        var ex = Assert.Throws<InvalidOperationException>(() => contributor.Contribute(registry));
        Assert.Contains("acme", ex.Message, StringComparison.Ordinal);
        Assert.Contains("k1", ex.Message, StringComparison.Ordinal);
        Assert.Contains("(source exception InvalidOperationException)", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("FAKE-SOURCE-SECRET-c1e4", ex.Message, StringComparison.Ordinal);
        Assert.IsType<InvalidOperationException>(ex.InnerException);
    }
    [Fact]
    public void Validation_ResolveNothing_TheContributorResolvesEachDeclaredSecretOnce()
    {
        // The other half of one-secret-pass-per-bind: binding the registry WITH the
        // contributed rules over a secret: reference must touch the source zero times;
        // the table contributor then makes the one pass, each declared secret read once.
        var source = new CountingSecretSource(
            new Dictionary<string, string?> { ["vault-k2"] = Hash(KeyA + "-2") },
            new HashSet<string>(StringComparer.Ordinal));
        var accessorFactory = new SecretAccessorFactory(source);
        var entries = BaseEntries();
        entries["CredProx:Callers:bold:Keys:0:KeyHash"] = "secret:vault-k2";
        var config = new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
        var registry = new CallerBinder(config, accessorFactory, [new CallerKeyRules()]).Bind();
        Assert.Empty(source.Reads);
        var table = (CallerKeyTable)new CallerKeyTableContributor(config, accessorFactory).Contribute(registry);
        Assert.Equal(2, table.Entries.Count);
        Assert.Equal(["vault-k2"], source.Reads);
    }

    [Fact]
    public async Task RefusedEditBeforeFirstLookup_LeavesEveryKeyServing()
    {
        var entries = BaseEntries();

        var (host, logs, provider) = BuildHost(entries);
        await host.StartAsync(default);

        var registryProvider = host.Services.GetRequiredService<CallerRegistryProvider>();
        var store = host.Services.GetRequiredService<ICallerStore>();
        var before = registryProvider.Current;

        // A shape refusal BEFORE the table's first use: the table must not be rebuilt
        // from the refused configuration.
        provider.Set("CredProx:Callers:bold:Keys:0:KeyHash", "sha256:not-a-hash");
        provider.Reload();
        await WaitForLog(logs, "keeping the previous registry");

        var acmeWorks = await store.ResolveKeyAsync(KeyA, default) is not null;
        var boldWorks = await store.ResolveKeyAsync(KeyA + "-2", default) is not null;
        var sameInstance = ReferenceEquals(before, registryProvider.Current);
        await host.StopAsync();

        Assert.True(sameInstance, "a refused edit must not swap the serving registry");
        Assert.True(acmeWorks, "an untouched caller's key must serve after a cold refused edit");
        Assert.True(boldWorks, "the refused caller's own key must still serve from the previous table");
    }

    [Fact]
    public async Task KeyOnlyRotation_TakesEffectWithinTheReloadWindow()
    {
        var entries = BaseEntries();

        var (host, _, provider) = BuildHost(entries);
        await host.StartAsync(default);
        var store = host.Services.GetRequiredService<ICallerStore>();

        // Warm the table, then rotate acme's key material only — the caller set is
        // untouched. A rotation must take effect: the old secret stops, the new one
        // starts, within the reload window. The committed generation, not "did the
        // core registry change", decides what serves.
        Assert.NotNull(await store.ResolveKeyAsync(KeyA, default));
        provider.Set("CredProx:Callers:acme:Keys:0:KeyHash", Hash(KeyA + "-rotated"));
        provider.Reload();
        await Task.Delay(500);

        var oldStillServes = await store.ResolveKeyAsync(KeyA, default) is not null;
        var rotatedServes = await store.ResolveKeyAsync(KeyA + "-rotated", default) is not null;
        await host.StopAsync();

        Assert.True(
            !oldStillServes,
            $"a rotated key must stop serving within the reload window (revocation-critical); oldStillServes={oldStillServes}");
        Assert.True(rotatedServes, "the rotated key must start serving within the reload window");
    }

    [Fact]
    public async Task KeyOnlyAddition_TakesEffectWithinTheReloadWindow()
    {
        var entries = BaseEntries();

        var (host, _, provider) = BuildHost(entries);
        await host.StartAsync(default);
        var store = host.Services.GetRequiredService<ICallerStore>();

        // Warm the table, then give acme a second key. The new key must start serving
        // within the reload window while the first keeps working.
        Assert.NotNull(await store.ResolveKeyAsync(KeyA, default));
        provider.Set("CredProx:Callers:acme:Keys:1:KeyId", "k-new");
        provider.Set("CredProx:Callers:acme:Keys:1:KeyHash", Hash(KeyA + "-new"));
        provider.Reload();
        await Task.Delay(500);

        var newKeyServes = await store.ResolveKeyAsync(KeyA + "-new", default) is not null;
        var firstKeyServes = await store.ResolveKeyAsync(KeyA, default) is not null;
        await host.StopAsync();

        Assert.True(
            newKeyServes,
            "a key added to an existing caller must start serving within the reload window");
        Assert.True(firstKeyServes, "the existing key must keep serving");
    }

    [Fact]
    public async Task AcceptedKeyOnlyEdit_CommitsOneGeneration_ServingTableIsBuiltAgainstServingRegistry()
    {
        var entries = BaseEntries();

        var (host, _, provider) = BuildHost(entries);
        await host.StartAsync(default);
        var store = host.Services.GetRequiredService<ICallerStore>();
        var registryProvider = host.Services.GetRequiredService<CallerRegistryProvider>();

        Assert.NotNull(await store.ResolveKeyAsync(KeyA, default));
        var before = registryProvider.CurrentGeneration;
        Assert.True(
            before.TryGetContributed<CallerKeyTableContributor>(out var beforeData),
            "the initial generation must carry the committed key table");

        // An accepted KEY-ONLY edit: the caller set is untouched, so "did the core
        // registry change" is not what re-keys anything — the identity that matters is
        // the generation: registry and table commit as one unit against one instance.
        provider.Set("CredProx:Callers:acme:Keys:0:KeyHash", Hash(KeyA + "-rotated"));
        provider.Reload();
        await Task.Delay(500);

        var after = registryProvider.CurrentGeneration;
        Assert.False(
            ReferenceEquals(before, after),
            "an accepted key-only edit must commit a NEW generation, even when the caller set is unchanged");
        Assert.True(
            ReferenceEquals(after.Registry, registryProvider.Current),
            "the served registry and the generation's registry must be one and the same instance");
        Assert.True(
            after.TryGetContributed<CallerKeyTableContributor>(out var afterData)
                && !ReferenceEquals(beforeData, afterData),
            "the new generation carries a table built against ITS registry, not the previous one");

        // The pre-edit table keeps the old key as data (a held snapshot serves its own
        // generation), while the live lookups run against the new table: the old key is
        // gone from what authenticates.
        var beforeTable = (CallerKeyTable)beforeData;
        var oldHash = SHA256.HashData(Encoding.UTF8.GetBytes(KeyA));
        var snapshotHoldsOldKey = beforeTable.Entries.Any(e => e.Hash.SequenceEqual(oldHash));

        var oldServes = await store.ResolveKeyAsync(KeyA, default) is not null;
        var rotatedServes = await store.ResolveKeyAsync(KeyA + "-rotated", default) is not null;
        await host.StopAsync();

        Assert.True(snapshotHoldsOldKey, "the previous generation's committed table still describes the unit it was built for");
        Assert.True(!oldServes, "the pre-edit table must no longer be what serves — the rotated key stops authenticating");
        Assert.True(rotatedServes, "the rotated key must serve from the newly committed generation");
    }

    [Fact]
    public void TableBuild_WhenASecretResolvesEmpty_RefusesNamingCallerAndKey()
    {
        var entries = new Dictionary<string, string?>
        {
            ["CredProx:Callers:acme:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:acme:Keys:0:KeyHash"] = "secret:gone",
        };
        var config = new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
        // "gone" answers, but answers EMPTY: not a failure, an empty value. The bind
        // still refuses — an empty hash is not key material, and committing it would
        // silently drop the caller's key instead of refusing the unit.
        var source = new CountingSecretSource(
            new Dictionary<string, string?> { ["gone"] = string.Empty },
            []);
        var accessorFactory = new SecretAccessorFactory(source);
        var registry = new CallerBinder(config, accessorFactory, []).Bind();
        var contributor = new CallerKeyTableContributor(config, accessorFactory);

        var ex = Assert.Throws<InvalidOperationException>(() => contributor.Contribute(registry));

        Assert.Contains("acme", ex.Message, StringComparison.Ordinal);
        Assert.Contains("k1", ex.Message, StringComparison.Ordinal);
        Assert.Contains("resolved an empty KeyHash secret", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TableBuild_WhenASecretFailsToResolve_RefusesNamingCallerAndKey()
    {
        var entries = new Dictionary<string, string?>
        {
            ["CredProx:Callers:acme:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:acme:Keys:0:KeyHash"] = "secret:vault-down",
        };
        var config = new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
        // The source FAILS for this name. The contributed rules check the declaration's
        // shape only, so this build is the resolution arm: the sole resolver per bind,
        // and the thing that refuses the bind when a shape-valid reference cannot
        // resolve — no unresolved hash can reach a committed generation.
        var source = new CountingSecretSource(new Dictionary<string, string?>(), ["vault-down"]);
        var accessorFactory = new SecretAccessorFactory(source);
        var registry = new CallerBinder(config, accessorFactory, []).Bind();
        var contributor = new CallerKeyTableContributor(config, accessorFactory);

        var ex = Assert.Throws<InvalidOperationException>(() => contributor.Contribute(registry));

        Assert.Contains("acme", ex.Message, StringComparison.Ordinal);
        Assert.Contains("k1", ex.Message, StringComparison.Ordinal);
        Assert.Contains("could not resolve its KeyHash secret", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TableBuild_NonHashKeyHash_RefusesWithTheShapeMessage()
    {
        var entries = new Dictionary<string, string?>
        {
            ["CredProx:Callers:acme:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:acme:Keys:0:KeyHash"] = "open-sesame",
        };
        var config = new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
        // An inline value that is not 'sha256:<hex>' at all: the core binder accepts the
        // section blind (the keys package owns its shape), so the build re-checks.
        var source = new CountingSecretSource(new Dictionary<string, string?>(), []);
        var accessorFactory = new SecretAccessorFactory(source);
        var registry = new CallerBinder(config, accessorFactory, []).Bind();
        var contributor = new CallerKeyTableContributor(config, accessorFactory);

        var ex = Assert.Throws<InvalidOperationException>(() => contributor.Contribute(registry));

        Assert.Contains("acme", ex.Message, StringComparison.Ordinal);
        Assert.Contains("k1", ex.Message, StringComparison.Ordinal);
        Assert.Contains("not 'sha256:<64 hex digits>'", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TableBuild_UnparseableExpiry_RefusesNamingCallerAndKey()
    {
        var entries = new Dictionary<string, string?>
        {
            ["CredProx:Callers:acme:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:acme:Keys:0:KeyHash"] = Hash(KeyA),
            ["CredProx:Callers:acme:Keys:0:ExpiresAt"] = "sometime next week",
        };
        var config = new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
        // A committed table must never carry a key whose expiry the build could not
        // read: the entry refuses instead of defaulting to never-expires.
        var source = new CountingSecretSource(new Dictionary<string, string?>(), []);
        var accessorFactory = new SecretAccessorFactory(source);
        var registry = new CallerBinder(config, accessorFactory, []).Bind();
        var contributor = new CallerKeyTableContributor(config, accessorFactory);

        var ex = Assert.Throws<InvalidOperationException>(() => contributor.Contribute(registry));

        Assert.Contains("acme", ex.Message, StringComparison.Ordinal);
        Assert.Contains("k1", ex.Message, StringComparison.Ordinal);
        Assert.Contains("unparseable ExpiresAt", ex.Message, StringComparison.Ordinal);
    }
}
