using System.Security.Cryptography;
using System.Text;
using System.Threading;
using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Memory;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The built-in caller store (§4 Phase B, §5.2 "Caller API keys"): hashed lookup against
/// the live registry, expiry, rotation (multiple active keys), and revocation via reload.
/// </summary>
public sealed class CallerStoreTests
{
    private const string KeyA = "key-value-alpha";
    private const string KeyB = "key-value-beta";

    [Fact]
    public async Task ValidKey_ResolvesCallerAndKeyId()
    {
        var store = Store(("caller-a", [("k1", KeyA, null)]));

        var match = await store.ResolveKeyAsync(KeyA, default);

        Assert.NotNull(match);
        Assert.Equal("caller-a", match!.Identity.CallerId);
        Assert.Equal("k1", match.Identity.KeyId);
    }

    [Fact]
    public async Task UnknownKey_ResolvesToNull()
    {
        var store = Store(("caller-a", [("k1", KeyA, null)]));

        Assert.Null(await store.ResolveKeyAsync("not-a-key", default));
    }

    [Fact]
    public async Task ExpiredKey_ResolvesToNull()
    {
        var now = new DateTimeOffset(2026, 10, 14, 12, 0, 0, TimeSpan.Zero);

        // expired: now >= expiry
        var match = await new ConfigCallerStore(
            Registry(("caller-a", [("k1", KeyA, now)])),
            new FixedTimeProvider(now)).ResolveKeyAsync(KeyA, default);

        Assert.Null(match);
    }

    [Fact]
    public async Task KeyNotYetExpired_Resolves()
    {
        var now = new DateTimeOffset(2026, 10, 14, 12, 0, 0, TimeSpan.Zero);
        var store = new ConfigCallerStore(
            Registry(("caller-a", [("k1", KeyA, now.AddSeconds(1))])),
            new FixedTimeProvider(now));

        Assert.NotNull(await store.ResolveKeyAsync(KeyA, default));
    }

    [Fact]
    public async Task TwoActiveKeys_BothResolve_SameCaller()
    {
        // Rotation window: old and new key both authenticate until the old one is removed.
        var store = Store(("caller-a", [("k-old", KeyA, null), ("k-new", KeyB, null)]));

        Assert.Equal("k-old", (await store.ResolveKeyAsync(KeyA, default))!.Identity.KeyId);
        Assert.Equal("k-new", (await store.ResolveKeyAsync(KeyB, default))!.Identity.KeyId);
    }

    [Fact]
    public async Task RevokedKey_ResolvesToNull()
    {
        // Revocation is removal from the registry (the reload that drops the key).
        var store = Store(("caller-a", [("k1", KeyA, null)]));
        Assert.NotNull(await store.ResolveKeyAsync(KeyA, default));

        var afterRevoke = Store(("caller-a", [("k2", KeyB, null)]));
        Assert.Null(await afterRevoke.ResolveKeyAsync(KeyA, default));
    }

    [Fact]
    public async Task KeysOfDifferentCallers_DoNotCross()
    {
        var store = Store(
            ("caller-a", [("k1", KeyA, null)]),
            ("caller-b", [("k1", KeyB, null)]));

        Assert.Equal("caller-a", (await store.ResolveKeyAsync(KeyA, default))!.Identity.CallerId);
        Assert.Equal("caller-b", (await store.ResolveKeyAsync(KeyB, default))!.Identity.CallerId);
    }

    [Fact]
    public void HashFormat_ParsesSha256Hex()
    {
        var hex = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(KeyA))).ToLowerInvariant();

        Assert.True(CallerBinder.TryParseHash($"sha256:{hex}", out var hash));
        Assert.Equal(32, hash.Length);

        // Case-insensitive prefix and hex.
        Assert.True(CallerBinder.TryParseHash($"SHA256:{hex.ToUpperInvariant()}", out _));

        Assert.False(CallerBinder.TryParseHash(hex, out _));                    // no prefix
        Assert.False(CallerBinder.TryParseHash($"sha256:{hex[..62]}", out _));  // short
        Assert.False(CallerBinder.TryParseHash($"sha256:{hex}00", out _));      // long
        Assert.False(CallerBinder.TryParseHash($"sha256:{new string('z', 64)}", out _)); // non-hex
    }

    [Fact]
    public async Task RebindMidResolution_ResolvesFromOneSnapshot()
    {
        // F1 regression: the store must resolve against a single registry snapshot. The
        // rebind is made deterministic by firing it from the TimeProvider call that
        // happens exactly at the matching key (ExpiresAt forces the expiry check): the
        // reload chain is synchronous, so Current swaps mid-loop and drops the *next*
        // caller the loop has not visited yet. Reading Current twice would throw
        // KeyNotFoundException for it; the snapshot serves the match. (Dictionary
        // add-order enumeration puts app-a — the match — before app-b.)
        var source = new ReloadableMemorySource(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash(KeyA),
            ["CredProx:Callers:app-a:Keys:0:ExpiresAt"] =
                new DateTimeOffset(2100, 1, 1, 0, 0, 0, TimeSpan.Zero).ToString("O"),
            ["CredProx:Callers:app-b:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-b:Keys:0:KeyHash"] = Hash(KeyB),
        });
        using var config = new ConfigurationRoot(new IConfigurationProvider[] { source.Provider });
        var secretSource = new ConfigurationSecretSource(config);
        var registryProvider = new CallerRegistryProvider(
            new CallerBinder(config, new SecretAccessorFactory(secretSource)),
            secretSource,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<CallerRegistryProvider>.Instance);

        var store = new ConfigCallerStore(registryProvider, new ReloadOnFirstCallTimeProvider(source.Provider));

        var match = await store.ResolveKeyAsync(KeyA, default);

        Assert.Equal("app-a", match!.Identity.CallerId);
        Assert.False(registryProvider.Current.TryGet("app-b", out _)); // the rebind did land
    }

    private sealed class ReloadableMemorySource(IDictionary<string, string?> initial) : IConfigurationSource
    {
        public ReloadableMemoryProvider Provider { get; } =
            new(new MemoryConfigurationSource { InitialData = initial });

        public IConfigurationProvider Build(IConfigurationBuilder builder) => Provider;
    }

    private sealed class ReloadableMemoryProvider(MemoryConfigurationSource source)
        : MemoryConfigurationProvider(source)
    {
        public void ReloadWithout(IDictionary<string, string?> data)
        {
            Data = data;
            OnReload();
        }
    }

    private sealed class ReloadOnFirstCallTimeProvider(ReloadableMemoryProvider provider) : TimeProvider
    {
        private int _fired;

        public override DateTimeOffset GetUtcNow()
        {
            if (Interlocked.Exchange(ref _fired, 1) == 0)
            {
                // Drop app-b: the loop has visited app-a (the match, which called here)
                // but not yet app-b, whose id came from the old snapshot.
                provider.ReloadWithout(new Dictionary<string, string?>
                {
                    ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
                    ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash(KeyA),
                    ["CredProx:Callers:app-a:Keys:0:ExpiresAt"] =
                        new DateTimeOffset(2100, 1, 1, 0, 0, 0, TimeSpan.Zero).ToString("O"),
                });
            }

            return new DateTimeOffset(2026, 10, 14, 12, 0, 0, TimeSpan.Zero);
        }
    }

    private static CallerRegistryProvider Registry(params (string Caller, (string KeyId, string Value, DateTimeOffset? Expires)[] Keys)[] callers)
    {
        var entries = new Dictionary<string, string?>();
        foreach (var (caller, keys) in callers)
        {
            for (var i = 0; i < keys.Length; i++)
            {
                entries[$"CredProx:Callers:{caller}:Keys:{i}:KeyId"] = keys[i].KeyId;
                entries[$"CredProx:Callers:{caller}:Keys:{i}:KeyHash"] = Hash(keys[i].Value);
                if (keys[i].Expires is { } expires)
                {
                    entries[$"CredProx:Callers:{caller}:Keys:{i}:ExpiresAt"] =
                        expires.ToString("O");
                }
            }
        }

        var config = new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
        return new CallerRegistryProvider(
            new CallerBinder(config, new SecretAccessorFactory(new ConfigurationSecretSource(config))),
            new ConfigurationSecretSource(config),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<CallerRegistryProvider>.Instance);
    }

    private static ConfigCallerStore Store(params (string Caller, (string KeyId, string Value, DateTimeOffset? Expires)[] Keys)[] callers) =>
        new(Registry(callers), TimeProvider.System);

    private static string Hash(string keyValue) =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(keyValue))).ToLowerInvariant();

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
