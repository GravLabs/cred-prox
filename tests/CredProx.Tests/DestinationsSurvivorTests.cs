using CredProx;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage of the destinations folder: the spec parser's failure paths keep the
/// out-parts empty, the shared partition binder lists registered schemes in a stable order
/// and turns a throwing factory into one labeled error, the binding's allow-list is the
/// single rejection gate with the exact 400/403 shapes, the header source reads the value it
/// was given, and the binder keeps a bad template to one error while the provider pins the
/// two rebind log lines.
/// </summary>
public sealed class DestinationsSurvivorTests
{
    private static DestinationBinder Binder(IConfiguration config) =>
        new(config, [new HeaderPartitionSourceFactory()]);

    private static IConfiguration Config(Dictionary<string, string?> entries) =>
        new ConfigurationBuilder().AddInMemoryCollection(entries).Build();

    // ---- PartitionSpec ----

    [Fact]
    public void Spec_FailurePaths_LeaveBothPartsEmpty()
    {
        // Every false path leaves scheme and argument empty: a caller must never see a
        // half-parsed spec. The ':' -only-scheme case additionally pins that the argument
        // was never cut from the separator (an empty scheme must fail before parsing).
        Assert.False(PartitionSpec.TryParse(null, out var s0, out var a0));
        Assert.Equal(string.Empty, s0);
        Assert.Equal(string.Empty, a0);

        Assert.False(PartitionSpec.TryParse("x", out var s1, out var a1));
        Assert.Equal(string.Empty, s1);
        Assert.Equal(string.Empty, a1);

        Assert.False(PartitionSpec.TryParse(":x", out var s2, out var a2));
        Assert.Equal(string.Empty, s2);
        Assert.Equal(string.Empty, a2);

        // A whitespace-only scheme trims to empty: still a failure, not a bound source.
        Assert.False(PartitionSpec.TryParse(" :x", out _, out _));
    }

    [Fact]
    public void Spec_ValidSpec_SplitsAtTheFirstColon()
    {
        Assert.True(PartitionSpec.TryParse("header:X-API-Env", out var scheme, out var argument));
        Assert.Equal("header", scheme);
        Assert.Equal("X-API-Env", argument);
    }

    // ---- PartitionBinder ----

    private sealed class StubFactory(string scheme) : IPartitionSourceFactory
    {
        public string Scheme => scheme;

        public IPartitionSource CreateSource(string argument) => new HeaderPartitionSource(argument);
    }

    private sealed class ThrowingFactory : IPartitionSourceFactory
    {
        public string Scheme => "boom";

        public IPartitionSource CreateSource(string argument) => throw new ArgumentException("boom-arg");
    }

    [Fact]
    public void PartitionBinder_UnknownScheme_ListsRegisteredSchemesInOrder()
    {
        // The known-schemes list is the operator's fix guide: comma-separated, ordered
        // case-insensitively like the lookup that missed.
        var factories = new IPartitionSourceFactory[] { new StubFactory("Zeta"), new StubFactory("alpha") };

        var ok = PartitionBinder.TryBind(
            "nope:x", ["canary"], factories, "destination 'triage'", out var binding, out var error);

        Assert.False(ok);
        Assert.Null(binding);
        Assert.Contains("partition scheme 'nope' has no registered partition source", error, StringComparison.Ordinal);
        Assert.Contains("Registered schemes: alpha, Zeta.", error, StringComparison.Ordinal);
    }

    [Fact]
    public void PartitionBinder_ThrowingFactory_BecomesOneLabeledError()
    {
        // A factory rejecting its argument is a configuration problem, reported as the
        // declaring destination's error with the factory's reason — never an exception
        // escaping the bind.
        var factories = new IPartitionSourceFactory[] { new ThrowingFactory() };

        var ok = PartitionBinder.TryBind(
            "boom:arg", ["canary"], factories, "destination 'triage'", out var binding, out var error);

        Assert.False(ok);
        Assert.Null(binding);
        Assert.Contains("partition 'boom:arg' cannot be created: boom-arg", error, StringComparison.Ordinal);
    }

    // ---- PartitionSourceBinding / PartitionNotAllowedException ----

    [Fact]
    public void RejectionException_DefaultShapeIsBadRequest_AndNamesTheSource()
    {
        var ex = new PartitionNotAllowedException("header 'X-Env'");

        Assert.Equal(
            "The request's partition value is missing or not allowed (header 'X-Env').",
            ex.Message);
        Assert.Equal(400, ex.StatusCode);
        Assert.Equal("credprox.partition_not_allowed", ex.Code);
        Assert.Equal("The requested partition is not allowed.", ex.Title);
    }

    [Fact]
    public void RejectionException_ForbiddenShapeIsOperationNotAllowed()
    {
        var ex = new PartitionNotAllowedException("the caller's identity", PartitionRejection.Forbidden);

        Assert.Equal(403, ex.StatusCode);
        Assert.Equal("credprox.operation_not_allowed", ex.Code);
        Assert.Equal("The caller is not allowed this operation.", ex.Title);
    }

    [Fact]
    public void Binding_ConstructorGuards()
    {
        var source = new HeaderPartitionSource("X-Env");

        Assert.Throws<ArgumentNullException>(() => new PartitionSourceBinding(null!, ["a"], "d"));
        var ex = Assert.Throws<ArgumentNullException>(
            () => new PartitionSourceBinding(source, null!, "d"));
        Assert.Equal("allowed", ex.ParamName);
        var empty = Assert.Throws<ArgumentException>(
            () => new PartitionSourceBinding(source, [], "d"));
        Assert.StartsWith("A partition allow-list must not be empty.", empty.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Binding_ResolvesExactMatches_RejectsEverythingElse()
    {
        var binding = new PartitionSourceBinding(
            new HeaderPartitionSource("X-Env"), ["canary"], "header 'X-Env'");

        await Assert.ThrowsAsync<ArgumentNullException>(() => binding.ResolveAsync(null!, default).AsTask());

        var context = new DefaultHttpContext();
        context.Request.Headers["X-Env"] = "canary";
        Assert.Equal("canary", await binding.ResolveAsync(context, default));

        // Exact ordinal only: a case difference is a different value.
        context.Request.Headers["X-Env"] = "Canary";
        var rejected = await Assert.ThrowsAsync<PartitionNotAllowedException>(
            () => binding.ResolveAsync(context, default).AsTask());
        Assert.Equal(400, rejected.StatusCode);
    }

    // ---- HeaderPartitionSource ----

    [Fact]
    public void HeaderSource_ConstructorAndFactory_GuardTheirArguments()
    {
        Assert.Throws<ArgumentNullException>(() => new HeaderPartitionSource(null!));
        Assert.Throws<ArgumentException>(() => new HeaderPartitionSource(""));

        var factory = new HeaderPartitionSourceFactory();
        Assert.Equal("header", factory.Scheme);
        Assert.Throws<ArgumentNullException>(() => factory.CreateSource(null!));
        Assert.Throws<ArgumentException>(() => factory.CreateSource(""));
    }

    [Fact]
    public async Task HeaderSource_ReturnsTheHeaderValueOrNull()
    {
        // A present header must surface its value — the allow-list's whole input is this
        // read. Missing and present-but-empty both resolve to null (rejected as missing).
        var source = new HeaderPartitionSource("X-Env");
        var context = new DefaultHttpContext();

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => source.GetPartitionAsync(null!, default).AsTask());

        Assert.Null(await source.GetPartitionAsync(context, default));

        context.Request.Headers["X-Env"] = "canary";
        Assert.Equal("canary", await source.GetPartitionAsync(context, default));

        context.Request.Headers["X-Env"] = "";
        Assert.Null(await source.GetPartitionAsync(context, default));
    }

    // ---- DestinationBinder / Registry ----

    [Fact]
    public void Binder_NotAbsoluteTemplate_ReportsOneErrorNotACascade()
    {
        // The template failed the address check; the placeholder-without-Partition rule
        // would fire too, but the first error short-circuits this destination: one fix
        // (the address) is one error, not a misleading second complaint.
        var config = Config(new Dictionary<string, string?>
        {
            ["CredProx:Destinations:acme:Template"] = "not-a-url/{partition}",
        });

        var ex = Assert.Throws<OptionsValidationException>(() => Binder(config).Bind());

        var failure = Assert.Single(ex.Failures);
        Assert.Contains("is not an absolute http(s) address", failure, StringComparison.Ordinal);
    }

    private static Dictionary<string, string?> TwoValidDestinations() => new()
    {
        ["CredProx:Destinations:acme:Template"] = "https://vendor.invalid/{partition}",
        ["CredProx:Destinations:acme:Partition"] = "header:X-Env",
        ["CredProx:Destinations:acme:Allowed:0"] = "canary",
        ["CredProx:Destinations:Beta:Template"] = "https://other.invalid/static",
    };

    [Fact]
    public void Registry_NamesAreOrderedLikeConfigurationLookup()
    {
        // Route metadata references are case-insensitive lookups; the listing orders the
        // same way so diagnostics match what a user typed.
        var registry = Binder(Config(TwoValidDestinations())).Bind();

        Assert.Equal(["acme", "Beta"], registry.Names);
    }

    [Fact]
    public void Registry_GuardAndGet_AndPrefixExpansion()
    {
        var registry = Binder(Config(TwoValidDestinations())).Bind();

        var nullName = Assert.Throws<ArgumentNullException>(() => registry.Get(null!));
        Assert.Equal("name", nullName.ParamName);

        var entry = registry.Get("ACME"); // case-insensitive like configuration keys
        Assert.Equal("https://vendor.invalid/canary", entry.ResolvePrefix("canary"));
        Assert.Throws<ArgumentNullException>(() => entry.ResolvePrefix(null!));
    }

    // ---- provider ----

    private sealed class ManualChangeToken : IChangeToken
    {
        private Action<object?>? _callback;
        private object? _state;

        public bool ActiveChangeCallbacks => true;

        public bool HasChanged => false;

        public IDisposable RegisterChangeCallback(Action<object?> callback, object? state)
        {
            _callback = callback;
            _state = state;
            return new NoopDisposable();
        }

        public void Fire() => _callback?.Invoke(_state);

        private sealed class NoopDisposable : IDisposable
        {
            public void Dispose()
            {
            }
        }
    }

    private sealed class StubSecretSource(ManualChangeToken token) : ISecretSource
    {
        public string Scheme => "triage";

        public ValueTask<string?> GetSecretAsync(string name, CancellationToken cancellationToken) =>
            new((string?)null);

        public IChangeToken GetChangeToken() => token;
    }

    private static DestinationBinder ValidBinder(out ReloadableMemoryConfigurationProvider reloadable)
    {
        var source = new ReloadableMemoryConfigurationSource(TwoValidDestinations());
        var config = new ConfigurationBuilder().Add(source).Build();
        reloadable = (ReloadableMemoryConfigurationProvider)config.Providers
            .OfType<ReloadableMemoryConfigurationProvider>().Single();
        return Binder(config);
    }

    [Fact]
    public void Provider_ConstructorGuards()
    {
        var binder = ValidBinder(out _);
        var secretSource = new StubSecretSource(new ManualChangeToken());
        ILogger<DestinationRegistryProvider> logger = NullLogger<DestinationRegistryProvider>.Instance;

        Assert.Throws<ArgumentNullException>(() => new DestinationRegistryProvider(null!, secretSource, logger));
        Assert.Throws<ArgumentNullException>(() => new DestinationRegistryProvider(binder, null!, logger));
        Assert.Throws<ArgumentNullException>(() => new DestinationRegistryProvider(binder, secretSource, null!));
    }

    [Fact]
    public void Provider_SuccessfulRebind_LogsTheExactLine()
    {
        var binder = ValidBinder(out _);
        var logs = new List<string?>();
        var token = new ManualChangeToken();
        _ = new DestinationRegistryProvider(
            binder,
            new StubSecretSource(token),
            new LoggerFactory([new CapturingLoggerProvider(logs)]).CreateLogger<DestinationRegistryProvider>());

        token.Fire();

        Assert.Contains(
            "CredProx destinations rebound after a configuration change.",
            logs);
    }

    [Fact]
    public void Provider_FailedRebind_LogsTheExactLine_AndKeepsThePreviousRegistry()
    {
        var binder = ValidBinder(out var reloadable);
        var logs = new List<string?>();
        var token = new ManualChangeToken();
        var provider = new DestinationRegistryProvider(
            binder,
            new StubSecretSource(token),
            new LoggerFactory([new CapturingLoggerProvider(logs)]).CreateLogger<DestinationRegistryProvider>());
        var serving = provider.Current.Get("acme");

        // Emptied Template fails validation on reload; the live registry must keep serving
        // and the rejection must be the operator's only signal that the edit was ignored.
        reloadable.Set("CredProx:Destinations:acme:Template", "");
        reloadable.Reload();
        token.Fire();

        Assert.Contains(
            "CredProx destinations failed to rebind after a configuration change; keeping the previous registry.",
            logs);
        Assert.Same(serving, provider.Current.Get("acme"));
    }
}
