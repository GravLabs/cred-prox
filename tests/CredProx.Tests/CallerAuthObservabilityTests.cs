using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using CredProx;
using CredProx.Abstractions;
using CredProx.CallerKeys;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using System.Text.Encodings.Web;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// Operator-facing log lines on the caller-authentication path (M31 mutation triage):
/// the failed-auth warning, the success debug line, and the rebind-success information
/// line are behaviour an operator greps for — the tests pin their existence, level and
/// content, and that a failure line never carries the key value. The caller-token
/// refusal reasons (M39, ADR-0004) are pinned here too, exact-message, so wording
/// drift breaks a test instead of silently blinding log-based operations.
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
            new CallerBinder(config, new SecretAccessorFactory(secretSource), []),
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
        var accessorFactory = new SecretAccessorFactory(secretSource);
        var registryProvider = new CallerRegistryProvider(
            new CallerBinder(config, accessorFactory, []),
            [new CallerKeyTableContributor(config, accessorFactory)],
            config,
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
        services.AddSingleton(registryProvider);
        services.AddCredProxCallerAuthenticator<CallerKeyAuthenticator>(config);
        context.RequestServices = services.BuildServiceProvider();
        return context;
    }

    [Fact]
    public async Task TokenPath_StaleToken_LogsRefusalReason_RunsBeforeAnyMapper()
    {
        var logs = new CapturingLoggerFactory();
        var mapper = new StubTokenMapper(mapping: null);
        var staleIat = DateTimeOffset.UtcNow.AddHours(-2).ToUnixTimeSeconds();
        var context = TokenContext(
            logs,
            new CallerTokenOptions { MaxTokenAge = TimeSpan.FromMinutes(15) },
            mapper,
            TokenPrincipal(staleIat));

        await new CallerAuthenticationFeature().ApplyAsync(context, default);

        Assert.Contains(
            logs.Entries,
            e => e.Level == LogLevel.Warning
                && e.Message == "Caller token refused (stale); client id 'agent-app-1'.");
        Assert.False(mapper.WasCalled); // the age bound is CredProx's own, ahead of any mapper
        Assert.True(context.Features.Get<CredProxRequestState>()!.IsAborted);
    }

    [Fact]
    public async Task TokenPath_UnlistedToken_LogsRefusalReason()
    {
        var logs = new CapturingLoggerFactory();
        var mapper = new StubTokenMapper(mapping: null);
        var context = TokenContext(logs, new CallerTokenOptions(), mapper, TokenPrincipal(issuedAtSeconds: null));

        await new CallerAuthenticationFeature().ApplyAsync(context, default);

        Assert.Contains(
            logs.Entries,
            e => e.Level == LogLevel.Warning
                && e.Message == "Caller token refused (unlisted); client id 'agent-app-1'.");
        Assert.True(mapper.WasCalled);
    }

    [Fact]
    public async Task TokenPath_NoNamedRuleMatched_LogsRefusalReason()
    {
        var logs = new CapturingLoggerFactory();
        var (feature, context) = AllowListContext(
            logs,
            operations: [("reports", "GET", "/reports/*", "reports-read")],
            scopes: ["other-role"]);

        await feature.ApplyAsync(context, default);

        Assert.Contains(
            logs.Entries,
            e => e.Level == LogLevel.Warning
                && e.Message == "Caller token refused (no named operation rule matched); "
                    + "caller 'app-a', client id 'client-sec-a'.");
    }

    [Fact]
    public async Task TokenPath_CallerWithoutNamedRules_LogsRefusalReason()
    {
        var logs = new CapturingLoggerFactory();
        var (feature, context) = AllowListContext(logs, operations: [], scopes: ["anything"]);

        await feature.ApplyAsync(context, default);

        Assert.Contains(
            logs.Entries,
            e => e.Level == LogLevel.Warning
                && e.Message == "Caller token refused (the caller declares no named operations); "
                    + "caller 'app-a', client id 'client-sec-a'.");
    }

    [Fact]
    public async Task TokenPath_OptionsNotRegistered_Throws_FailClosed()
    {
        var logs = new CapturingLoggerFactory();
        var mapper = new StubTokenMapper(new CallerTokenMapping(
            new CallerIdentity("app-a", "token:abc", "agent-app-1"),
            new HashSet<string>(StringComparer.Ordinal)));
        var context = TokenContext(logs, options: null, mapper, TokenPrincipal(issuedAtSeconds: null));

        // The token path cannot enforce its age bound without its options; a missing
        // registration is a broken container, not a licence to admit unchecked tokens.
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => new CallerAuthenticationFeature().ApplyAsync(context, default).AsTask());
    }

    [Fact]
    public void TokenPath_OptionsPreRegisteredByHost_ConfiguredBoundStillWins()
    {
        var entries = new Dictionary<string, string?>
        {
            ["CredProx:CallerToken:Authority"] = "https://issuer.example",
            ["CredProx:CallerToken:Audience"] = "credprox-api",
            ["CredProx:CallerToken:MaxTokenAge"] = "00:15:00",
        };
        var config = new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();

        // A host registering its own options before CredProx's extension must not
        // silently drop the configured MaxTokenAge bound.
        services.AddSingleton(new CallerTokenOptions { MaxTokenAge = TimeSpan.FromHours(12) });
        services.AddCredProxCallerTokenAuthentication(config);

        var options = services.BuildServiceProvider().GetRequiredService<CallerTokenOptions>();

        Assert.Equal(TimeSpan.FromMinutes(15), options.MaxTokenAge);
        Assert.Equal("https://issuer.example", options.Authority);
    }

    private static ClaimsPrincipal TokenPrincipal(long? issuedAtSeconds)
    {
        var claims = new List<Claim> { new("azp", "agent-app-1") };
        if (issuedAtSeconds is { } iat)
        {
            claims.Add(new Claim("iat", iat.ToString(CultureInfo.InvariantCulture)));
        }

        var identity = new ClaimsIdentity(claims, authenticationType: CallerTokenOptions.Scheme);
        return new ClaimsPrincipal(identity);
    }

    private static DefaultHttpContext TokenContext(
        CapturingLoggerFactory logs,
        CallerTokenOptions? options,
        StubTokenMapper mapper,
        ClaimsPrincipal principal)
    {
        var context = M4Contexts.Create(out _);
        var entries = new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("unused"),
        };
        var config = new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
        var secretSource = new ConfigurationSecretSource(config);
        var accessorFactory = new SecretAccessorFactory(secretSource);
        var registryProvider = new CallerRegistryProvider(
            new CallerBinder(config, accessorFactory, []),
            [new CallerKeyTableContributor(config, accessorFactory)],
            config,
            secretSource,
            NullLogger<CallerRegistryProvider>.Instance);
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<ILoggerFactory>(logs);
        services.AddOptions();
        // The caller-key store and scheme stay registered: they are the inputs this harness
        // was built with, and the key scheme resolves through DI below.
        services.AddSingleton<ICallerStore>(new ConfigCallerStore(registryProvider, TimeProvider.System));
        if (options is not null)
        {
            services.AddSingleton(options);
        }

        services.AddSingleton(new StubTokenPrincipal(principal));
        services.AddSingleton<ICallerTokenMapper>(mapper);
        services.AddAuthentication()
            .AddScheme<CallerKeyOptions, CallerKeyAuthenticationHandler>(CredProxAuth.CallerKeyScheme, _ => { })
            .AddScheme<AuthenticationSchemeOptions, StubTokenAuthenticationHandler>(
                CallerTokenOptions.Scheme, _ => { });
        services.AddSingleton(registryProvider);
        services.AddCredProxCallerAuthenticator<CallerTokenAuthenticator>(config);
        context.RequestServices = services.BuildServiceProvider();
        return context;
    }

    private static (OperationAllowListFeature Feature, DefaultHttpContext Context) AllowListContext(
        CapturingLoggerFactory logs,
        (string? Route, string Method, string Path, string? Name)[] operations,
        string[] scopes)
    {
        var entries = new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = Hash("unused"),
        };
        for (var i = 0; i < operations.Length; i++)
        {
            if (operations[i].Route is { } route)
            {
                entries[$"CredProx:Callers:app-a:Operations:{i}:Route"] = route;
            }

            entries[$"CredProx:Callers:app-a:Operations:{i}:Methods:0"] = operations[i].Method;
            entries[$"CredProx:Callers:app-a:Operations:{i}:Paths:0"] = operations[i].Path;
            if (operations[i].Name is { } name)
            {
                entries[$"CredProx:Callers:app-a:Operations:{i}:Name"] = name;
            }
        }

        var config = new ConfigurationBuilder().AddInMemoryCollection(entries).Build();
        var secretSource = new ConfigurationSecretSource(config);
        var registryProvider = new CallerRegistryProvider(
            new CallerBinder(config, new SecretAccessorFactory(secretSource), []),
            secretSource,
            NullLogger<CallerRegistryProvider>.Instance);

        var context = M4Contexts.Create(out _);
        context.Request.Method = "GET";
        context.Request.Path = "/reports/q1";
        context.Features.Set(new CallerIdentity("app-a", "token:abc", "client-sec-a"));
        context.Features.Set(new CallerRequestScopes(new HashSet<string>(scopes, StringComparer.Ordinal)));

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<ILoggerFactory>(logs);
        context.RequestServices = services.BuildServiceProvider();

        return (new OperationAllowListFeature(registryProvider), context);
    }

    private sealed class StubTokenPrincipal(ClaimsPrincipal principal)
    {
        public ClaimsPrincipal Principal { get; } = principal;
    }

    private sealed class StubTokenMapper(CallerTokenMapping? mapping) : ICallerTokenMapper
    {
        public bool WasCalled { get; private set; }

        public CallerTokenMapping? MapToken(ClaimsPrincipal principal)
        {
            WasCalled = true;
            return mapping;
        }
    }

    private sealed class StubTokenAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        StubTokenPrincipal principalHolder)
        : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        protected override Task<AuthenticateResult> HandleAuthenticateAsync() =>
            Task.FromResult(AuthenticateResult.Success(
                new AuthenticationTicket(principalHolder.Principal, Scheme.Name)));

        protected override Task HandleChallengeAsync(AuthenticationProperties properties) => Task.CompletedTask;

        protected override Task HandleForbiddenAsync(AuthenticationProperties properties) => Task.CompletedTask;
    }
}
