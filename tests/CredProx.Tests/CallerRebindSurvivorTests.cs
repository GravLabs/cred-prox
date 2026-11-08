using System.Collections.Concurrent;
using System.Text;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage of the caller-auth handler and the registry provider: the two
/// identical failure texts a rejected caller sees (missing key and unknown key stay
/// indistinguishable but carry distinct internal reasons), the 401 problem document the
/// challenge writes, and the failed-rebind log line that is the operator's only evidence
/// that a reload was rejected and the old registry is still serving.
/// </summary>
public sealed class CallerRebindSurvivorTests
{
    private sealed class StubStore(CallerKeyMatch? match) : ICallerStore
    {
        public ValueTask<CallerKeyMatch?> ResolveKeyAsync(string keyValue, CancellationToken cancellationToken) =>
            new(match);
    }

    // The handler is resolved through DI exactly as the pipeline builds it (the scheme
    // registration supplies the infrastructure arguments), reached via the context's
    // service provider like any real request.
    private static DefaultHttpContext NewContext(
        CallerKeyMatch? match,
        string? presentedKey,
        List<string?>? logs = null)
    {
        var context = new DefaultHttpContext
        {
            Response = { Body = new MemoryStream() },
        };
        if (presentedKey is not null)
        {
            context.Request.Headers[new CallerKeyOptions().HeaderName] = presentedKey;
        }

        var services = new ServiceCollection();
        services.AddLogging(builder =>
        {
            if (logs is not null)
            {
                builder.AddProvider(new CapturingLoggerProvider(logs));
            }
        });

        services.AddSingleton<ICallerStore>(new StubStore(match));
        services.AddAuthentication()
            .AddScheme<CallerKeyOptions, CallerKeyAuthenticationHandler>(CredProxAuth.CallerKeyScheme, _ => { });
        context.RequestServices = services.BuildServiceProvider();
        return context;
    }

    [Fact]
    public async Task Authenticate_MissingKey_FailsWithItsExactReason()
    {
        var context = NewContext(match: null, presentedKey: null);

        var result = await context.AuthenticateAsync(CredProxAuth.CallerKeyScheme);

        Assert.Equal("No caller API key was presented.", result.Failure!.Message);
    }

    [Fact]
    public async Task Authenticate_UnknownKey_FailsWithItsExactReason_AndLogsNoKeyMaterial()
    {
        var logs = new List<string?>();
        var context = NewContext(match: null, presentedKey: "triage-key-value", logs);

        var result = await context.AuthenticateAsync(CredProxAuth.CallerKeyScheme);

        Assert.Equal("The presented API key is not valid.", result.Failure!.Message);
        // The handler's warning is the audit line; the auth infrastructure adds its own
        // debug entry. Neither may carry the key value.
        Assert.Contains("A caller API key failed authentication on this request.", logs);
        Assert.All(logs, message => Assert.DoesNotContain("triage-key-value", message ?? string.Empty, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Challenge_WritesTheCallerUnauthenticatedProblemDocument()
    {
        var context = NewContext(match: null, presentedKey: null);

        await context.ChallengeAsync(CredProxAuth.CallerKeyScheme, properties: null);

        var body = Encoding.UTF8.GetString(((MemoryStream)context.Response.Body).ToArray());
        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        Assert.Contains("credprox.caller_unauthenticated", body, StringComparison.Ordinal);
        Assert.Contains("A valid caller API key is required.", body, StringComparison.Ordinal);
    }

    // ---- provider: a failed rebind keeps serving and says so ----

    private sealed class MutableSource : IConfigurationSource
    {
        public MutableProvider Provider { get; } = new();

        public IConfigurationProvider Build(IConfigurationBuilder builder) => Provider;
    }

    private sealed class MutableProvider : ConfigurationProvider
    {
        public void SetData(Dictionary<string, string?> entries)
        {
            Data = new ConcurrentDictionary<string, string?>(entries);
            OnReload();
        }
    }

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

    [Fact]
    public void RebindFailure_LogsTheExactLine_AndKeepsThePreviousRegistry()
    {
        var source = new MutableSource();
        source.Provider.SetData(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
            ["CredProx:Callers:app-a:Keys:0:KeyHash"] = "sha256:" + new string('a', 64),
        });
        var config = new ConfigurationBuilder().Add(source).Build();
        var binder = new CallerBinder(config, new SecretAccessorFactory(new ConfigurationSecretSource(config)));
        var logs = new List<string?>();
        var token = new ManualChangeToken();
        var provider = new CallerRegistryProvider(
            binder,
            new StubSecretSource(token),
            new LoggerFactory([new CapturingLoggerProvider(logs)]).CreateLogger<CallerRegistryProvider>());

        Assert.Equal("app-a", provider.Current.Get("app-a").CallerId);

        // A reload that does not bind (the key lost its hash) must not take the live
        // registry down — and must say so loudly, because this is the only signal the
        // operator gets that their edit was ignored.
        source.Provider.SetData(new Dictionary<string, string?>
        {
            ["CredProx:Callers:app-a:Keys:0:KeyId"] = "k1",
        });
        token.Fire();

        Assert.Contains(
            "CredProx callers failed to rebind after a configuration change; keeping the previous registry.",
            logs);
        Assert.Equal("app-a", provider.Current.Get("app-a").CallerId);
    }
}
