using Azure;
using Azure.Core;
using CredProx;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// The add-on <c>TokenCredential</c> type: the scope reaches the Azure credential, the
/// token is cached until its expiry, and pipeline failures surface as
/// <see cref="InvalidOperationException"/> naming only the exception type.
/// </summary>
public sealed class AzureTokenCredentialProviderTests
{
    private static CredentialRequestContext Context(string partition = "p1") =>
        new() { CredentialName = "arm", Partition = partition };

    [Fact]
    public async Task Scope_ReachesTheTokenCredential()
    {
        var credential = new FakeTokenCredential("azure-token", TimeSpan.FromHours(1));
        var provider = CreateProvider(credential);

        var token = await provider.GetCredentialAsync(
            new TokenCredentialOptions { Scope = "https://management.azure.com/.default" },
            TestSecrets.AccessorFor(new()), Context(), default);

        Assert.Equal("azure-token", token);
        Assert.Equal(["https://management.azure.com/.default"], Assert.Single(credential.RequestedScopes));
    }

    [Fact]
    public async Task Token_IsCachedUntilExpiry()
    {
        var time = new FakeTimeProvider();
        var credential = new FakeTokenCredential("azure-token", TimeSpan.FromMinutes(30), time);
        var provider = CreateProvider(credential, time);
        var options = new TokenCredentialOptions { Scope = "scope" };

        await provider.GetCredentialAsync(options, TestSecrets.AccessorFor(new()), Context(), default);

        // Served while now < min(started + 0.8×30min, started + 30min − 30s) = started + 24min.
        time.Advance(TimeSpan.FromMinutes(20));
        await provider.GetCredentialAsync(options, TestSecrets.AccessorFor(new()), Context(), default);
        Assert.Equal(1, credential.CallCount);

        time.Advance(TimeSpan.FromMinutes(5));
        await provider.GetCredentialAsync(options, TestSecrets.AccessorFor(new()), Context(), default);
        Assert.Equal(2, credential.CallCount);
    }

    [Fact]
    public async Task CredentialFailure_WrapsWithExceptionTypeNameOnly()
    {
        var credential = new FakeTokenCredential(new RequestFailedException(401, "hidden detail with secret s3cret"));
        var provider = CreateProvider(credential);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetCredentialAsync(
                new TokenCredentialOptions { Scope = "scope" },
                TestSecrets.AccessorFor(new()), Context(), default).AsTask());

        Assert.Contains("arm", error.Message);
        Assert.Contains(nameof(RequestFailedException), error.Message);
        Assert.DoesNotContain("s3cret", error.Message);
    }

    [Fact]
    public async Task Cancellation_Propagates()
    {
        var credential = new FakeTokenCredential(new OperationCanceledException());
        var provider = CreateProvider(credential);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            provider.GetCredentialAsync(
                new TokenCredentialOptions { Scope = "scope" },
                TestSecrets.AccessorFor(new()), Context(), cts.Token).AsTask());
    }

    [Fact]
    public void Attachment_IsBearerAuthorizationHeader()
    {
        var options = new TokenCredentialOptions { Scope = "scope" };
        var attachment = (IHasAttachment)options;

        Assert.Equal(CredentialLocation.Header, attachment.Location);
        Assert.Equal("Authorization", attachment.Name);
        Assert.Equal("Bearer ", attachment.Prefix);
    }

    [Fact]
    public async Task AddCredProxAzureTokenCredential_BindsThroughTheBinder()
    {
        var time = new FakeTimeProvider();
        var credential = new FakeTokenCredential("arm-token", TimeSpan.FromHours(1), time);
        var configuration = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["CredProx:Credentials:arm:Type"] = "TokenCredential",
                ["CredProx:Credentials:arm:Scope"] = "https://management.azure.com/.default",
            })
            .Build();

        var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
        services.AddCredProxTokenCache();
        services.AddCredProxConfigurationSecrets(configuration);
        services.AddCredProxAzureTokenCredential(credential);
        services.AddCredProxCredentials(configuration);

        var registry = services.BuildServiceProvider().GetRequiredService<CredentialRegistry>();

        var binding = registry.Get("arm");
        Assert.Equal("TokenCredential", binding.TypeName);
        Assert.Equal("arm-token", await binding.GetCredential(
            new CredentialRequestContext { CredentialName = "arm" }, default));

        var request = new HttpRequestMessage(HttpMethod.Get, "https://management.azure.com/subscriptions");
        binding.Attach!(request, "arm-token");
        Assert.Equal("Bearer arm-token", request.Headers.Authorization!.ToString());
    }

    [Fact]
    public void MissingScope_FailsStartup()
    {
        var configuration = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["CredProx:Credentials:arm:Type"] = "TokenCredential",
            })
            .Build();

        var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
        services.AddCredProxTokenCache();
        services.AddCredProxConfigurationSecrets(configuration);
        services.AddCredProxAzureTokenCredential(new FakeTokenCredential("t", TimeSpan.FromHours(1)));
        services.AddCredProxCredentials(configuration);

        var error = Assert.Throws<Microsoft.Extensions.Options.OptionsValidationException>(() =>
            services.BuildServiceProvider().GetRequiredService<CredentialRegistry>());
        Assert.Contains("Scope", error.Message);
    }

    [Fact]
    public void EmptyTokenTypeName_AttachesRawToken()
    {
        var options = new TokenCredentialOptions { Scope = "scope", TokenTypeName = "" };

        Assert.Equal("", ((IHasAttachment)options).Prefix);
    }

    [Fact]
    public void Constructor_RejectsNullArguments()
    {
        var cache = new InMemoryTokenCache(Options.Create(new TokenCacheOptions()), new FakeTimeProvider());
        Assert.Throws<ArgumentNullException>(() => new AzureTokenCredentialProvider(null!, new FakeTokenCredential("t", TimeSpan.FromHours(1))));
        Assert.Throws<ArgumentNullException>(() => new AzureTokenCredentialProvider(cache, null!));
    }

    private static AzureTokenCredentialProvider CreateProvider(
        TokenCredential credential,
        FakeTimeProvider? time = null)
    {
        time ??= new FakeTimeProvider();
        var cache = new InMemoryTokenCache(Options.Create(new TokenCacheOptions()), time);
        return new AzureTokenCredentialProvider(cache, credential);
    }

    private sealed class FakeTokenCredential : TokenCredential
    {
        private readonly string? _token;
        private readonly TimeSpan? _lifetime;
        private readonly Exception? _failure;
        private readonly TimeProvider _time;

        public FakeTokenCredential(string token, TimeSpan lifetime, TimeProvider? time = null)
        {
            _token = token;
            _lifetime = lifetime;
            _time = time ?? TimeProvider.System;
        }

        public FakeTokenCredential(Exception failure)
        {
            _failure = failure;
            _time = TimeProvider.System;
        }

        public int CallCount { get; private set; }

        public List<string[]> RequestedScopes { get; } = [];

        public override AccessToken GetToken(
            TokenRequestContext requestContext,
            CancellationToken cancellationToken) =>
            GetTokenAsync(requestContext, cancellationToken).GetAwaiter().GetResult();

        public override ValueTask<AccessToken> GetTokenAsync(
            TokenRequestContext requestContext,
            CancellationToken cancellationToken)
        {
            CallCount++;
            RequestedScopes.Add(requestContext.Scopes);
            cancellationToken.ThrowIfCancellationRequested();

            if (_failure is not null)
            {
                return ValueTask.FromException<AccessToken>(_failure);
            }

            return new ValueTask<AccessToken>(
                new AccessToken(_token!, _time.GetUtcNow() + _lifetime!.Value));
        }
    }
}
