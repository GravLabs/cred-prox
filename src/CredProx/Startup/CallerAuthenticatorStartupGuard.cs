using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace CredProx;

/// <summary>
/// Refuses startup when callers are configured under <c>CredProx:Callers</c> but no caller
/// authenticator is registered (ADR-0005, fail closed): with callers declared and nothing
/// registered through <see cref="CredProxServiceCollectionExtensions.AddCredProxCallerAuthenticator{TAuthenticator}"/>,
/// every caller request would answer 401 with no way for any credential to admit it. It is
/// the mirror of the binder's refusal for the opposite half (caller authentication registered
/// with no caller configured), which the startup validator performs by resolving the caller
/// registry the authenticator registration now brings. The check runs at startup because the
/// authenticator may be registered by any extension in any order. A configuration that
/// declares no callers needs no authenticator and stays silent.
/// </summary>
[Experimental("CREDPROX001")]
internal sealed class CallerAuthenticatorStartupGuard(
    IServiceProvider services,
    IConfiguration configuration) : IHostedService
{
    /// <inheritdoc />
    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (!configuration.GetSection("CredProx:Callers").GetChildren().Any())
        {
            return Task.CompletedTask; // no callers declared: nothing needs an authenticator
        }

        if (services.GetServices<ICallerAuthenticator>().Any())
        {
            return Task.CompletedTask;
        }

        throw new InvalidOperationException(
            "Callers are configured under 'CredProx:Callers' but no caller authenticator is "
            + $"registered: register at least one through {nameof(CredProxServiceCollectionExtensions.AddCredProxCallerAuthenticator)}()"
            + " (ADR-0005). Without one, every caller request would be refused with no credential "
            + "able to admit it.");
    }

    /// <inheritdoc />
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
