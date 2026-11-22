using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace CredProx;

/// <summary>
/// Refuses startup when a configured caller has no way to authenticate (ADR-0005 fail
/// closed, sharpened per-caller by R1 in ADR-0007): a caller under <c>CredProx:Callers</c>
/// is admitted to startup only if it declares key hashes and the caller-key machinery is
/// registered (the entry brings it from the hash itself since M49), or some other
/// authenticator is registered — the caller-token machinery from <c>CredProx.Identity</c>,
/// or a third-party one through
/// <see cref="CredProxBuilderExtensions.WithCallerAuthenticator{TAuthenticator}"/>.
/// The refusal names each caller left without a way in — a silent 401 for one caller
/// beside a healthy sibling is the shape this catches. It is the mirror of the binder's
/// refusal for the opposite half (caller authentication registered with no caller
/// configured), which the startup validator performs by resolving the caller registry the
/// authenticator registration now brings. The check runs at startup because the
/// authenticator may be registered by any extension in any order. A configuration that
/// declares no callers needs no authenticator and stays silent. The built-in
/// key authenticator is detected by full type name, not by assembly reference — the core
/// must not know the identity package's types (the Operations marker in
/// <see cref="CredProxStartupValidator"/> keeps the same doctrine).
/// </summary>
[Experimental("CREDPROX001")]
internal sealed class CallerAuthenticatorStartupGuard(
    IServiceProvider services,
    IConfiguration configuration) : IHostedService
{
    /// <inheritdoc />
    public Task StartAsync(CancellationToken cancellationToken)
    {
        var callerIds = configuration.GetSection("CredProx:Callers").GetChildren()
            .Select(caller => caller.Key)
            .ToList();
        if (callerIds.Count == 0)
        {
            return Task.CompletedTask; // no callers declared: nothing needs a way in
        }

        var authenticatorNames = services.GetServices<ICallerAuthenticator>()
            .Select(authenticator => authenticator.GetType().FullName)
            .ToHashSet(StringComparer.Ordinal);
        var keyMechanism = authenticatorNames.Contains(typeof(CallerKeyAuthenticator).FullName);
        var anyOtherWay = authenticatorNames.Any(name => name != typeof(CallerKeyAuthenticator).FullName);

        // A keyed caller is only admitted when the machinery that reads those hashes is
        // registered — hashes without the scheme authenticate nobody.
        var withoutWayIn = callerIds.Where(callerId =>
            !(keyMechanism
                && configuration.GetSection($"CredProx:Callers:{callerId}:Keys").GetChildren().Any())
            && !anyOtherWay)
            .ToList();
        if (withoutWayIn.Count == 0)
        {
            return Task.CompletedTask;
        }

        var names = string.Join(", ", withoutWayIn.Select(callerId => $"'{callerId}'"));
        throw new InvalidOperationException(
            $"Callers {names} are configured under 'CredProx:Callers' with no way to authenticate: "
            + "give them key hashes under 'CredProx:Callers:<caller>:Keys' — the caller-key machinery "
            + "registers itself when the core entry reads one — "
            + "or install the CredProx.Identity package and call .AddIdentity(), "
            + "or register an authenticator through WithCallerAuthenticator<T>() (ADR-0005). "
            + "Without one, every caller request would be refused with no credential "
            + "able to admit it.");
    }

    /// <inheritdoc />
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
