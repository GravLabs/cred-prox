using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CredProx;

/// <summary>
/// Startup advice for caller-token configurations: nothing here refuses. Fail-closed
/// refusal of a token scheme without caller authentication is the startup validator's
/// job — the token extension registers the caller pipeline through the authenticator
/// seam, and the validator's eager caller-registry resolution refuses a pipeline with no
/// caller configured before any request is served. This guard warns — without
/// refusing — about callers that list token client ids but name no operation rule: on
/// the token path only named rules admit a request, so such a caller can never admit a
/// token (ADR-0004); its key path is untouched, so startup continues. It also
/// warns — once, without refusing — when a supplied <c>registerScheme</c> callback
/// registered no handler under the caller-token scheme; only the swap marker
/// (<see cref="CallerTokenSwapRequested"/>) tells that case apart from a host that
/// never registered the token layer at all, which stays silent.
/// </summary>
internal sealed class CallerTokenStartupGuard(
    IServiceProvider services,
    IAuthenticationSchemeProvider schemes) : IHostedService
{
    /// <inheritdoc />
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var scheme = await schemes
            .GetSchemeAsync(CallerTokenOptions.Scheme)
            .ConfigureAwait(false);
        if (scheme is null)
        {
            // The scheme is absent for exactly two reasons (M39, ADR-0004): the host
            // supplied a registerScheme callback that registered no handler under the
            // caller-token scheme — then every token request is refused with no other
            // clue, so say so once, in the same advisory style — or the token layer was
            // never registered and the host owns its own scheme set, which is legitimate
            // and silent. The marker exists only in the first case.
            if (services.GetService<CallerTokenSwapRequested>() is not null)
            {
                var swapLogger = services.GetService<ILogger<CallerTokenStartupGuard>>();
                if (swapLogger is not null)
                {
                    swapLogger.LogWarning(
                        "The registerScheme callback registered no handler under {Scheme}; "
                        + "caller-token requests will be refused. Register the handler under that "
                        + "scheme name, or pass no callback to get the default JWT bearer handler.",
                        CallerTokenOptions.Scheme);
                }
            }

            return; // a host that replaced authentication owns its own scheme set
        }

        // The token extension registers this guard and the caller pipeline through the
        // authenticator seam in the same call, so the provider is always registered here;
        // a pipeline with no caller configured is already refused by the startup validator
        // before its hosted services start.
        var registry = services.GetRequiredService<CallerRegistryProvider>().Current;

        // Advisory, once per caller, at startup (M39, ADR-0004): a caller
        // that lists token client ids but names no operation rule can never admit a
        // token — named rules are what a token's roles match — so every token request
        // for it would answer 403 with no local clue why. The key path is unaffected,
        // so this warns and the host starts. The client-id lists are read from
        // configuration — this package owns that key; the core registry only names callers.
        var configuration = services.GetRequiredService<IConfiguration>();
        var logger = services.GetService<ILogger<CallerTokenStartupGuard>>();
        foreach (var callerId in registry.CallerIds)
        {
            if (logger is not null
                && registry.TryGet(callerId, out var definition)
                && configuration.GetSection($"CredProx:Callers:{callerId}:TokenClientIds").GetChildren()
                    .Any(entry => !string.IsNullOrWhiteSpace(entry.Value))
                && !definition.Operations.Any(rule => rule.Name is not null))
            {
                logger.LogWarning(
                    "Caller '{CallerId}' lists token client ids but declares no named operation rule: "
                    + "this caller can never admit a token, because a token gets exactly the operations "
                    + "its roles name. Name one of its operations, or remove the token client ids.",
                    callerId);
            }
        }
    }

    /// <inheritdoc />
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

/// <summary>
/// Registration marker: the host called
/// <see cref="CredProxCallerTokenServiceCollectionExtensions.AddCredProxCallerTokenAuthentication"/>
/// with a <c>registerScheme</c> callback (ADR-0004). The startup guard resolves it
/// optionally to tell a no-handler swap (warn) from a host that never registered the
/// token layer (silent). Internal: no public surface.
/// </summary>
internal sealed class CallerTokenSwapRequested;
