using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

namespace CredProx;

/// <summary>
/// Arms the metering reload check (M50 fold LOW-4): an unknown key introduced under
/// <c>CredProx:Metering</c> by a configuration reload must fail closed the way it does at
/// startup, and M45 security finding F-5 says how a reload callback does that safely:
/// catch everything but a cancellation, log the error TYPE only (a binder or provider
/// message can carry secret-shaped detail — no exception object and no message reaches the
/// log), keep the last-known-good options, and never throw on the reload thread. The
/// options instance is bound once at startup and never rebound, so the walk only ever
/// validates: a rejected reload leaves the previous window in force.
/// </summary>
/// <remarks>
/// ChangeToken.OnChange re-arms, so this keeps firing across reloads; the registration
/// lives as long as this singleton — the same shape as the registry providers' own reload
/// walks (F-5). The metering response feature resolves this guard, and the startup
/// validator constructs that feature at host start, so the walk is live before the app
/// serves a request.
/// </remarks>
internal sealed class CredProxMeteringReloadGuard
{
    public CredProxMeteringReloadGuard(IConfiguration configuration, ILogger<CredProxMeteringReloadGuard> logger)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(logger);

        ChangeToken.OnChange(configuration.GetReloadToken, () =>
        {
            try
            {
                CredProxConfigValidation.RejectUnknownKeysAtStartup(
                    configuration, "CredProx:Metering", typeof(CredProxMeteringOptions));
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // M45 security finding F-5: the log carries the failure kind only.
                logger.LogError(
                    "CredProx metering rejected a configuration reload ({ErrorType}); keeping the previous configuration.",
                    ex.GetType().Name);
            }
        });
    }
}
