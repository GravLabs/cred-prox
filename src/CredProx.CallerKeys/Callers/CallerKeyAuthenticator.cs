using System.Diagnostics.CodeAnalysis;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace CredProx;

/// <summary>
/// The built-in API-key authenticator (ADR-0005): asks the caller-key scheme to authenticate
/// the inbound request and reports the identity its handler established — no scope set, so
/// the operation allow-list applies unchanged. A request without a key (or whose key failed
/// handler validation) is no-credential, so a later registered authenticator still gets its
/// turn. The handler's own diagnostics (failed-authentication warning, per-key debug line)
/// stay in the handler and are unchanged.
/// </summary>
[Experimental("CREDPROX001")]
internal sealed class CallerKeyAuthenticator : ICallerAuthenticator
{
    /// <inheritdoc />
    public string CredentialRequirementHint => "caller API key";

    /// <inheritdoc />
    public async ValueTask<CallerAuthenticationResult> AuthenticateAsync(
        HttpContext context,
        CancellationToken cancellationToken)
    {
        var result = await context
            .AuthenticateAsync(CallerKeyOptions.Scheme)
            .ConfigureAwait(false);
        if (!result.Succeeded || result.Principal is not { } keyPrincipal)
        {
            return CallerAuthenticationResult.NoCredential();
        }

        if (CallerIdentity.FromPrincipal(keyPrincipal) is not { } identity)
        {
            // A principal from this scheme without the caller claim is a contract break;
            // fail closed rather than serve an unidentified caller.
            return CallerAuthenticationResult.Refused();
        }

        return CallerAuthenticationResult.Authenticated(identity);
    }
}
