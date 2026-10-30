using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using System.Text.Encodings.Web;
using CredProx.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CredProx;

/// <summary>
/// The ASP.NET Core authentication handler of the caller API-key scheme (§3.5 "Caller
/// authentication"): reads the configured inbound header, resolves the value through
/// <see cref="ICallerStore"/>, and on success produces a principal carrying the
/// <c>credprox.caller</c> and <c>credprox.keyid</c> claims. A missing, unknown, expired or
/// revoked key fails identically — the caller learns only that authentication failed, and
/// the key value never enters a log, a claim or an exception (§5.2 "Caller API keys").
/// The challenge writes the §3.4 <c>401 credprox.caller_unauthenticated</c> problem
/// document, so middleware-based enforcement answers the same body as the built-in
/// pipeline enforcement.
/// </summary>
[Experimental("CREDPROX001")]
public sealed class CallerKeyAuthenticationHandler : AuthenticationHandler<CallerKeyOptions>
{
    private readonly ICallerStore _store;

    /// <summary>Creates the handler.</summary>
    /// <param name="options">The scheme options (header name).</param>
    /// <param name="logger">Logs authentication outcomes; messages never carry the key.</param>
    /// <param name="encoder">The URL encoder required by the base class.</param>
    /// <param name="store">The caller store resolving key values to identities.</param>
    public CallerKeyAuthenticationHandler(
        IOptionsMonitor<CallerKeyOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ICallerStore store)
        : base(options, logger, encoder)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
    }

    /// <inheritdoc />
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var keyValue = Request.Headers[Options.HeaderName].ToString();
        if (string.IsNullOrEmpty(keyValue))
        {
            return AuthenticateResult.Fail("No caller API key was presented.");
        }

        var match = await _store.ResolveKeyAsync(keyValue, Context.RequestAborted).ConfigureAwait(false);
        if (match is null)
        {
            Logger.LogWarning("A caller API key failed authentication on this request.");
            return AuthenticateResult.Fail("The presented API key is not valid.");
        }

        var identity = new ClaimsIdentity(
            [
                new Claim(CallerIdentity.CallerClaimType, match.Identity.CallerId),
                new Claim(CallerIdentity.KeyIdClaimType, match.Identity.KeyId),
            ],
            authenticationType: Scheme.Name,
            nameType: CallerIdentity.CallerClaimType,
            roleType: null);

        Logger.LogDebug("Caller '{Caller}' authenticated with key '{KeyId}'.", match.Identity.CallerId, match.Identity.KeyId);
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name));
    }

    /// <inheritdoc />
    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        await CredProxProblemResponses
            .WriteAsync(Response, StatusCodes.Status401Unauthorized, "credprox.caller_unauthenticated",
                "A valid caller API key is required.")
            .ConfigureAwait(false);
    }
}
