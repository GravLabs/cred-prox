using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;

namespace CredProx;

/// <summary>
/// Decides the caller-token validation backchannel once, after every options callback
/// has run (M45 security finding R-4). Plain assignment inside <c>Configure</c> made
/// the outcome depend on who configured last: before us, the host's handler was
/// silently dropped; after us, a redirect-following host handler reopened the door
/// (F-1). Here neither happens — a host that supplied no <c>BackchannelHttpHandler</c>
/// gets CredProx's redirect-refusing default — stamped with CredProx's default
/// User-Agent, the same one the token-acquisition clients send — replacing only the
/// JwtBearer handler's own default label on that transport, never an explicit host
/// value — because an identity
/// provider's edge can refuse a User-Agent-less request before it answers (product bug
/// 2026-11-22: GitHub's edge answered the UA-less token exchange 403 while every
/// offline cell passed) — and a host that supplied one keeps it, running, wrapped in
/// the same refusal so discovery and the JWKS fetch cannot land on another host's key
/// set. A host that supplies the whole <c>Backchannel</c> client owns that transport
/// itself, User-Agent included; this covers <c>BackchannelHttpHandler</c>.
/// It must be registered before every <c>AddJwtBearer</c> call for this scheme:
/// post-configures run in registration order, and JwtBearer's own builds
/// <c>options.Backchannel</c> from the handler property when it runs — deciding the
/// property afterwards changes a transport nobody reads.
/// Internal — no new public surface.
/// </summary>
internal sealed class CallerTokenBackchannelPostConfigure : IPostConfigureOptions<JwtBearerOptions>
{
    public void PostConfigure(string? name, JwtBearerOptions options)
    {
        if (name != CallerTokenOptions.Scheme)
        {
            return;
        }

        switch (options.BackchannelHttpHandler)
        {
            case null:
                options.BackchannelHttpHandler = new CredProxUserAgentHandler
                {
                    // The JwtBearer handler labels its own requests before the first
                    // delegating handler runs; on this CredProx-built transport the label
                    // is the framework default, so the stamp replaces exactly that label.
                    ReplaceFrameworkDefaultUserAgent = true,
                    InnerHandler = new SocketsHttpHandler
                    {
                        AllowAutoRedirect = false,
                        // Mirrors the pooled-connection lifetime of the credential clients.
                        PooledConnectionLifetime = TimeSpan.FromMinutes(2),
                    },
                };
                break;
            case CallerTokenRedirectGuard:
                break; // already wrapped — reloads must not stack guards
            case CredProxUserAgentHandler:
                break; // already stamped — reloads must not stack stamp layers
            case { } hostHandler:
                options.BackchannelHttpHandler = new CallerTokenRedirectGuard { InnerHandler = hostHandler };
                break;
        }
    }
}
