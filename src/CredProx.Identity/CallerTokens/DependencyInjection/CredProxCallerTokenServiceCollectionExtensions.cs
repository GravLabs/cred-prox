using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http;
using CredProx;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// DI entry point of the caller-token layer in CredProx.Identity (ADR-0004). The caller-token
/// validation layer registers here — the JWT bearer handler and its options live in this
/// package, and the core carries no token validation: a host gets the token path by
/// referencing this package and chaining
/// <see cref="CredProxIdentityBuilderExtensions.AddIdentity"/> on the builder the
/// <c>AddCredProx</c> entry hands back.
/// </summary>
[Experimental("CREDPROX001")]
internal static class CredProxCallerTokenServiceCollectionExtensions
{
    /// <summary>
    /// Registers the caller-token validation layer (ADR-0004): the stock ASP.NET Core JWT
    /// bearer handler under <see cref="CallerTokenOptions.Scheme"/>, configured from
    /// <c>CredProx:CallerToken</c> (<c>Authority</c> and <c>Audience</c> required — like
    /// <c>CredProx:CallerAuth</c>, unknown keys and a missing issuer or audience fail
    /// registration). CredProx mints nothing: Entra — or any OIDC issuer — signs, and the
    /// framework validates signature, issuer, audience and expiry. The caller policy
    /// (<see cref="CredProxAuth.CallerPolicy"/>) accepts this scheme alongside the caller
    /// API-key scheme; mapping a validated principal to a caller is the
    /// <c>ICallerTokenMapper</c> layer. Swapping this scheme for another handler (multi-tenant
    /// Entra, introspection) changes nothing above it: pass <paramref name="registerScheme"/>
    /// and the host's handler replaces the stock one. This extension also validates every
    /// <c>CredProx:Callers:&lt;id&gt;:TokenClientIds</c> entry — blank, padded or
    /// double-listed client ids refuse registration — because this package owns that key.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The application configuration root.</param>
    /// <param name="registerScheme">
    /// Optional swap point for the validation handler (ADR-0004). When supplied, this
    /// extension calls it <b>instead of</b> adding the stock JWT bearer handler; the host
    /// registers its own handler under <see cref="CallerTokenOptions.Scheme"/>
    /// (<c>Microsoft.Identity.Web</c>, another OIDC issuer, an introspection handler).
    /// <c>Authority</c> and <c>Audience</c> are then the host's business: they are not
    /// required and no JWT bearer configuration is bound. Everything else is unchanged in
    /// both paths — the <see cref="CallerTokenOptions"/> registration, the mapper, the
    /// startup guard, and the <c>MaxTokenAge</c> bound the caller-authentication stage
    /// enforces from those options. The replacement handler must deliver the raw claim
    /// names CredProx reads — <c>roles</c>/<c>scp</c>, <c>azp</c>/<c>appid</c>, and
    /// <c>iat</c> — for example by setting <c>MapInboundClaims = false</c> on a JWT bearer
    /// handler; otherwise configure <c>ScopeClaimNames</c> and <c>ClientClaimNames</c> to
    /// the names it emits. A renamed <c>roles</c> claim fails closed: the token's roles
    /// match no named rule, so every caller token gets a 403. A host that only wants to
    /// adjust the stock handler passes nothing: <see cref="CallerTokenOptions.RequireHttpsMetadata"/>
    /// is a configuration key, and anything beyond it is standard
    /// <c>services.PostConfigure&lt;JwtBearerOptions&gt;(CallerTokenOptions.Scheme, …)</c>.
    /// </param>
    /// <returns>The same <paramref name="services"/>, for chaining.</returns>
    internal static IServiceCollection AddCredProxCallerTokenAuthentication(
        this IServiceCollection services,
        IConfiguration configuration,
        Action<AuthenticationBuilder>? registerScheme = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions();

        var callerTokenOptions = new CallerTokenOptions();
        var callerTokenSection = configuration.GetSection("CredProx:CallerToken");
        callerTokenSection.Bind(callerTokenOptions);

        // Fail closed (the M14a CallerAuth rule): a typo here would silently validate
        // against the wrong issuer or audience — every token in the tenant would pass.
        // Array keys legitimately nest, so only unknown parents are rejected; a nested
        // scalar (Authority:Foo) binds null and is caught by the required-value checks.
        var knownKeys = new[]
        {
            nameof(CallerTokenOptions.Authority),
            nameof(CallerTokenOptions.Audience),
            nameof(CallerTokenOptions.RequireHttpsMetadata),
            nameof(CallerTokenOptions.MaxTokenAge),
            nameof(CallerTokenOptions.ClientClaimNames),
            nameof(CallerTokenOptions.ScopeClaimNames),
        };
        foreach (var child in callerTokenSection.GetChildren())
        {
            if (!knownKeys.Contains(child.Key, StringComparer.OrdinalIgnoreCase))
            {
                throw new OptionsValidationException(
                    "CredProx:CallerToken",
                    typeof(CallerTokenOptions),
                    [$"The CallerToken section declares the unknown configuration key '{child.Key}'. "
                        + $"Known keys: {string.Join(", ", knownKeys)}."]);
            }
        }

        // Missing Authority or Audience is not a defaultable choice: without an authority
        // nothing pins who signs, and without an audience a token minted for any other
        // API passes. Refuse registration naming what is missing. These are checks on the
        // DEFAULT handler only: with registerScheme the host validates, so pinning who
        // signs and for which API is the host's own decision (M39, ADR-0004 swap point).
        if (registerScheme is null)
        {
            if (string.IsNullOrWhiteSpace(callerTokenOptions.Authority))
            {
                throw new OptionsValidationException(
                    "CredProx:CallerToken",
                    typeof(CallerTokenOptions),
                    [$"The CallerToken section requires '{nameof(CallerTokenOptions.Authority)}' — "
                        + "the OIDC authority whose published keys validate caller tokens."]);
            }

            if (string.IsNullOrWhiteSpace(callerTokenOptions.Audience))
            {
                throw new OptionsValidationException(
                    "CredProx:CallerToken",
                    typeof(CallerTokenOptions),
                    [$"The CallerToken section requires '{nameof(CallerTokenOptions.Audience)}' — "
                        + "a caller token minted for any other API would otherwise pass."]);
            }

            // The offline opt-out must not survive the copy (slice 5b): false is accepted
            // only for an http Authority on a loopback host — the local issuer stub this
            // key exists for. Any other Authority keeps the https requirement, so a dev
            // setting left in a production config refuses startup instead of quietly
            // accepting a forged key set.
            if (!callerTokenOptions.RequireHttpsMetadata && !IsLoopbackHttpAuthority(callerTokenOptions.Authority))
            {
                throw new OptionsValidationException(
                    "CredProx:CallerToken",
                    typeof(CallerTokenOptions),
                    [$"'{nameof(CallerTokenOptions.RequireHttpsMetadata)}' is false but '{nameof(CallerTokenOptions.Authority)}' "
                        + $"is '{callerTokenOptions.Authority}' — the opt-out holds only for an http Authority on a loopback "
                        + "host (localhost, 127.0.0.1, ::1). It exists for a local issuer stub; any other issuer must be "
                        + "reached over https."]);
            }
        }

        // A MaxTokenAge the operator cannot have meant is worse than none: the config
        // binder reads a bare "15" as 15 DAYS (~1440x the intended minutes), a zero or
        // negative limit 401s every caller token forever behind a generic detail, and a
        // day-scale limit is not the short-lived bound this knob exists to enforce
        // (M39, ADR-0004). Refused at startup like the unknown-key family above.
        if (callerTokenOptions.MaxTokenAge is { } maxAge
            && (maxAge <= TimeSpan.Zero || maxAge >= TimeSpan.FromDays(1)))
        {
            throw new OptionsValidationException(
                "CredProx:CallerToken",
                typeof(CallerTokenOptions),
                [$"The CallerToken section sets '{nameof(CallerTokenOptions.MaxTokenAge)}' to '{maxAge}', "
                    + "which is not a usable maximum token age — it must be greater than zero and less than 24 h. "
                    + "Write the value as d.HH:mm:ss; a bare number is read as days, so 15 minutes is '00:15:00'."]);
        }

        // This package matches client ids verbatim, so the entry-shape rules that keep a
        // silent no-match impossible are owned here, with the key. The rules ride the
        // core's registry validation: host start AND every live rebind (ADR-0004), so a
        // configuration that drifts into a refused shape after start cannot take effect
        // either. The core still accepts TokenClientIds as a caller key (a 0.11.0 config
        // must bind) but reads no values.
        services.AddCredProxCallerRegistryValidator<CallerTokenClientIdRules>();

        // AddSingleton, not TryAddSingleton: the config-bound options are what the token
        // path fail-closes on (GetRequiredService), and the last registration wins — a
        // host that registered its own CallerTokenOptions earlier must not silently drop
        // the configured MaxTokenAge bound (M39).
        services.AddSingleton(callerTokenOptions);

        // M45 security finding R-4: the validation backchannel is decided once, after
        // every options callback — the host's handler runs, wrapped in the F-1 refusal;
        // CredProx's closed default ships when the host supplied none. The registration
        // MUST precede every AddJwtBearer call below: post-configures run in registration
        // order, and JwtBearer's own builds options.Backchannel from the handler property
        // at the moment it runs — a post-configure registered after it decides a property
        // nobody reads again.
        services.AddSingleton<IPostConfigureOptions<JwtBearerOptions>, CallerTokenBackchannelPostConfigure>();

        var callerTokenBuilder = services.AddAuthentication();
        if (registerScheme is null)
        {
            // Validation is the framework handler: signature, issuer, audience, expiry
            // and not-before, with OIDC discovery and key rollover from the authority's
            // metadata.
            callerTokenBuilder.AddJwtBearer(
                CallerTokenOptions.Scheme,
                options =>
                {
                    options.Authority = callerTokenOptions.Authority;
                    options.Audience = callerTokenOptions.Audience;

                    // Offline-stub knob (slice 5b): true by default — production authorities
                    // are https and http metadata is a forged-key door. The stock handler
                    // applies it exactly as it would natively; a swap-point host owns this
                    // on its own handler.
                    options.RequireHttpsMetadata = callerTokenOptions.RequireHttpsMetadata;

                    // M39: no inbound claim renaming on this scheme. Entra's raw
                    // claim names (roles, scp, azp, appid, uti) reach the mapper and the
                    // host's HttpContext.User unchanged — "claim names are met by
                    // configuration" (ADR-0004) is only true when nothing maps them, and
                    // the stock rename would silently empty CallerTokenMapping.Scopes.
                    options.MapInboundClaims = false;

                    // With mapping off the handler's role claim type must name the raw
                    // claim, or ClaimsPrincipal.IsInRole stops seeing app roles.
                    options.TokenValidationParameters.RoleClaimType = "roles";
                    // M45 security findings F-1 and R-4: this backchannel carries OIDC
                    // discovery and the JWKS fetch. It is decided after every Configure
                    // callback by CallerTokenBackchannelPostConfigure — a host handler is
                    // kept and wrapped, never replaced; ours ships when none is supplied.
                    // That post-configure is registered above, before this call, so its
                    // decision lands before JwtBearer builds the Backchannel from it.
                });
        }
        else
        {
            // The swap point (M39, ADR-0004): the host registers its own validation
            // handler under the caller-token scheme — Microsoft.Identity.Web, another
            // OIDC issuer, an introspection handler. Nothing above or below changes,
            // and the stage still enforces MaxTokenAge from the options registered
            // by this extension, so the bound survives the swap.
            registerScheme(callerTokenBuilder);

            // The swap was REQUESTED: mark it so the startup guard can warn when the
            // callback registered no handler under the caller-token scheme (every token
            // would then be refused, silently). A host that never called this extension
            // has no marker, so the guard's scheme-absent path stays silent for it.
            services.AddSingleton<CallerTokenSwapRequested>();
        }

        // The mapping layer only exists with this extension: without it the caller
        // authenticator never attempts the token scheme at all. A host can replace it with a
        // mapper for another claim layout or caller directory.
        services.TryAddSingleton<ICallerTokenMapper, DefaultCallerTokenMapper>();

        // ADR-0005: the built-in token authenticator rides the same public path a
        // third-party one takes — registered after the key authenticator, so a request
        // presenting both credentials keeps the key (registration order decides).
        services.AddCredProxCallerAuthenticator<CallerTokenAuthenticator>(configuration);

        // M39: startup advice — callers that can never admit a token, and a swap that
        // registered no handler. Evaluated at startup, not here (registration order is
        // the host's).
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IHostedService, CallerTokenStartupGuard>());

        return services;
    }

    // The only Authority shape the RequireHttpsMetadata opt-out serves: an explicit http
    // URL whose host is loopback — localhost, any 127/8 address, or ::1. A relative or
    // unparseable Authority is not that shape, so it refuses under the opt-out too.
    private static bool IsLoopbackHttpAuthority(string? authority)
    {
        if (!Uri.TryCreate(authority, UriKind.Absolute, out var uri)
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal))
        {
            return false;
        }

        var host = uri.Host;
        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (host.Length > 2 && host[0] == '[')
        {
            host = host[1..^1]; // Uri.Host keeps the brackets of an IPv6 literal
        }

        return IPAddress.TryParse(host, out var address) && IPAddress.IsLoopback(address);
    }
}
