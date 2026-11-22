using System.Net.Http;
using System.Reflection;

namespace CredProx;

/// <summary>
/// Stamps CredProx's default User-Agent on every credential-acquisition client
/// (product bug found by the M46 githubapp live run 2026-11-22, shipped in 0.15.0):
/// .NET's <see cref="HttpClient"/> sends no User-Agent, and GitHub's API edge refuses a
/// UA-less request with 403 "Request forbidden by administrative rules." before any
/// credential is read — so every CredProx-origined token exchange failed against
/// GitHub while every offline cell passed, because no stand-in checked. The stamped
/// value is <c>CredProx/&lt;informational version&gt;</c>; the stamp lands only when the
/// request carries no User-Agent at all, so a value the host set — through the client's
/// <c>DefaultRequestHeaders</c> (which the BCL merges before the first handler runs) or
/// directly on the request — always wins. The forwarder's client never carries this
/// handler: a forwarded caller's own User-Agent passes through as it always did, and
/// CredProx invents none for the caller. Internal — no new public surface.
/// </summary>
internal sealed class CredProxUserAgentHandler : DelegatingHandler
{
    /// <summary>The stamped value: the CredProx assembly's informational version without
    /// the <c>+source-control-revision</c> suffix SourceLink appends.</summary>
    internal static string DefaultUserAgent { get; } = "CredProx/" + InformationalVersionCore();

    /// <summary>The label the JwtBearer handler puts on every backchannel request the
    /// framework itself issues; it is merged onto the request before the first
    /// delegating handler runs. A framework default, not somebody's choice.</summary>
    private const string JwtBearerHandlerUserAgent = "Microsoft ASP.NET Core JwtBearer handler";

    /// <summary>Opt-in for the transports CredProx builds itself (the caller-token
    /// backchannel): replaces the framework's own label with CredProx's stamp. An
    /// explicit host value — through the client's <c>DefaultRequestHeaders</c> or set
    /// directly on the request — still wins either way. Off by default: the
    /// token-acquisition clients keep the plain stamp-only-when-absent rule.</summary>
    internal bool ReplaceFrameworkDefaultUserAgent { get; init; }

    private static string InformationalVersionCore()
    {
        var core = typeof(CredProxUserAgentHandler).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?.Split('+')[0];
        return string.IsNullOrEmpty(core) ? "unknown" : core;
    }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        // Presence only, and TryAddWithoutValidation: the stamp must never throw and
        // never rewrite a value somebody else set, however oddly it parses.
        if (!request.Headers.Contains("User-Agent"))
        {
            request.Headers.TryAddWithoutValidation("User-Agent", DefaultUserAgent);
        }
        else if (ReplaceFrameworkDefaultUserAgent
            && request.Headers.TryGetValues("User-Agent", out var current)
            // The User-Agent parser splits the label into product tokens, so compare
            // the joined wire form, not one header value.
            && string.Equals(string.Join(" ", current), JwtBearerHandlerUserAgent, StringComparison.Ordinal))
        {
            // Only the framework's own label is replaced, on the transports CredProx
            // builds; anything else somebody set — however oddly it parses — still wins.
            request.Headers.Remove("User-Agent");
            request.Headers.TryAddWithoutValidation("User-Agent", DefaultUserAgent);
        }

        return base.SendAsync(request, cancellationToken);
    }
}
