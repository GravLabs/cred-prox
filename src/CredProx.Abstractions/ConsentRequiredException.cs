using System.Diagnostics.CodeAnalysis;

namespace CredProx.Abstractions;

/// <summary>
/// Thrown by a credential provider that knows the end user has not yet authorized this
/// application (see <c>docs/credprox-plan.md</c> §8.3). The core turns this into
/// <c>401 credprox.consent_required</c> and does not forward the request: unlike the
/// generic <c>credential_unavailable</c> 502 (the <em>credential</em> is broken), this is
/// a real next step — the caller opens or relays <see cref="AuthorizeUrl"/>, the user
/// consents at the identity provider, and the request is retried afterwards.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="AuthorizeUrl"/> rides the problem response as the <c>authorize_url</c>
/// extension member, but only when it is an absolute http(s) URL without embedded
/// credentials — anything else (a relative reference, a non-browser scheme such as
/// <c>javascript:</c>, or userinfo) is left out of the response. The consent problem
/// itself is returned either way.
/// </para>
/// <para>
/// On the refresh-on-401 path the response cannot be rewritten: there the upstream's own
/// 401 is returned untouched and no retry is attempted — consent is interactive, so a
/// silent retry could not help.
/// </para>
/// </remarks>
[Experimental("CREDPROX001")]
public sealed class ConsentRequiredException : InvalidOperationException
{
    /// <summary>Creates the exception carrying the URL that starts the consent flow.</summary>
    /// <param name="authorizeUrl">
    /// The identity provider's authorize URL for this user and application. Surfaced to
    /// the caller as the problem's <c>authorize_url</c> extension member when it is a safe
    /// absolute http(s) URL. Never contains the user's credentials or tokens.
    /// </param>
    /// <param name="message">
    /// A developer-facing message naming the credential — no secret values. It stays in
    /// logs and never enters the response body.
    /// </param>
    public ConsentRequiredException(string authorizeUrl, string message)
        : base(message)
    {
        ArgumentException.ThrowIfNullOrEmpty(authorizeUrl);
        AuthorizeUrl = authorizeUrl;
    }

    /// <summary>The URL that starts the consent flow; see the remarks for how it is surfaced.</summary>
    public string AuthorizeUrl { get; }
}
