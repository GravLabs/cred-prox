using System.Collections.Specialized;
using System.Web;

namespace CredProx;

/// <summary>
/// Places an obtained credential value on an outbound request, replacing any existing
/// value instead of duplicating it (§5.2 "Static key" row: overwritten, not duplicated;
/// the same rule holds for every placement). Pure with respect to <see cref="HttpRequestMessage"/>
/// state so the semantics are testable without the YARP pipeline (M4 wraps this in the
/// request feature).
/// </summary>
/// <remarks>
/// The query rebuild normalizes pass-through parameters as a side effect: duplicate keys
/// are merged comma-separated, a literal <c>+</c> becomes <c>%20</c>, and <c>?x</c>
/// becomes <c>?x=</c>. The credential parameter itself is always replaced exactly once.
/// If a vendor proves sensitive to pass-through normalization, M4 can switch to
/// append-only surgery on the raw query string.
/// </remarks>
internal static class CredentialAttacher
{
    public static void Apply(
        HttpRequestMessage request,
        CredentialLocation location,
        string name,
        string value,
        string? prefix = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentNullException.ThrowIfNull(value);

        var content = string.IsNullOrEmpty(prefix) ? value : prefix + value;

        if (location == CredentialLocation.Header)
        {
            // Remove-then-add: a caller-supplied header is replaced, not merged
            // (§3.4 header hygiene: Authorization is replaced, not merged).
            request.Headers.Remove(name);
            request.Headers.Add(name, content);
            return;
        }

        if (location == CredentialLocation.Cookie)
        {
            // The whole Cookie header is replaced, never merged: a caller-supplied Cookie
            // carries the caller's own cookies, and merging would smuggle them to the
            // vendor next to the credential (§3.4 header hygiene, cookie-sized version).
            if (!IsValidCookieName(name))
            {
                throw new ArgumentException(
                    $"Cookie name '{name}' is not a valid RFC 6265 cookie name.",
                    nameof(name));
            }

            EnsureCookieValueSafe(content);

            request.Headers.Remove("Cookie");
            request.Headers.Add("Cookie", $"{name}={content}");
            return;
        }

        var uri = request.RequestUri
            ?? throw new InvalidOperationException("The request has no URI to attach a query credential to.");

        var query = HttpUtility.ParseQueryString(uri.Query);
        query[name] = content; // indexer replaces an existing key, never duplicates it

        var builder = new UriBuilder(uri)
        {
            Query = Rebuild(query),
        };
        request.RequestUri = builder.Uri;
    }

    /// <summary>
    /// RFC 6265 §4.1.1: a cookie name is an RFC 2616 token — no CTLs, no spaces, no
    /// tspecials. Startup validation rejects bad names; this guard backs it up for
    /// options built programmatically.
    /// </summary>
    public static bool IsValidCookieName(string name)
    {
        if (string.IsNullOrEmpty(name))
        {
            return false;
        }

        foreach (var c in name)
        {
            if (c <= 0x20 || c >= 0x7f || "()<>@,;:\\\"/[]?={}".IndexOf(c) >= 0)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// A credential value placed in a cookie must not be able to end the pair or the
    /// header: <c>;</c> would inject a second cookie, and CR/LF would split the request
    /// (§3.4 header hygiene). NUL is rejected likewise. Since M23 review note N2 the
    /// guard also refuses DEL and everything above ASCII: request headers travel as
    /// Latin-1 bytes, so a non-ASCII value cannot round-trip faithfully to the vendor —
    /// refusing it beats silently maiming it. The vendor's own <c>Set-Cookie</c> path
    /// could never produce such a value (response headers decode as Latin-1); this
    /// backs up the attacher for values built programmatically.
    /// </summary>
    private static void EnsureCookieValueSafe(string value)
    {
        foreach (var c in value)
        {
            if (c is '\r' or '\n' or '\0' or ';' || c >= 0x7f)
            {
                throw new ArgumentException(
                    "A cookie credential value must be ASCII and cannot contain ';', CR, "
                    + "LF or NUL; it would inject extra cookies, split the request, or "
                    + "not survive the Latin-1 framing of request headers.",
                    nameof(value));
            }
        }
    }

    private static string Rebuild(NameValueCollection query)
    {
        var parts = new List<string>(query.Count);
        foreach (var key in query.AllKeys)
        {
            parts.Add($"{Uri.EscapeDataString(key!)}={Uri.EscapeDataString(query[key] ?? string.Empty)}");
        }

        return string.Join('&', parts);
    }
}
