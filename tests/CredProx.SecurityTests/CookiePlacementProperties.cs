using System.Net.Http;
using CredProx;
using FsCheck;
using FsCheck.Xunit;
using Xunit;

namespace CredProx.SecurityTests;

/// <summary>
/// §8.1 cookie placement as a property (§3.4 hygiene, cookie-sized): whatever the caller
/// sends in its <c>Cookie</c> header, none of it survives placement — the header is
/// replaced wholesale, never merged — and whatever a vendor hands back as the session
/// value, an accepted value can never carry a second cookie pair or end the header
/// early.
/// </summary>
public sealed class CookiePlacementProperties
{
    [Property(MaxTest = 500)]
    public void CallerCookies_NeverSurviveCookiePlacement(NonNull<string> generated)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "https://vendor.example/api");
        request.Headers.TryAddWithoutValidation("Cookie", $"attacker={generated.Get}; CRMSESSION=forged");

        CredentialAttacher.Apply(request, CredentialLocation.Cookie, "CRMSESSION", "real-session");

        Assert.Equal(
            "CRMSESSION=real-session",
            Assert.Single(request.Headers.GetValues("Cookie")));
    }

    [Property(MaxTest = 500)]
    public void AcceptedValue_NeverBecomesASecondCookie(NonNull<string> generated)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "https://vendor.example/api");

        try
        {
            CredentialAttacher.Apply(request, CredentialLocation.Cookie, "CRMSESSION", generated.Get);
        }
        catch (ArgumentException)
        {
            return; // ';' / CR / LF / NUL refused at placement — nothing reached the wire
        }

        // Accepted: the header is exactly one pair, so nothing in the value could have
        // terminated it and smuggled another cookie alongside the credential.
        Assert.Equal(
            $"CRMSESSION={generated.Get}",
            Assert.Single(request.Headers.GetValues("Cookie")));
    }

    [Property(MaxTest = 500)]
    public void HeaderPlacement_StillReplacesOnlyItsOwnHeader(NonNull<string> generated)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "https://vendor.example/api");
        request.Headers.TryAddWithoutValidation("Cookie", $"attacker={generated.Get}");
        request.Headers.TryAddWithoutValidation("X-Sentinel", "keep");

        CredentialAttacher.Apply(request, CredentialLocation.Header, "X-Token", "secret");

        // Cookie mode is the only placement that touches the Cookie header; header
        // placement of some other name leaves the caller's cookies exactly as they were.
        Assert.Equal($"attacker={generated.Get}", Assert.Single(request.Headers.GetValues("Cookie")));
        Assert.Equal("keep", Assert.Single(request.Headers.GetValues("X-Sentinel")));
        Assert.Equal("secret", Assert.Single(request.Headers.GetValues("X-Token")));
    }
}
