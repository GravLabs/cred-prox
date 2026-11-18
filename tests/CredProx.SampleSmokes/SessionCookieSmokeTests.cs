using Xunit;

namespace CredProx.SampleSmokes;

// Offline cells for the SessionCookie sample: the gateway host drives the full proxy
// path against the CRM stand-in — form login answered by Set-Cookie, the session
// replayed as a Cookie header per call, per-environment partitions with their own
// accounts and secrets behind a strict allow-list, caller cookies replaced wholesale,
// transparent refresh through server-side expiry, vendor-error normalisation and audit.
[Collection("SessionCookie")]
public class SessionCookieSmokeTests(SessionCookieFixture fixture)
{
    [Fact]
    [Trait("Sample", "SessionCookie")]
    public async Task KeylessAndForgedCalls_AreRefusedAtTheGateway_NoLoginHappens()
    {
        var host = fixture.StartHost();
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(SessionCookieFixture.HostUrl) };
        var before = await fixture.LoginsAsync("sandbox");
        using var noKey = await client.GetAsync("/crm/api/contacts");
        using var forged = await client.SendAsync(CallerRequest("/crm/api/contacts", "not-a-real-key", "sandbox"));
        var after = await fixture.LoginsAsync("sandbox");

        Assert.Equal(401, (int)noKey.StatusCode);
        Assert.Equal(401, (int)forged.StatusCode);
        Assert.Equal(0, after - before); // refused at the gateway; the vendor was never touched
    }

    [Fact]
    [Trait("Sample", "SessionCookie")]
    public async Task FormLogin_IsReplayedAsCookie_ScrubbedAndCached()
    {
        var host = fixture.StartHost();
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(SessionCookieFixture.HostUrl) };
        var before = await fixture.LoginsAsync("sandbox");
        var first = await client.SendAsync(CallerRequest("/crm/api/contacts", SessionCookieFixture.ErpKey, "sandbox"));
        var firstBody = await first.Content.ReadAsStringAsync();

        // 200 means the gateway logged in (form POST → Set-Cookie) and the API accepted
        // the replayed cookie; the caller sees the echo already redacted, never the
        // session value or the login password.
        Assert.True(first.IsSuccessStatusCode,
            $"sandbox call failed: {(int)first.StatusCode} {firstBody}\n{host.Stderr}");
        Assert.Contains("Acme (sandbox CRM)", firstBody, StringComparison.Ordinal);
        Assert.Contains("CRMSESSION=[redacted]", firstBody, StringComparison.Ordinal);
        Assert.DoesNotContain(SessionCookieFixture.SessionMarker, firstBody, StringComparison.Ordinal);
        Assert.DoesNotContain(SessionCookieFixture.SandboxPassword, firstBody, StringComparison.Ordinal);

        // The session is cached: repeated calls ride the same cookie, no second login.
        using var second = await client.SendAsync(CallerRequest("/crm/api/contacts", SessionCookieFixture.ErpKey, "sandbox"));
        var after = await fixture.LoginsAsync("sandbox");
        Assert.True(second.IsSuccessStatusCode);
        Assert.Equal(1, after - before);
    }

    [Fact]
    [Trait("Sample", "SessionCookie")]
    public async Task EachPartition_HasItsOwnAccountLoginAndSession()
    {
        var host = fixture.StartHost();
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(SessionCookieFixture.HostUrl) };
        var sandboxBefore = await fixture.LoginsAsync("sandbox");
        var productionBefore = await fixture.LoginsAsync("production");

        var prod = await client.SendAsync(CallerRequest("/crm/api/contacts", SessionCookieFixture.ErpKey, "production"));
        var prodBody = await prod.Content.ReadAsStringAsync();
        var sandboxAfter = await fixture.LoginsAsync("sandbox");
        var productionAfter = await fixture.LoginsAsync("production");

        // A different partition is a different account and a different secret — its own
        // single login, and the sandbox session untouched.
        Assert.True(prod.IsSuccessStatusCode,
            $"production call failed: {(int)prod.StatusCode} {prodBody}\n{host.Stderr}");
        Assert.Contains("Acme (production CRM)", prodBody, StringComparison.Ordinal);
        Assert.DoesNotContain(SessionCookieFixture.SessionMarker, prodBody, StringComparison.Ordinal);
        Assert.Equal(1, productionAfter - productionBefore);
        Assert.Equal(0, sandboxAfter - sandboxBefore);
    }

    [Fact]
    [Trait("Sample", "SessionCookie")]
    public async Task CallerCookies_AreReplacedNeverMerged()
    {
        var host = fixture.StartHost();
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(SessionCookieFixture.HostUrl) };
        var withCookies = await client.SendAsync(CallerRequest(
            "/crm/api/contacts", SessionCookieFixture.ErpKey, "sandbox", cookie: "theme=dark; CRMSESSION=caller-forged"));
        var cookieBody = await withCookies.Content.ReadAsStringAsync();

        // The vendor's echo carries only the injected pair: the caller's cookies never
        // arrived, and a forged session value cannot ride along.
        Assert.True(withCookies.IsSuccessStatusCode,
            $"call with caller cookies failed: {(int)withCookies.StatusCode} {cookieBody}\n{host.Stderr}");
        Assert.DoesNotContain("theme=dark", cookieBody, StringComparison.Ordinal);
        Assert.DoesNotContain("caller-forged", cookieBody, StringComparison.Ordinal);
        Assert.Contains("CRMSESSION=[redacted]", cookieBody, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Sample", "SessionCookie")]
    public async Task CraftedEnvironment_IsRefusedWithAFourHundred()
    {
        var host = fixture.StartHost();
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(SessionCookieFixture.HostUrl) };
        var crafted = await client.SendAsync(CallerRequest("/crm/api/contacts", SessionCookieFixture.ErpKey, "sandbox-evil"));
        var craftedBody = await crafted.Content.ReadAsStringAsync();

        // The environment header is an exact allow-list, not a Contains match.
        Assert.Equal(400, (int)crafted.StatusCode);
        Assert.Contains("credprox.partition_not_allowed", craftedBody, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Sample", "SessionCookie")]
    public async Task ServerSideExpiry_RefreshesInvisibly_WithOneExtraLogin()
    {
        var host = fixture.StartHost();
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(SessionCookieFixture.HostUrl) };
        var before = await fixture.LoginsAsync("sandbox");
        using var warm = await client.SendAsync(CallerRequest("/crm/api/contacts", SessionCookieFixture.ErpKey, "sandbox"));
        Assert.True(warm.IsSuccessStatusCode);

        await fixture.InvalidateSessionAsync("sandbox");

        var refreshed = await client.SendAsync(CallerRequest("/crm/api/contacts", SessionCookieFixture.ErpKey, "sandbox"));
        var refreshedBody = await refreshed.Content.ReadAsStringAsync();
        var after = await fixture.LoginsAsync("sandbox");

        // The vendor's 401 triggers a re-login and one retry; the caller just sees 200.
        Assert.True(refreshed.IsSuccessStatusCode,
            $"call after server-side expiry failed: {(int)refreshed.StatusCode} {refreshedBody}\n{host.Stderr}");
        Assert.Contains("CRMSESSION=[redacted]", refreshedBody, StringComparison.Ordinal);
        Assert.DoesNotContain(SessionCookieFixture.SessionMarker, refreshedBody, StringComparison.Ordinal);
        Assert.Equal(2, after - before); // the warm login plus exactly one refresh login
    }

    [Fact]
    [Trait("Sample", "SessionCookie")]
    public async Task VendorErrors_AreNormalised_WhileTheOptedOutRouteStaysRaw()
    {
        var host = fixture.StartHost();
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(SessionCookieFixture.HostUrl) };
        var vendorError = await client.SendAsync(CallerRequest(
            "/crm/api/inventory/UNKNOWN-9", SessionCookieFixture.ErpKey, "sandbox"));
        var vendorErrorBody = await vendorError.Content.ReadAsStringAsync();
        Assert.Equal(404, (int)vendorError.StatusCode);
        Assert.Equal("application/problem+json", vendorError.Content.Headers.ContentType?.MediaType);
        Assert.Contains("urn:credprox:errors:vendor", vendorErrorBody, StringComparison.Ordinal);
        Assert.Contains("credprox.vendor_error", vendorErrorBody, StringComparison.Ordinal);
        Assert.Contains("SKU_NOT_FOUND", vendorErrorBody, StringComparison.Ordinal);
        Assert.Contains("UNKNOWN-9", vendorErrorBody, StringComparison.Ordinal);

        var rawError = await client.SendAsync(CallerRequest(
            "/crm-raw/api/inventory/UNKNOWN-9", SessionCookieFixture.ErpKey, "sandbox"));
        var rawErrorBody = await rawError.Content.ReadAsStringAsync();
        Assert.Equal(404, (int)rawError.StatusCode);
        Assert.Equal("application/json", rawError.Content.Headers.ContentType?.MediaType);
        Assert.Contains("SKU_NOT_FOUND", rawErrorBody, StringComparison.Ordinal);
        Assert.DoesNotContain("urn:credprox", rawErrorBody, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Sample", "SessionCookie")]
    public async Task Audit_RecordsProxiedCalls_NoCredentialValueAnywhere()
    {
        var host = fixture.StartHost();
        await fixture.WaitForHostAsync(host);

        using var client = new HttpClient { BaseAddress = new Uri(SessionCookieFixture.HostUrl) };
        using var sandboxCall = await client.SendAsync(CallerRequest("/crm/api/contacts", SessionCookieFixture.ErpKey, "sandbox"));
        using var productionCall = await client.SendAsync(CallerRequest("/crm/api/contacts", SessionCookieFixture.ErpKey, "production"));
        Assert.True(sandboxCall.IsSuccessStatusCode && productionCall.IsSuccessStatusCode,
            $"setup calls failed: sandbox={(int)sandboxCall.StatusCode} production={(int)productionCall.StatusCode}\n{host.Stderr}");

        // Audit records land on the gateway's console (Information under CredProx.Audit).
        await SessionCookieFixture.WaitUntilAsync(
            () => Task.FromResult(host.Stdout.Contains("caller=erp-integration", StringComparison.Ordinal)),
            $"audit line for erp-integration never appeared:\n{host.Stdout}");
        Assert.Contains("credprox.proxied_call", host.Stdout, StringComparison.Ordinal);

        // "Never a credential" is proven for every value in the chain: session cookies,
        // both partition passwords and the caller's own key.
        var output = host.Stdout + host.Stderr;
        Assert.DoesNotContain(SessionCookieFixture.SessionMarker, output, StringComparison.Ordinal);
        Assert.DoesNotContain(SessionCookieFixture.SandboxPassword, output, StringComparison.Ordinal);
        Assert.DoesNotContain(SessionCookieFixture.ProductionPassword, output, StringComparison.Ordinal);
        Assert.DoesNotContain(SessionCookieFixture.ErpKey, output, StringComparison.Ordinal);
    }

    private static HttpRequestMessage CallerRequest(string path, string callerKey, string environment, string? cookie = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Add("X-CredProx-Key", callerKey);
        request.Headers.Add("X-API-Env", environment);
        if (cookie is not null)
        {
            request.Headers.Add("Cookie", cookie);
        }

        return request;
    }
}
