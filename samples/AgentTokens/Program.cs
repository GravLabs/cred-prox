using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CredProx;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// E19: agents authenticate with OIDC access tokens (ADR-0004, Entra-first). CredProx
// validates them with the stock JWT bearer handler (signature, issuer, audience, expiry —
// via the authority's published metadata), maps the azp claim to a caller through its
// TokenClientIds, and intersects the token's Entra app roles (roles claim) with that
// caller's NAMED operation rules — scopes narrow, never widen. MaxTokenAge caps how old
// a token may be (measured from iat) even while the issuer still considers it valid.
// Nothing here is Entra-specific: any OIDC issuer that publishes keys works the same way.
builder.Services.AddCredProxTokenCache();
builder.Services.AddCredProxConfigurationSecrets(builder.Configuration);
builder.Services.AddCredProxBuiltInCredentials();
builder.Services.AddCredProxCredentials(builder.Configuration);
builder.Services.AddCredProxCallerAuthentication(builder.Configuration);
builder.Services.AddCredProxCallerTokenAuthentication(builder.Configuration);

// OFFLINE SAMPLE ONLY: the WireMock issuer on this compose network is plain http, and the
// handler requires https metadata by default. A real Entra authority is https — delete this
// line when pointing at one. It mutates the caller-token scheme's options; it does not
// replace them (claim mapping and the role claim type stay as CredProx configured them).
builder.Services.Configure<JwtBearerOptions>(
    CredProxAuth.CallerTokenScheme,
    options => options.RequireHttpsMetadata = false);

builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx(builder.Configuration);

builder.WebHost.UseUrls("http://localhost:5096");


var app = builder.Build();

app.MapReverseProxy();

if (args.Contains("--smoke"))
{
    app.Start();
    using var client = new HttpClient { BaseAddress = new Uri("http://localhost:5096") };

    // The demo signing key: this sample's stand-in for Entra's own signing keys, generated
    // fresh in this process at every smoke run — no private material is committed anywhere.
    // The stub issuer learns its public half as a JWK through the WireMock admin API at
    // priority 0 (above any static mapping that might reappear), and the kid check below
    // fails the smoke if the issuer ever serves a key other than the one signing here.
    const string GeneratedKid = "demo-agent-generated-1";
    using var signingKey = RSA.Create(2048);
    var rsaPublic = signingKey.ExportParameters(includePrivateParameters: false);
    var publicJwk = new Dictionary<string, object>
    {
        ["kty"] = "RSA",
        ["use"] = "sig",
        ["alg"] = "RS256",
        ["kid"] = GeneratedKid,
        ["n"] = Base64UrlEncoder.Encode(rsaPublic.Modulus!),
        ["e"] = Base64UrlEncoder.Encode(rsaPublic.Exponent!),
    };
    using var issuerAdmin = new HttpClient { BaseAddress = new Uri("http://localhost:8085") };
    var registration = await issuerAdmin.PostAsync(
        "/__admin/mappings",
        new StringContent(
            JsonSerializer.Serialize(new
            {
                priority = 0,
                request = new { method = "GET", urlPath = "/jwks" },
                response = new
                {
                    status = 200,
                    headers = new Dictionary<string, string> { ["Content-Type"] = "application/json" },
                    jsonBody = new { keys = new[] { publicJwk } },
                },
            }),
            Encoding.UTF8,
            "application/json"));
    if (!registration.IsSuccessStatusCode)
    {
        return Fail("registering the generated public JWK with the stub issuer", $"{(int)registration.StatusCode}", "2xx");
    }

    using var servedKeys = JsonDocument.Parse(await issuerAdmin.GetStringAsync("/jwks"));
    var servedKid = servedKeys.RootElement.GetProperty("keys")[0].GetProperty("kid").GetString();
    if (servedKid != GeneratedKid)
    {
        return Fail("stub issuer serving the generated key", servedKid ?? "<no key>", $"kid {GeneratedKid}");
    }

    var now = DateTimeOffset.UtcNow;
    string Issue(string azp, object? roles, DateTimeOffset issuedAt, string uti)
    {
        var payload = new Dictionary<string, object>
        {
            ["iss"] = "http://localhost:8085",
            ["aud"] = "credprox-agent-api",
            ["azp"] = azp,
            ["uti"] = uti,
            ["nbf"] = now.AddMinutes(-1).ToUnixTimeSeconds(),
            ["exp"] = now.AddMinutes(5).ToUnixTimeSeconds(),
            ["iat"] = issuedAt.ToUnixTimeSeconds(),
        };
        if (roles is not null)
        {
            payload["roles"] = roles;
        }

        var credentials = new SigningCredentials(
            new RsaSecurityKey(signingKey) { KeyId = GeneratedKid },
            SecurityAlgorithms.RsaSha256);
        return new JsonWebTokenHandler().CreateToken(JsonSerializer.Serialize(payload), credentials);
    }

    // 1) Right app, right role as a single string, fresh token -> proxied 200 (the shape
    //    some issuers emit for a one-element claim; CredProx must read it the same).
    var admitted = await client.SendAsync(Request(Issue("demo-agent-client", "docs-read", now, "tok-ok")));
    if ((int)admitted.StatusCode != 200)
    {
        return Fail("fresh docs-read token", $"{(int)admitted.StatusCode}", "200");
    }

    // 2) The same role as an ARRAY — the shape Entra writes — admits identically.
    var admittedArray = await client.SendAsync(Request(Issue("demo-agent-client", new[] { "docs-read" }, now, "tok-array")));
    if ((int)admittedArray.StatusCode != 200)
    {
        return Fail("fresh docs-read token with roles as an array", $"{(int)admittedArray.StatusCode}", "200");
    }

    // 3) Multi-role array: one role names the caller's rule -> that operation is admitted;
    //    the extra role names nothing here and adds nothing.
    var admittedMulti = await client.SendAsync(Request(Issue("demo-agent-client", new[] { "billing-admin", "docs-read" }, now, "tok-multi-ok")));
    if ((int)admittedMulti.StatusCode != 200)
    {
        return Fail("multi-role token containing the named role", $"{(int)admittedMulti.StatusCode}", "200");
    }

    // 4) Multi-role array with no role naming a rule the request needs -> 403: a wider
    //    roles claim never widens what is admitted — it is still an intersection.
    var deniedMulti = await client.SendAsync(Request(Issue("demo-agent-client", new[] { "billing-admin", "ops" }, now, "tok-multi-deny")));
    if ((int)deniedMulti.StatusCode != 403)
    {
        return Fail("multi-role token naming no matching rule", $"{(int)deniedMulti.StatusCode}", "403");
    }

    // 5) Right app, a role that names no rule -> 403 (valid caller, rule not in scope —
    //    the same refusal the operation allow-list gives a key caller).
    var wrongRole = await client.SendAsync(Request(Issue("demo-agent-client", "billing-admin", now, "tok-role")));
    if ((int)wrongRole.StatusCode != 403)
    {
        return Fail("token with an unlisted role", $"{(int)wrongRole.StatusCode}", "403");
    }

    // 6) No roles at all -> nothing intersects the named rule -> 403.
    var noRole = await client.SendAsync(Request(Issue("demo-agent-client", null, now, "tok-norole")));
    if ((int)noRole.StatusCode != 403)
    {
        return Fail("token with no roles claim", $"{(int)noRole.StatusCode}", "403");
    }

    // 7) A token signed by the right issuer for an app nobody listed -> 401: a valid
    //    token from an unconfigured app is not a caller.
    var unlisted = await client.SendAsync(Request(Issue("rogue-client", "docs-read", now, "tok-rogue")));
    if ((int)unlisted.StatusCode != 401)
    {
        return Fail("token from an unlisted client id", $"{(int)unlisted.StatusCode}", "401");
    }

    // 8) The MaxTokenAge knob: issued 2 h ago, still inside its own expiry, limit 15 min
    //    -> 401. Revocation-by-staleness without waiting for Entra's lifetime policy.
    var stale = await client.SendAsync(Request(Issue("demo-agent-client", "docs-read", now.AddHours(-2), "tok-stale")));
    if ((int)stale.StatusCode != 401)
    {
        return Fail("token older than MaxTokenAge", $"{(int)stale.StatusCode}", "401");
    }

    // 9) The stub's journal proves the caller's bearer token never reaches the upstream —
    //    CredProx strips it after authenticating the caller; the upstream only ever sees
    //    its own contract.
    using var journalClient = new HttpClient();
    using var journal = JsonDocument.Parse(
        await journalClient.GetStringAsync("http://localhost:8086/__admin/requests"));
    var records = journal.RootElement.GetProperty("requests").EnumerateArray()
        .Where(r => r.GetProperty("request").GetProperty("url").GetString()?.StartsWith("/docs") == true)
        .ToList();
    var leaked = records.Any(r =>
        r.GetProperty("request").GetProperty("headers").TryGetProperty("Authorization", out _));
    if (leaked || records.Count == 0)
    {
        return Fail("journal proof the Authorization header was stripped", $"records={records.Count} leaked={leaked}", "records > 0, no Authorization");
    }

    Console.WriteLine("SMOKE OK: generated signing key served by the stub, agent token admitted as string and array (200), multi-role arrays admit only what they name (200/403), unlisted role and roleless tokens 403, unlisted client and stale token 401, bearer token stripped before forwarding.");
    return 0;

    static HttpRequestMessage Request(string token)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "http://localhost:5096/docs/readme");
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + token);
        return request;
    }

    static int Fail(string what, string got, string want)
    {
        Console.WriteLine($"SMOKE FAILED: {what} -> {got}, want {want}");
        return 1;
    }
}

app.Run();
return 0;
