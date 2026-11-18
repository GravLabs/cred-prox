using Microsoft.AspNetCore.Authentication.JwtBearer;

// A stand-in vendor API for the OAuthKeycloak example: it validates Keycloak tokens and
// echoes the Authorization header it received. /revoke simulates vendor-side revocation,
// the signal CredProx's refresh-on-401 reacts to.
var builder = WebApplication.CreateBuilder(args);

var authority = builder.Configuration["Api:Authority"]
    ?? "http://keycloak:8080/realms/credprox";
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = authority;
        options.RequireHttpsMetadata = false;
        options.TokenValidationParameters.ValidateAudience = false;
    });
builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

// /revoke marks the token this API last accepted as no longer acceptable, so the next
// request with it gets a 401. Real vendors revoke in their own way; what CredProx
// guarantees is the one refresh-and-retry on any 401.
string? lastSeen = null;
string? revoked = null;
var seen = new System.Collections.Concurrent.ConcurrentDictionary<string, byte>();

app.MapGet("/secrets", (HttpContext context) =>
{
    var authorization = context.Request.Headers.Authorization.ToString();
    lastSeen = authorization;
    // Only valid tokens reach this handler (RequireAuthorization short-circuits the
    // rest), so the set is exactly the tokens this API accepted.
    seen[authorization] = 0;
    if (authorization.Length > 0 && authorization == revoked)
    {
        return Results.Unauthorized();
    }

    // Echo the credential the upstream actually received.
    return Results.Text(authorization);
}).RequireAuthorization();

app.MapPost("/revoke", () =>
{
    revoked = lastSeen;
    return Results.Text(revoked is null ? "nothing to revoke" : "revoked the last accepted token");
});

// The example scrubs the injected token from the caller's echo, so its offline cells ask
// this API's own record for the rotation and cache single-flight checks — the vendor-side
// counterpart of a WireMock journal.
app.MapGet("/seen", () => Results.Text(lastSeen ?? string.Empty));
app.MapGet("/seen-count", () => Results.Text(seen.Count.ToString()));

app.Run();
