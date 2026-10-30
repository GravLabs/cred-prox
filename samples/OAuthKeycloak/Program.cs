using CredProx;
using Microsoft.AspNetCore.Authentication.JwtBearer;

// One project, two roles (plan §6 E2): the CredProx proxy (default) and a small protected
// API that validates Keycloak tokens ('--role api'). The proxy side is pure configuration —
// the only C# here is the standard CredProx host block and the API's ordinary JwtBearer setup.
if (args.Contains("api"))
{
    RunProtectedApi();
}
else
{
    RunProxy();
}

return 0;

void RunProxy()
{
    var builder = WebApplication.CreateBuilder(args);

    builder.Services.AddCredProxTokenCache();
    builder.Services.AddCredProxConfigurationSecrets(builder.Configuration);
    builder.Services.AddCredProxBuiltInCredentials();
    builder.Services.AddCredProxCredentials(builder.Configuration);
    builder.Services.AddRouting();
    builder.Services.AddReverseProxy()
        .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
        .AddCredProx(builder.Configuration);

    var app = builder.Build();
    app.MapReverseProxy();
    app.Run();
}

void RunProtectedApi()
{
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

    // A deliberate stand-in for vendor-side revocation: /revoke marks the token this API
    // last accepted as no longer acceptable, so the next request with it gets a 401 —
    // exactly the signal CredProx's refresh-on-401 reacts to. Real vendors revoke in their
    // own way; what CredProx guarantees is the one refresh-and-retry on any 401.
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

    // Since M20 (§8.2) the injected token is scrubbed from the caller's echo, so the smoke
    // proves token rotation and cache single-flight against the API's own record — the
    // vendor-side counterpart of E1/E12's WireMock journal. The smoke asks these directly,
    // the way it drives /revoke.
    app.MapGet("/seen", () => Results.Text(lastSeen ?? string.Empty));
    app.MapGet("/seen-count", () => Results.Text(seen.Count.ToString()));

    app.Run();
}
