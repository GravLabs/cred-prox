using System.Security.Claims;
using CredProx;
using Microsoft.AspNetCore.Authentication.JwtBearer;

// One project, two roles (plan §6 E14): the CredProx proxy (default) and a protected
// downstream API ('--role api'). The proxy side is pure configuration — the caller key,
// the TokenExchange credential and the route are all appsettings.json. The downstream
// validates its OWN audience (credprox-downstream), so the caller's inbound token
// (audience credprox-proxy) is refused by it: only the exchanged token passes.
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
    builder.Services.AddCredProxCallerAuthentication(builder.Configuration);
    builder.Services.AddCredProxAudit(builder.Configuration);
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

    // Keycloak's frontend URL (KC_HOSTNAME) is the docker-network URL, so one issuer
    // covers every route: the smoke's tokens (host port) and the proxy's exchanges
    // (internal) carry the same iss, and the API validates through plain discovery.
    var authority = builder.Configuration["Api:Authority"]
        ?? "http://keycloak:8080/realms/credprox";
    builder.Services
        .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
        {
            options.Authority = authority;
            options.RequireHttpsMetadata = false;
            // The point of E14: the downstream checks its own audience. The inbound
            // user token (aud credprox-proxy) must NOT pass here.
            options.TokenValidationParameters.ValidAudience = "credprox-downstream";
        });
    builder.Services.AddAuthorization();

    var app = builder.Build();
    app.UseAuthentication();
    app.UseAuthorization();

    // Echo the subject AND the authorized party: sub proves whose token it is, azp
    // proves it is the EXCHANGED token (azp=credprox-proxy), never the inbound one
    // (azp=credprox-frontend).
    // (JsonWebTokenHandler keeps the raw claim types.) preferred_username is the human
    // subject; the cache key inside CredProx uses the validated "sub" (the Keycloak user id).
    app.MapGet("/", (ClaimsPrincipal user) => Results.Text(
        $"{user.FindFirst("preferred_username")?.Value}|{user.FindFirst("azp")?.Value}"))
        .RequireAuthorization();

    app.Run();
}
