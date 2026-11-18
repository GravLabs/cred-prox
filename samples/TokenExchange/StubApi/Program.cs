using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;

// A stand-in downstream API for the TokenExchange example: it validates its OWN audience
// (credprox-downstream), so only the EXCHANGED token passes. The echo proves which token
// arrived — sub is the human subject, azp=credprox-proxy marks the exchanged one.
var builder = WebApplication.CreateBuilder(args);

// Keycloak's frontend URL (KC_HOSTNAME) is the docker-network URL, so one issuer covers
// every route: minted tokens and exchanges agree on iss, validated via plain discovery.
var authority = builder.Configuration["Api:Authority"]
    ?? "http://keycloak:8080/realms/credprox";
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = authority;
        options.RequireHttpsMetadata = false;
        options.TokenValidationParameters.ValidAudience = "credprox-downstream";
    });
builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", (ClaimsPrincipal user) => Results.Text(
    $"{user.FindFirst("preferred_username")?.Value}|{user.FindFirst("azp")?.Value}"))
    .RequireAuthorization();

app.Run();
