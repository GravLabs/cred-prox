using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;

// A stand-in vendor API for the PerCallerCredentials example: it validates Keycloak
// tokens and echoes the `azp` claim — the Keycloak client the token was minted for — so
// each caller key visibly reaches its OWN vendor account.
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

app.MapGet("/", (ClaimsPrincipal user) =>
    Results.Text(user.FindFirst("azp")?.Value ?? "anonymous")).RequireAuthorization();

app.Run();
