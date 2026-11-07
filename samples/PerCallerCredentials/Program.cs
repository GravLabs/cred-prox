using System.Security.Claims;
using CredProx;
using Microsoft.AspNetCore.Authentication.JwtBearer;

// One project, two roles (plan §6 E7): the CredProx proxy (default) and a small protected
// API that echoes the vendor account its token belongs to ('--role api'). The proxy side
// is pure configuration — caller keys, the caller:-partitioned credential, the allow-list
// and the audit sink are all appsettings.json.
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
    builder.Services.AddCredProxHealthProbes(builder.Configuration);
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

    // Echo the vendor account the received token was minted for: the `azp` claim is the
    // Keycloak client that did the client-credentials grant — credprox-app-a for caller
    // app-a, credprox-app-b for caller app-b.
    app.MapGet("/", (ClaimsPrincipal user) =>
        Results.Text(user.FindFirst("azp")?.Value ?? "anonymous")).RequireAuthorization();

    app.Run();
}
