using CredProx;

// The CredProx host of the TokenExchange example: the caller key, the token-exchange
// credential and the route are all appsettings.json — the host is one call plus the
// add-ons this proxy needs. The protected downstream behind it is StubApi/.
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCredProx(builder.Configuration);
builder.Services.AddCredProxOAuth();
builder.Services.AddCredProxCallerAuthentication(builder.Configuration);
builder.Services.AddCredProxAudit(builder.Configuration);
builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx(builder.Configuration);

var app = builder.Build();
app.MapReverseProxy();
app.Run();
