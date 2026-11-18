using CredProx;

// The CredProx host of the GitHub App example: the whole GitHub flow — RS256 app JWT,
// BearerExchange against the installation-access-tokens endpoint, the cached installation
// token on every forwarded request — is plain config in appsettings.json.
var builder = WebApplication.CreateBuilder(args);

// StubApi/ is the offline GitHub stand-in the sample cells drive; live traffic is plain.
builder.Services.AddCredProx(builder.Configuration);
builder.Services.AddCredProxOAuth(); // JwtAssertion (with BearerExchange) ships in CredProx.OAuth

builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx(builder.Configuration);

var app = builder.Build();
app.MapReverseProxy();
app.Run();
return 0;
