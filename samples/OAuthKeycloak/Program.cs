using CredProx;

// The CredProx host of the OAuthKeycloak example: AddCredProx registers the core defaults
// (cache, secrets source, StaticKey), the chained AddIdentity() brings the OAuth
// client-credentials type, and the proxy itself is pure configuration. The API behind it
// is StubApi/.
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCredProx(builder.Configuration)
    .AddIdentity();

builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx();

var app = builder.Build();
app.MapReverseProxy();
app.Run();
