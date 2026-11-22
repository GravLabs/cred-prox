using CredProx;

// The CredProx host of the TokenExchange example: the caller key, the token-exchange
// credential, the audit sink and the route are all appsettings.json — the host is one
// entry plus the add-on chain it needs. The protected downstream behind it is StubApi/.
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
