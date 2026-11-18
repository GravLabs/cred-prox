using CredProx;

// The CredProx host of the PerCallerCredentials example: caller keys, the caller-partitioned
// OAuth credential, the allow-lists and the audit sink are all appsettings.json — the host
// is one call plus the add-ons this proxy needs. The vendor API behind it is StubApi/.
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCredProx(builder.Configuration);
builder.Services.AddCredProxOAuth();
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
