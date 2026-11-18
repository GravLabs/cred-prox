using CredProx;

// The AI provider gateway: caller keys in, provider key out, per-caller allow-lists,
// budgets, cluster throttle and audit — all config. StubApi/ is the provider stand-in
// the offline cells drive; a real provider is just a different address and key.
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCredProxTokenCache();
builder.Services.AddCredProxConfigurationSecrets(builder.Configuration);
builder.Services.AddCredProxBuiltInCredentials();
builder.Services.AddCredProxCredentials(builder.Configuration);
builder.Services.AddCredProxCallerAuthentication(builder.Configuration);
builder.Services.AddCredProxThrottling(builder.Configuration);
builder.Services.AddCredProxAudit(builder.Configuration);

builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx(builder.Configuration);

var app = builder.Build();
app.MapReverseProxy();
app.Run();
return 0;
