using CredProx;

// Agent egress gateway: each agent holds only its own caller key — the OAuth client
// secret and the minted session token never cross to the agent's side, and the
// allow-lists are the agents' tool boundaries. StubApi/ is the vendor stand-in.
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCredProxTokenCache();
builder.Services.AddCredProxConfigurationSecrets(builder.Configuration);
builder.Services.AddCredProxBuiltInCredentials();
builder.Services.AddCredProxOAuth();
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
return 0;
