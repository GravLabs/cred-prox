using CredProx;

// Agent egress gateway: each agent holds only its own caller key — the OAuth client
// secret and the minted session token never cross to the agent's side, and the
// allow-lists are the agents' tool boundaries. StubApi/ is the vendor stand-in.
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
return 0;
