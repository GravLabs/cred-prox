using CredProx;

// The AI provider gateway: caller keys in, provider key out, per-caller allow-lists,
// budgets, cluster throttle and audit — all config. StubApi/ is the provider stand-in
// the offline cells drive; a real provider is just a different address and key.
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCredProx(builder.Configuration)
    .AddOperations();

builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx();

var app = builder.Build();
app.MapReverseProxy();
app.Run();
return 0;
