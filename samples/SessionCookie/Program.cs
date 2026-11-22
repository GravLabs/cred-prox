using CredProx;

// Session-cookie vendor gateway: one LoginExchange credential logs in with a form,
// captures the Set-Cookie session and replays it per call — pure config. Partitions
// pick the per-environment account and secret behind a strict header allow-list.
// StubApi/ is the vendor stand-in the offline cells drive.
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCredProx(builder.Configuration);

builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx();

var app = builder.Build();
app.MapReverseProxy();
app.Run();
return 0;
