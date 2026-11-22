using CredProx;

var builder = WebApplication.CreateBuilder(args);

// The LoginExchange credential type against a vendor-neutral WireMock stub — a vendor
// with no OAuth at all: POST a service account, get a session token back. One
// {partition} credential serves many environments; everything is plain config.

// AddCredProx registers the core defaults, the LoginExchange credential type among them.
builder.Services.AddCredProx(builder.Configuration);

builder.Services.AddRouting();
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddCredProx();

var app = builder.Build();

app.MapReverseProxy();
app.Run();
